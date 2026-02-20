package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/recording"
	"github.com/pomerium/pomerium/pkg/grpc/testproto"
	"github.com/pomerium/pomerium/pkg/storage"
	"github.com/pomerium/pomerium/pkg/storage/blob"
	"github.com/pomerium/pomerium/pkg/storage/blob/providers"
)

func main() {
	rootCmd := BuildRootCommand()

	rootCmd.AddCommand(BuildRecordCommand())
	rootCmd.AddCommand(BuildMetadataQueryCommand())
	rootCmd.AddCommand(BuildViewCommand())
	if err := rootCmd.Execute(); err != nil {
		log.Ctx(rootCmd.Context()).Err(err).Msg("failed to run command")
	}
}

func BuildRootCommand() *cobra.Command {
	return &cobra.Command{}
}

// parseSimpleFilter parses a simple "field=value" filter expression using structpb.
// Returns nil if filterStr is empty.
func parseSimpleFilter(filterStr string) (storage.FilterExpression, error) {
	if filterStr == "" {
		return nil, nil
	}

	// Split on '=' to get field and value
	parts := strings.SplitN(filterStr, "=", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid filter format, expected 'field=value', got: %s", filterStr)
	}

	field := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])

	// Build filter using structpb
	filterMap := map[string]interface{}{
		field: value,
	}

	filterStruct, err := structpb.NewStruct(filterMap)
	if err != nil {
		return nil, fmt.Errorf("create filter struct: %w", err)
	}

	return storage.FilterExpressionFromStruct(filterStruct)
}

// BuildMetadataQueryCommand creates a command that queries blob storage metadata.
func BuildMetadataQueryCommand() *cobra.Command {
	var (
		queryFilter string
		orderBy     string
	)

	cmd := &cobra.Command{
		Use:   "query",
		Short: "query file metadata from blob storage",
		Long: `Query file metadata from blob storage.

Examples:
  # List all files
  query

  # Filter by path
  query -f "path=/var/log/app.log"

  # Filter by file type
  query -f "file_type=regular"

  # Sort by modification time (descending)
  query -o "-mtime_unix"

  # Sort by size (ascending)
  query -o "size"
`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()

			// Hardcoded blob storage configuration for local MinIO
			cfg := &blob.StorageConfig{
				Provider: "S3",
				Bucket:   "your-bucket-name",
				S3: &blob.S3Config{
					Endpoint:  "localhost:9000",
					AccessKey: "minioadmin",
					SecretKey: "minioadmin",
					Region:    "us-east-1",
					Insecure:  true,
				},
			}

			// Create blob storage bucket
			bucket, err := providers.NewBucketFromConfig(cfg)
			if err != nil {
				return fmt.Errorf("create bucket: %w", err)
			}
			defer bucket.Close()

			// Create blob store for anypb.Any (matching what the server uses)
			store := blob.NewStore[testproto.FileMetadata](ctx, "")
			store.OnConfigChange(ctx, bucket)
			defer store.Stop()

			// Build query options
			var queryOpts []blob.QueryOption

			// Parse filter expression if provided
			if queryFilter != "" {
				filter, err := parseSimpleFilter(queryFilter)
				if err != nil {
					return fmt.Errorf("parse filter: %w", err)
				}
				if filter != nil {
					queryOpts = append(queryOpts, blob.WithQueryFilter(filter))
				}
			}

			// Parse order by if provided
			if orderBy != "" {
				queryOpts = append(queryOpts, blob.WithQueryOrderBy(storage.OrderByFromString(orderBy)))
			}

			// Execute query for RecordingMetadata to get the IDs
			results, err := store.QueryMetadata(ctx, "file", queryOpts...)
			if err != nil {
				return fmt.Errorf("query metadata: %w", err)
			}

			// Print results as JSON using protojson
			log.Ctx(ctx).Info().Int("count", len(results)).Msg("query results")
			marshaler := protojson.MarshalOptions{
				Multiline:       true,
				Indent:          "  ",
				EmitUnpopulated: true,
			}

			for _, recordingMd := range results {
				data, err := marshaler.Marshal(recordingMd.Md)
				if err != nil {
					panic(err)
				}
				cmd.Println(string(data))
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&queryFilter, "filter", "f", "", "filter expression (format: 'field=value', e.g., 'path=/var/log/app.log')")
	cmd.Flags().StringVarP(&orderBy, "order-by", "o", "", "order by fields (e.g., 'mtime_unix' or '-size' for descending)")

	return cmd
}

// buildFileMetadata creates a FileMetadata proto from file stats
func buildFileMetadata(path string, info os.FileInfo) (*testproto.FileMetadata, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("failed to get syscall.Stat_t")
	}

	fileType := "regular"
	switch {
	case info.IsDir():
		fileType = "directory"
	case info.Mode()&os.ModeSymlink != 0:
		fileType = "symlink"
	case info.Mode()&os.ModeDevice != 0:
		fileType = "device"
	}

	var symlinkTarget string
	if fileType == "symlink" {
		target, _ := os.Readlink(path)
		symlinkTarget = target
	}

	return &testproto.FileMetadata{
		Path:          path,
		Size:          uint64(info.Size()),
		Mode:          uint32(info.Mode()),
		Uid:           stat.Uid,
		Gid:           stat.Gid,
		AtimeUnix:     stat.Atim.Sec,
		MtimeUnix:     stat.Mtim.Sec,
		CtimeUnix:     stat.Ctim.Sec,
		FileType:      fileType,
		Inode:         stat.Ino,
		Nlink:         uint32(stat.Nlink),
		SymlinkTarget: symlinkTarget,
	}, nil
}

// parseLogLine parses a JSON structured log line into a LogEntry.
// Expected format: {"level":"info","time":"2026-02-08T23:33:56-05:00","message":"...","field":"value",...}
func parseLogLine(line string) *testproto.LogEntry {
	entry := &testproto.LogEntry{
		TimestampUnix: time.Now().Unix(),
		Level:         "info",
		Message:       line,
		Logger:        "pomerium",
		Fields:        make(map[string]string),
	}

	// Try to parse as JSON
	var logData map[string]interface{}
	if err := json.Unmarshal([]byte(line), &logData); err != nil {
		// Not JSON, return the line as-is
		return entry
	}

	// Extract standard fields
	if level, ok := logData["level"].(string); ok {
		entry.Level = level
		delete(logData, "level")
	}

	if timeStr, ok := logData["time"].(string); ok {
		if t, err := time.Parse(time.RFC3339, timeStr); err == nil {
			entry.TimestampUnix = t.Unix()
		}
		delete(logData, "time")
	}

	if msg, ok := logData["message"].(string); ok {
		entry.Message = msg
		delete(logData, "message")
	}

	// Extract logger/component/service fields
	if component, ok := logData["component"].(string); ok {
		entry.Logger = component
		delete(logData, "component")
	} else if service, ok := logData["service"].(string); ok {
		entry.Logger = service
		delete(logData, "service")
	}

	// Extract error as stacktrace if present
	if errStr, ok := logData["error"].(string); ok {
		entry.Stacktrace = errStr
		delete(logData, "error")
	}

	// Store remaining fields as key-value pairs
	for key, value := range logData {
		if str, ok := value.(string); ok {
			entry.Fields[key] = str
		} else {
			// Convert non-string values to JSON string
			if jsonBytes, err := json.Marshal(value); err == nil {
				entry.Fields[key] = string(jsonBytes)
			}
		}
	}

	return entry
}

// encodeLogEntries marshals a slice of LogEntry protos to bytes
func encodeLogEntries(entries []*testproto.LogEntry) ([]byte, error) {
	var allBytes []byte
	for _, entry := range entries {
		data, err := proto.Marshal(entry)
		if err != nil {
			return nil, fmt.Errorf("marshal log entry: %w", err)
		}
		// Prefix each entry with its length for proper deserialization
		lenBuf := make([]byte, binary.MaxVarintLen64)
		n := binary.PutUvarint(lenBuf, uint64(len(data)))
		allBytes = append(allBytes, lenBuf[:n]...)
		allBytes = append(allBytes, data...)
	}
	return allBytes, nil
}

// BuildRecordCommand creates a cobra command that streams a file to the
// recording service in chunks.
func BuildRecordCommand() *cobra.Command {
	var (
		grpcAddr    string
		filePath    string
		recordingID string
	)

	cmd := &cobra.Command{
		Use:   "record",
		Short: "push a file to the recording server in chunks",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()

			f, err := os.Open(filePath)
			if err != nil {
				return fmt.Errorf("open file: %w", err)
			}
			defer f.Close()

			// Get file stats for metadata
			fileInfo, err := f.Stat()
			if err != nil {
				return fmt.Errorf("stat file: %w", err)
			}

			cc, err := grpc.NewClient(grpcAddr,
				grpc.WithTransportCredentials(insecure.NewCredentials()),
			)
			if err != nil {
				return fmt.Errorf("dial: %w", err)
			}
			defer cc.Close()

			client := recording.NewRecordingServiceClient(cc)
			stream, err := client.Record(ctx)
			if err != nil {
				return fmt.Errorf("open stream: %w", err)
			}

			// 1. Build and send metadata with FileMetadata proto.
			fileMetadata, err := buildFileMetadata(filePath, fileInfo)
			if err != nil {
				return fmt.Errorf("build file metadata: %w", err)
			}

			metadataAny, err := anypb.New(fileMetadata)
			if err != nil {
				return fmt.Errorf("create any metadata: %w", err)
			}

			if err := stream.Send(&recording.RecordingData{
				Data: &recording.RecordingData_Metadata{
					Metadata: &recording.RecordingMetadata{
						Id:            recordingID,
						RecordingType: "file",
						Metadata:      metadataAny,
					},
				},
			}); err != nil {
				return fmt.Errorf("send metadata: %w", err)
			}

			// 2. Receive initial session (server config + manifest).
			session, err := stream.Recv()
			if err != nil {
				return fmt.Errorf("recv session: %w", err)
			}

			serverCfg := session.GetConfig()
			chunkSize := serverCfg.GetMaxChunkSize()
			maxBatchNum := serverCfg.GetMaxChunkBatchNum()
			if maxBatchNum <= 0 {
				maxBatchNum = 1
			}

			manifest := session.GetManifest()
			log.Ctx(ctx).Info().
				Int("existing_chunks", len(manifest.GetItems())).
				Uint32("chunk_size", chunkSize).
				Uint32("max_batch", maxBatchNum).
				Msg("connected to recording server")

			// 2b. Resume: Calculate how many log entries to skip based on existing chunks.
			// We need to estimate the number of entries from the total bytes in the manifest.
			// This is an approximation since we don't know the exact entry count without decoding.
			var skipLines int
			var totalExistingBytes uint32
			for _, item := range manifest.GetItems() {
				totalExistingBytes += item.GetSize()
			}

			// We'll skip lines by reading through them first to count how many entries
			// match the byte count in the manifest. This ensures we resume correctly.
			if totalExistingBytes > 0 {
				log.Ctx(ctx).Info().
					Uint32("existing_bytes", totalExistingBytes).
					Msg("resuming upload - calculating entries to skip")

				// Pre-scan to count how many entries we need to skip
				tempScanner := bufio.NewScanner(f)
				var bytesEncoded uint32
				for bytesEncoded < totalExistingBytes && tempScanner.Scan() {
					line := tempScanner.Text()
					if line == "" {
						continue
					}

					// Estimate encoded size for this entry
					entry := parseLogLine(line)
					entryData, err := proto.Marshal(entry)
					if err != nil {
						continue
					}

					// Add varint length prefix size + data size
					lenBuf := make([]byte, binary.MaxVarintLen64)
					n := binary.PutUvarint(lenBuf, uint64(len(entryData)))
					bytesEncoded += uint32(n + len(entryData))
					skipLines++

					if bytesEncoded >= totalExistingBytes {
						break
					}
				}

				// Seek back to start and skip the lines
				if _, err := f.Seek(0, 0); err != nil {
					return fmt.Errorf("seek to start: %w", err)
				}

				log.Ctx(ctx).Info().
					Int("skip_lines", skipLines).
					Uint32("skip_bytes", bytesEncoded).
					Msg("resuming upload")
			}

			// 3. Parse the file as log entries and stream in batched chunks.
			// The server expects up to maxBatchNum chunks followed by a
			// checksum, then it writes the batch and sends an ack. The
			// client must wait for the ack before sending the next batch.
			scanner := bufio.NewScanner(f)
			var totalBytes int64
			var chunkCount int
			var logEntryCount int
			const maxEntriesPerChunk = 100 // Max log entries per chunk

			// Skip already uploaded lines
			var linesSkipped int
			for linesSkipped < skipLines {
				if !scanner.Scan() {
					return fmt.Errorf("failed to skip to resume position")
				}
				if scanner.Text() != "" {
					linesSkipped++
				}
			}
			if scanner.Err() != nil {
				return fmt.Errorf("scan file during skip: %w", scanner.Err())
			}

			eof := false
			for !eof {
				var batchData []byte
				var batchChunks uint32

				// Create up to maxBatchNum chunks per batch
				for batchChunks < maxBatchNum && !eof {
					// Collect log entries for this chunk
					var entries []*testproto.LogEntry

					for len(entries) < maxEntriesPerChunk {
						if !scanner.Scan() {
							eof = true
							break
						}

						line := scanner.Text()
						if line == "" {
							continue // Skip empty lines
						}

						entry := parseLogLine(line)
						entries = append(entries, entry)
						logEntryCount++
					}

					if scanner.Err() != nil {
						return fmt.Errorf("scan file: %w", scanner.Err())
					}

					// If we have entries, encode and send them as a chunk
					if len(entries) > 0 {
						encodedData, err := encodeLogEntries(entries)
						if err != nil {
							return fmt.Errorf("encode log entries: %w", err)
						}

						if err := stream.Send(&recording.RecordingData{
							Data: &recording.RecordingData_Chunk{Chunk: encodedData},
						}); err != nil {
							return fmt.Errorf("send chunk: %w", err)
						}

						batchData = append(batchData, encodedData...)
						batchChunks++
						totalBytes += int64(len(encodedData))
						chunkCount++
						log.Ctx(ctx).Debug().
							Int("chunk", chunkCount).
							Int("entries", len(entries)).
							Int("bytes", len(encodedData)).
							Msg("sent chunk")
					}
				}

				// Send checksum for this batch
				if batchChunks > 0 {
					checksum := sha256.Sum256(batchData)
					if err := stream.Send(&recording.RecordingData{
						Data: &recording.RecordingData_Checksum{Checksum: checksum[:]},
					}); err != nil {
						return fmt.Errorf("send checksum: %w", err)
					}

					// Wait for the server to acknowledge this batch.
					if _, err := stream.Recv(); err != nil {
						return fmt.Errorf("recv ack: %w", err)
					}
				}
			}

			// 4. Close the client side.
			if err := stream.CloseSend(); err != nil {
				return fmt.Errorf("close stream: %w", err)
			}

			// Drain the stream so we block until the server's Record handler
			// returns. Without this the gRPC connection tears down immediately
			// and the server-side context is cancelled before chunks are flushed.
			for {
				if _, err := stream.Recv(); err != nil {
					break
				}
			}

			log.Ctx(ctx).Info().
				Int("chunks", chunkCount).
				Int("log_entries", logEntryCount).
				Int64("bytes", totalBytes).
				Msg("upload complete")
			return nil
		},
	}

	cmd.Flags().StringVarP(&grpcAddr, "grpc-addr", "a", "", "recording server gRPC address (required)")
	cmd.Flags().StringVarP(&filePath, "file", "f", "", "path to the file to upload (required)")
	cmd.Flags().StringVarP(&recordingID, "id", "i", "", "recording ID (required)")

	_ = cmd.MarkFlagRequired("grpc-addr")
	_ = cmd.MarkFlagRequired("file")
	_ = cmd.MarkFlagRequired("id")

	return cmd
}

// decodeLogEntries decodes a byte slice containing varint-prefixed LogEntry protos
func decodeLogEntries(data []byte) ([]*testproto.LogEntry, error) {
	var entries []*testproto.LogEntry
	offset := 0

	for offset < len(data) {
		// Read the length prefix
		length, n := binary.Uvarint(data[offset:])
		if n <= 0 {
			return nil, fmt.Errorf("failed to read varint at offset %d", offset)
		}
		offset += n

		// Check if we have enough data
		if offset+int(length) > len(data) {
			return nil, fmt.Errorf("incomplete entry at offset %d: expected %d bytes, got %d", offset, length, len(data)-offset)
		}

		// Unmarshal the entry
		entry := &testproto.LogEntry{}
		if err := proto.Unmarshal(data[offset:offset+int(length)], entry); err != nil {
			return nil, fmt.Errorf("unmarshal log entry: %w", err)
		}
		entries = append(entries, entry)
		offset += int(length)
	}

	return entries, nil
}

// BuildViewCommand creates a command that displays log entries from a recording in a TUI
func BuildViewCommand() *cobra.Command {
	var (
		recordingID string
		pageSize    int
	)

	cmd := &cobra.Command{
		Use:   "view",
		Short: "view log entries from a recording with pagination",
		Long: `View log entries from a recording in an interactive TUI.

Keys:
  n - next page (10 entries forward)
  p - previous page (10 entries backward)
  q - quit

Examples:
  # View a recording
  view -i "my-recording-id"

  # View with custom page size
  view -i "my-recording-id" --page-size 20
`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()

			// Hardcoded blob storage configuration for local MinIO
			cfg := &blob.StorageConfig{
				Provider: "S3",
				Bucket:   "your-bucket-name",
				S3: &blob.S3Config{
					Endpoint:  "localhost:9000",
					AccessKey: "minioadmin",
					SecretKey: "minioadmin",
					Region:    "us-east-1",
					Insecure:  true,
				},
			}

			// Create blob storage bucket
			bucket, err := providers.NewBucketFromConfig(cfg)
			if err != nil {
				return fmt.Errorf("create bucket: %w", err)
			}
			defer bucket.Close()

			// Create blob store
			store := blob.NewStore[testproto.LogEntry](ctx, "")
			store.OnConfigChange(ctx, bucket)
			defer store.Stop()

			// Get chunk reader
			reader, err := store.ReaderWriter().ChunkReader(ctx, "file", recordingID)
			if err != nil {
				return fmt.Errorf("create chunk reader: %w", err)
			}

			// Load all log entries from chunks
			var allEntries []*testproto.LogEntry
			cmd.Println("Loading log entries...")

			for chunkData, err := range reader.Chunks(ctx) {
				if err != nil {
					return fmt.Errorf("read chunk: %w", err)
				}

				entries, err := decodeLogEntries(chunkData)
				if err != nil {
					return fmt.Errorf("decode log entries: %w", err)
				}
				allEntries = append(allEntries, entries...)
			}

			cmd.Printf("Loaded %d log entries. Use 'n' for next, 'p' for previous, 'q' to quit.\n\n", len(allEntries))

			// Start TUI
			return runTUI(cmd, allEntries, pageSize)
		},
	}

	cmd.Flags().StringVarP(&recordingID, "id", "i", "", "recording ID to view (required)")
	cmd.Flags().IntVarP(&pageSize, "page-size", "n", 10, "number of entries to display per page")

	_ = cmd.MarkFlagRequired("id")

	return cmd
}

// runTUI runs the interactive TUI for viewing log entries
func runTUI(cmd *cobra.Command, entries []*testproto.LogEntry, pageSize int) error {
	if len(entries) == 0 {
		cmd.Println("No log entries found.")
		return nil
	}

	currentOffset := 0

	// Set terminal to raw mode for single-key input
	// Store original state
	var oldState syscall.Termios
	if _, _, err := syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(syscall.Stdin),
		syscall.TCGETS,
		uintptr(unsafe.Pointer(&oldState))); err != 0 {
		return fmt.Errorf("get terminal state: %w", err)
	}

	// Create new state with raw mode
	newState := oldState
	newState.Lflag &^= syscall.ICANON | syscall.ECHO
	if _, _, err := syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(syscall.Stdin),
		syscall.TCSETS,
		uintptr(unsafe.Pointer(&newState))); err != 0 {
		return fmt.Errorf("set terminal raw mode: %w", err)
	}

	// Restore terminal state on exit
	defer func() {
		syscall.Syscall(syscall.SYS_IOCTL,
			uintptr(syscall.Stdin),
			syscall.TCSETS,
			uintptr(unsafe.Pointer(&oldState)))
	}()

	displayPage := func(offset int) {
		// Clear screen
		cmd.Print("\033[2J\033[H")

		// Display entries
		end := offset + pageSize
		if end > len(entries) {
			end = len(entries)
		}

		cmd.Printf("=== Log Entries %d-%d of %d ===\n\n", offset+1, end, len(entries))

		for i := offset; i < end; i++ {
			entry := entries[i]
			timestamp := time.Unix(entry.TimestampUnix, 0).Format("2006-01-02 15:04:05")
			cmd.Printf("[%s] [%s] %s\n", timestamp, entry.Level, entry.Message)

			// Display fields if any
			if len(entry.Fields) > 0 {
				for k, v := range entry.Fields {
					cmd.Printf("  %s: %s\n", k, v)
				}
			}

			// Display stacktrace if present
			if entry.Stacktrace != "" {
				cmd.Printf("  stacktrace: %s\n", entry.Stacktrace)
			}
			cmd.Println()
		}

		cmd.Printf("\n[n] Next | [p] Previous | [q] Quit (showing %d-%d of %d)\n", offset+1, end, len(entries))
	}

	// Display initial page
	displayPage(currentOffset)

	// Read single characters
	buf := make([]byte, 1)
	for {
		n, err := syscall.Read(syscall.Stdin, buf)
		if err != nil || n == 0 {
			continue
		}

		key := buf[0]
		switch key {
		case 'n', 'N':
			// Next page
			if currentOffset+pageSize < len(entries) {
				currentOffset += pageSize
				displayPage(currentOffset)
			}
		case 'p', 'P':
			// Previous page
			if currentOffset-pageSize >= 0 {
				currentOffset -= pageSize
				displayPage(currentOffset)
			}
		case 'q', 'Q', 3: // 'q', 'Q', or Ctrl+C
			cmd.Print("\033[2J\033[H") // Clear screen
			return nil
		}
	}
}
