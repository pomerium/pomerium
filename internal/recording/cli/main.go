package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/recording"
)

func main() {
	cmd := BuildRecordCommand()
	if err := cmd.Execute(); err != nil {
		log.Ctx(cmd.Context()).Err(err).Msg("failed to run record command")
	}
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

			// 1. Send metadata.
			if err := stream.Send(&recording.RecordingData{
				Data: &recording.RecordingData_Metadata{
					Metadata: &recording.RecordingMetadata{
						Id: recordingID,
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

			// 2b. Resume: skip past bytes the server already has.
			var offset int64
			for _, item := range manifest.GetItems() {
				offset += int64(item.GetSize())
			}
			if offset > 0 {
				if _, err := f.Seek(offset, io.SeekStart); err != nil {
					return fmt.Errorf("seek to offset %d: %w", offset, err)
				}
				log.Ctx(ctx).Info().Int64("offset", offset).Msg("resuming upload")
			}

			// 3. Stream the file in batched chunks.
			// The server expects up to maxBatchNum chunks followed by a
			// checksum, then it writes the batch and sends an ack. The
			// client must wait for the ack before sending the next batch.
			buf := make([]byte, chunkSize)
			var totalBytes int64
			var chunkCount int

			for {
				var batchData []byte
				var batchChunks uint32
				done := false

				for batchChunks < maxBatchNum {
					n, readErr := f.Read(buf)
					if n > 0 {
						if err := stream.Send(&recording.RecordingData{
							Data: &recording.RecordingData_Chunk{Chunk: buf[:n]},
						}); err != nil {
							return fmt.Errorf("send chunk: %w", err)
						}
						batchData = append(batchData, buf[:n]...)
						batchChunks++
						totalBytes += int64(n)
						chunkCount++
						log.Ctx(ctx).Debug().Int("chunk", chunkCount).Int("bytes", n).Msg("sent chunk")
					}
					if readErr == io.EOF {
						done = true
						break
					}
					if readErr != nil {
						return fmt.Errorf("read file: %w", readErr)
					}
				}

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

				if done {
					break
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

			log.Ctx(ctx).Info().Int("chunks", chunkCount).Int64("bytes", totalBytes).Msg("upload complete")
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
