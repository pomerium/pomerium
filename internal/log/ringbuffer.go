package log

import (
	"math/rand/v2"
	"sync"
)

const (
	// DefaultBufferSize is the total ring buffer capacity (6 MB).
	DefaultBufferSize = 6 * 1024 * 1024
	// DefaultSamplingThreshold is the byte count after which sampling kicks in (3 MB).
	DefaultSamplingThreshold = 3 * 1024 * 1024
	// DefaultSamplingRate is the probability of capturing a log entry after the threshold.
	DefaultSamplingRate = 0.05
)

// entry is a single log line stored in the ring buffer.
type entry struct {
	data []byte
}

// RingBuffer is a fixed-capacity circular buffer for filtered log entries.
// It implements io.Writer: each Write call is a complete JSON log line from zerolog.
//
// Filtering and sampling happen at write time:
//   - Only log lines passing CaptureFilter are stored.
//   - After SamplingThreshold bytes have been written since the last Flush,
//     entries are sampled at SamplingRate (uniform random).
//   - When the buffer is full, the oldest entries are overwritten.
//   - Flush returns all buffered entries and resets the bytes-written counter.
type RingBuffer struct {
	mu sync.Mutex

	entries []entry
	head    int // next write position
	count   int // number of valid entries (≤ len(entries))
	size    int // total bytes stored

	capacity          int     // max bytes
	samplingThreshold int     // bytes before sampling starts
	samplingRate      float64 // probability of capture after threshold
	bytesSinceFlush   int     // bytes written since last flush (for sampling decision)

	randFunc func() float64 // for testing
}

// NewRingBuffer creates a ring buffer with default settings.
func NewRingBuffer() *RingBuffer {
	return &RingBuffer{
		capacity:          DefaultBufferSize,
		samplingThreshold: DefaultSamplingThreshold,
		samplingRate:      DefaultSamplingRate,
		randFunc:          rand.Float64,
	}
}

// Write implements io.Writer. Each call receives a complete JSON log line.
// It always returns len(p), nil so it never blocks the logger.
func (rb *RingBuffer) Write(p []byte) (int, error) {
	n := len(p)

	if !CaptureFilter(p) {
		return n, nil
	}

	rb.mu.Lock()
	defer rb.mu.Unlock()

	// Apply sampling if we've exceeded the threshold since last flush.
	if rb.bytesSinceFlush >= rb.samplingThreshold {
		if rb.randFunc() >= rb.samplingRate {
			return n, nil
		}
	}

	// Copy the data so we don't hold a reference to the caller's buffer.
	data := make([]byte, n)
	copy(data, p)
	e := entry{data: data}

	// Evict oldest entries if we'd exceed capacity.
	for rb.size+n > rb.capacity && rb.count > 0 {
		rb.evictOldest()
	}

	// If a single entry exceeds capacity, drop it.
	if n > rb.capacity {
		return n, nil
	}

	// Append to circular buffer.
	if rb.count < len(rb.entries) {
		rb.entries[rb.head] = e
	} else {
		// Grow the slice until we reach steady state.
		rb.entries = append(rb.entries, entry{})
		// After append, indices may have shifted — recalculate head.
		rb.head = len(rb.entries) - 1
		rb.entries[rb.head] = e
	}
	rb.head = (rb.head + 1) % len(rb.entries)
	rb.count++
	rb.size += n
	rb.bytesSinceFlush += n

	return n, nil
}

// Flush returns all buffered entries in chronological order and resets
// the bytes-since-flush counter (re-enabling 100% capture).
func (rb *RingBuffer) Flush() [][]byte {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if rb.count == 0 {
		rb.bytesSinceFlush = 0
		return nil
	}

	result := make([][]byte, 0, rb.count)

	// Read from oldest to newest.
	start := (rb.head - rb.count + len(rb.entries)) % len(rb.entries)
	for i := range rb.count {
		idx := (start + i) % len(rb.entries)
		result = append(result, rb.entries[idx].data)
	}

	// Clear the buffer.
	rb.entries = rb.entries[:0]
	rb.head = 0
	rb.count = 0
	rb.size = 0
	rb.bytesSinceFlush = 0

	return result
}

// BytesSinceFlush returns the number of bytes written since the last flush.
func (rb *RingBuffer) BytesSinceFlush() int {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.bytesSinceFlush
}

// Count returns the number of entries currently in the buffer.
func (rb *RingBuffer) Count() int {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.count
}

// Size returns the total bytes currently stored in the buffer.
func (rb *RingBuffer) Size() int {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.size
}

func (rb *RingBuffer) evictOldest() {
	oldest := (rb.head - rb.count + len(rb.entries)) % len(rb.entries)
	rb.size -= len(rb.entries[oldest].data)
	rb.entries[oldest] = entry{}
	rb.count--
}
