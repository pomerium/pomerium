package fanout

import "time"

const (
	defaultPublishTimeout = time.Second
	minPublishTimeout     = time.Millisecond * 100

	defaultReceiverCallbackTimeout = time.Second
	minReceiverCallbackTimeout     = time.Millisecond * 100

	defaultAddSubscriberTimeout = time.Millisecond * 100
	minAddSubscriberTimeout     = time.Millisecond * 100

	defaultReceiverBufferSize   = 100
	defaultMessageBufferSize    = 1024
	defaultSubscriberBufferSize = 100
)

type config struct {
	publishTimeout          time.Duration
	receiverBufferSize      int
	receiverCallbackTimeout time.Duration
	publishBufferSize       int
	subscriberBufferSize    int
	addSubscriberTimeout    time.Duration
}

// Option configures a FanOut
type Option func(*config)

// WithPublishTimeout sets the internal timeout for publishing messages to the fanout
func WithPublishTimeout(timeout time.Duration) Option {
	if timeout < defaultPublishTimeout {
		timeout = defaultPublishTimeout
	}

	return func(c *config) {
		c.publishTimeout = timeout
	}
}

// WithReceiverBufferSize sets the buffer size for the buffer between fanout and subscriber receiver
func WithReceiverBufferSize(size int) Option {
	if size < 1 {
		size = 1
	}
	return func(c *config) {
		c.receiverBufferSize = size
	}
}

// WithReceiverCallbackTimeout sets the timeout for the callback function of the receiver
func WithReceiverCallbackTimeout(timeout time.Duration) Option {
	if timeout < minReceiverCallbackTimeout {
		timeout = minReceiverCallbackTimeout
	}

	return func(c *config) {
		c.receiverCallbackTimeout = timeout
	}
}

// WithMessagesBufferSize sets the buffer size for the buffer that holds messages to be published
func WithMessagesBufferSize(size int) Option {
	if size < 1 {
		size = 1
	}
	return func(c *config) {
		c.publishBufferSize = size
	}
}

// WithSubscriberBufferSize sets the new subscriber requsts buffer size
func WithSubscriberBufferSize(size int) Option {
	if size < 1 {
		size = 1
	}
	return func(c *config) {
		c.subscriberBufferSize = size
	}
}

// WithAddSubscriberTimeout sets the timeout for adding a subscriber
// If it is not possible to add a subscriber within the timeout,
// it means the fanout is at capacity, and it is better to reject the subscriber,
// that will likely be propagated to the downstream,
// which would retry and eventually succeed with another instance
func WithAddSubscriberTimeout(timeout time.Duration) Option {
	if timeout < minAddSubscriberTimeout {
		timeout = minAddSubscriberTimeout
	}

	return func(c *config) {
		c.addSubscriberTimeout = timeout
	}
}

func defaultFanOutConfig() config {
	var c config
	c.apply(
		WithPublishTimeout(defaultPublishTimeout),
		WithMessagesBufferSize(defaultMessageBufferSize),
		WithReceiverCallbackTimeout(defaultReceiverCallbackTimeout),
		WithReceiverBufferSize(defaultReceiverBufferSize),
		WithSubscriberBufferSize(defaultSubscriberBufferSize),
		WithAddSubscriberTimeout(defaultAddSubscriberTimeout),
	)
	return c
}

func (c *config) apply(opts ...Option) {
	for _, opt := range opts {
		opt(c)
	}
}
