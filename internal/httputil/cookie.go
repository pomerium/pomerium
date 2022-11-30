package httputil

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
)

// ErrCookieTooLarge indicates that a cookie is too large.
var ErrCookieTooLarge = errors.New("cookie too large")

const (
	defaultCookieChunkerChunkSize = 3800
	defaultCookieChunkerMaxChunks = 16
)

type cookieChunkerConfig struct {
	chunkSize int
	maxChunks int
}

// A CookieChunkerOption customizes the cookie chunker.
type CookieChunkerOption func(cfg *cookieChunkerConfig)

// WithCookieChunkerChunkSize sets the chunk size for the cookie chunker.
func WithCookieChunkerChunkSize(chunkSize int) CookieChunkerOption {
	return func(cfg *cookieChunkerConfig) {
		cfg.chunkSize = chunkSize
	}
}

// WithCookieChunkerMaxChunks sets the maximum number of chunks for the cookie chunker.
func WithCookieChunkerMaxChunks(maxChunks int) CookieChunkerOption {
	return func(cfg *cookieChunkerConfig) {
		cfg.maxChunks = maxChunks
	}
}

func getCookieChunkerConfig(options ...CookieChunkerOption) *cookieChunkerConfig {
	cfg := new(cookieChunkerConfig)
	WithCookieChunkerChunkSize(defaultCookieChunkerChunkSize)(cfg)
	WithCookieChunkerMaxChunks(defaultCookieChunkerMaxChunks)(cfg)
	for _, option := range options {
		option(cfg)
	}
	return cfg
}

// A CookieChunker breaks up a large cookie into multiple pieces.
type CookieChunker struct {
	cfg *cookieChunkerConfig
}

// NewCookieChunker creates a new CookieChunker.
func NewCookieChunker(options ...CookieChunkerOption) *CookieChunker {
	return &CookieChunker{
		cfg: getCookieChunkerConfig(options...),
	}
}

// SetCookie sets a chunked cookie.
func (cc *CookieChunker) SetCookie(w http.ResponseWriter, cookie *http.Cookie) error {
	chunks := chunk(cookie.Value, cc.cfg.chunkSize)
	if len(chunks) > cc.cfg.maxChunks {
		return ErrCookieTooLarge
	}

	sizeCookie := *cookie
	sizeCookie.Value = strconv.Itoa(len(chunks))
	http.SetCookie(w, &sizeCookie)
	for i, chunk := range chunks {
		chunkCookie := *cookie
		chunkCookie.Name += strconv.Itoa(i)
		chunkCookie.Value = chunk
		http.SetCookie(w, &chunkCookie)
	}
	return nil
}

// LoadCookie loads a chunked cookie.
func (cc *CookieChunker) LoadCookie(r *http.Request, name string) (*http.Cookie, error) {
	sizeCookie, err := r.Cookie(name)
	if err != nil {
		return nil, err
	}

	size, err := strconv.Atoi(sizeCookie.Value)
	if err != nil {
		return nil, err
	}
	if size > cc.cfg.maxChunks {
		return nil, ErrCookieTooLarge
	}

	var b strings.Builder
	for i := 0; i < size; i++ {
		chunkCookie, err := r.Cookie(name + strconv.Itoa(i))
		if err != nil {
			return nil, err
		}
		_, err = b.WriteString(chunkCookie.Value)
		if err != nil {
			return nil, err
		}
	}

	cookie := *sizeCookie
	cookie.Value = b.String()
	return &cookie, nil
}

func chunk(s string, size int) []string {
	ss := make([]string, 0, len(s)/size+1)
	for len(s) > 0 {
		if len(s) < size {
			size = len(s)
		}
		ss, s = append(ss, s[:size]), s[size:]
	}
	return ss
}
