package log // import "github.com/pomerium/pomerium/internal/log"

import (
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Used to stash the authenticated user in the response for access when logging requests.
const loggingUserHeader = "SSO-Authenticated-User"
const gapMetaDataHeader = "GAP-Auth"

// responseLogger is wrapper of http.ResponseWriter that keeps track of its HTTP status
// code and body size
type responseLogger struct {
	w         http.ResponseWriter
	status    int
	size      int
	proxyHost string
	authInfo  string
}

func (l *responseLogger) Header() http.Header {
	return l.w.Header()
}

func (l *responseLogger) extractUser() {
	authInfo := l.w.Header().Get(loggingUserHeader)
	if authInfo != "" {
		l.authInfo = authInfo
		l.w.Header().Del(loggingUserHeader)
	}
}

func (l *responseLogger) ExtractGAPMetadata() {
	authInfo := l.w.Header().Get(gapMetaDataHeader)
	if authInfo != "" {
		l.authInfo = authInfo

		l.w.Header().Del(gapMetaDataHeader)
	}
}

func (l *responseLogger) Write(b []byte) (int, error) {
	if l.status == 0 {
		// The status will be StatusOK if WriteHeader has not been called yet
		l.status = http.StatusOK
	}
	l.extractUser()
	l.ExtractGAPMetadata()

	size, err := l.w.Write(b)
	l.size += size
	return size, err
}

func (l *responseLogger) WriteHeader(s int) {
	l.extractUser()
	l.ExtractGAPMetadata()

	l.w.WriteHeader(s)
	l.status = s
}

func (l *responseLogger) Status() int {
	return l.status
}

func (l *responseLogger) Size() int {
	return l.size
}

func (l *responseLogger) Flush() {
	f := l.w.(http.Flusher)
	f.Flush()
}

// loggingHandler is the http.Handler implementation for LoggingHandlerTo and its friends
type loggingHandler struct {
	handler http.Handler
}

// NewLoggingHandler returns a new loggingHandler that wraps a handler, and writer.
func NewLoggingHandler(h http.Handler) http.Handler {
	return loggingHandler{
		handler: h,
	}
}

func (h loggingHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	t := time.Now()
	url := *req.URL
	logger := &responseLogger{w: w, proxyHost: getProxyHost(req)}
	h.handler.ServeHTTP(logger, req)
	requestDuration := time.Since(t)

	logRequest(logger.proxyHost, logger.authInfo, req, url, requestDuration, logger.Status())
}

// logRequest logs information about a request
func logRequest(proxyHost, username string, req *http.Request, url url.URL, requestDuration time.Duration, status int) {
	uri := req.Host + url.RequestURI()
	Info().
		Int("http-status", status).
		Str("request-method", req.Method).
		Str("request-uri", uri).
		Str("proxy-host", proxyHost).
		// Str("user-agent", req.Header.Get("User-Agent")).
		Str("remote-address", getRemoteAddr(req)).
		Dur("duration", requestDuration).
		Str("user", username).
		Msg("request")

}

// getRemoteAddr returns the client IP address from a request. If present, the
// X-Forwarded-For header is assumed to be set by a load balancer, and its
// rightmost entry (the client IP that connected to the LB) is returned.
func getRemoteAddr(req *http.Request) string {
	addr := req.RemoteAddr
	forwardedHeader := req.Header.Get("X-Forwarded-For")
	if forwardedHeader != "" {
		forwardedList := strings.Split(forwardedHeader, ",")
		forwardedAddr := strings.TrimSpace(forwardedList[len(forwardedList)-1])
		if forwardedAddr != "" {
			addr = forwardedAddr
		}
	}
	return addr
}

// getProxyHost attempts to get the proxy host from the redirect_uri parameter
func getProxyHost(req *http.Request) string {
	err := req.ParseForm()
	if err != nil {
		return ""
	}
	redirect := req.Form.Get("redirect_uri")
	redirectURL, err := url.Parse(redirect)
	if err != nil {
		return ""
	}
	return redirectURL.Host
}
