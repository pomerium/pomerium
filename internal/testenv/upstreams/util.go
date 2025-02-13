package upstreams

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pomerium/pomerium/integration/forms"
	"github.com/pomerium/pomerium/internal/retry"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/proto"
)

var ErrRetry = errors.New("error")

func doAuthenticatedRequest(
	ctx context.Context,
	newRequest func(context.Context) (*http.Request, error),
	getClient func(context.Context) *http.Client,
	options *RequestOptions,
) (*http.Response, error) {
	var resp *http.Response
	resendCount := 0
	client := getClient(ctx)

	if err := retry.Retry(ctx, "http", func(ctx context.Context) error {
		req, err := newRequest(ctx)
		if err != nil {
			return retry.NewTerminalError(err)
		}

		switch body := options.body.(type) {
		case string:
			req.Body = io.NopCloser(strings.NewReader(body))
		case []byte:
			req.Body = io.NopCloser(bytes.NewReader(body))
		case io.Reader:
			req.Body = io.NopCloser(body)
		case proto.Message:
			buf, err := proto.Marshal(body)
			if err != nil {
				return retry.NewTerminalError(err)
			}
			req.Body = io.NopCloser(bytes.NewReader(buf))
			req.Header.Set("Content-Type", "application/octet-stream")
		default:
			buf, err := json.Marshal(body)
			if err != nil {
				panic(fmt.Sprintf("unsupported body type: %T", body))
			}
			req.Body = io.NopCloser(bytes.NewReader(buf))
			req.Header.Set("Content-Type", "application/json")
		case nil:
		}

		if options.headers != nil && req.Header == nil {
			req.Header = http.Header{}
		}
		for k, v := range options.headers {
			req.Header.Add(k, v)
		}

		if options.authenticateAs != "" {
			resp, err = authenticateFlow(ctx, client, req, options.authenticateAs, true) //nolint:bodyclose
		} else {
			resp, err = client.Do(req) //nolint:bodyclose
		}
		// retry on connection refused
		span := oteltrace.SpanFromContext(ctx)
		if err != nil {
			span.RecordError(err)
			var opErr *net.OpError
			if errors.As(err, &opErr) && opErr.Op == "dial" && opErr.Err.Error() == "connect: connection refused" {
				span.AddEvent("Retrying on dial error")
				return err
			}
			return retry.NewTerminalError(err)
		}
		if resp.StatusCode/100 == 5 {
			resendCount++
			_, _ = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			span.SetAttributes(semconv.HTTPRequestResendCount(resendCount))
			span.AddEvent("Retrying on 5xx error", oteltrace.WithAttributes(
				attribute.String("status", resp.Status),
			))
			return errors.New(http.StatusText(resp.StatusCode))
		}
		span.SetStatus(codes.Ok, "request completed successfully")
		return nil
	},
		retry.WithInitialInterval(1*time.Millisecond),
		retry.WithMaxInterval(100*time.Millisecond),
	); err != nil {
		return nil, err
	}
	return resp, nil
}

func authenticateFlow(ctx context.Context, client *http.Client, req *http.Request, email string, checkLocation bool) (*http.Response, error) {
	span := oteltrace.SpanFromContext(ctx)
	var res *http.Response
	originalHostname := req.URL.Hostname()
	res, err := client.Do(req)
	if err != nil {
		span.RecordError(err)
		return nil, err
	}
	location := res.Request.URL
	if checkLocation && location.Hostname() == originalHostname {
		// already authenticated
		span.SetStatus(codes.Ok, "already authenticated")
		return res, nil
	}
	fs := forms.Parse(res.Body)
	_, _ = io.ReadAll(res.Body)
	_ = res.Body.Close()
	if len(fs) > 0 {
		f := fs[0]
		f.Inputs["email"] = email
		f.Inputs["token_expiration"] = strconv.Itoa(int((time.Hour * 24).Seconds()))
		span.AddEvent("submitting form", oteltrace.WithAttributes(attribute.String("location", location.String())))
		formReq, err := f.NewRequestWithContext(ctx, location)
		if err != nil {
			span.RecordError(err)
			return nil, err
		}
		resp, err := client.Do(formReq)
		if err != nil {
			span.RecordError(err)
			return nil, err
		}
		span.SetStatus(codes.Ok, "form submitted successfully")
		return resp, nil
	}
	return nil, fmt.Errorf("test bug: expected IDP login form")
}

type rwConn struct {
	serverReader io.ReadCloser
	serverWriter io.WriteCloser

	net.Conn
	remote net.Conn

	closeOnce sync.Once
	wg        *sync.WaitGroup
}

func NewRWConn(reader io.ReadCloser, writer io.WriteCloser) *rwConn {
	rwc := &rwConn{
		serverReader: reader,
		serverWriter: writer,
		wg:           &sync.WaitGroup{},
	}

	rwc.Conn, rwc.remote = net.Pipe()
	rwc.wg.Add(2)
	go func() {
		defer rwc.wg.Done()
		io.Copy(rwc.remote, rwc.serverReader)
		rwc.remote.Close()
	}()
	go func() {
		defer rwc.wg.Done()
		io.Copy(rwc.serverWriter, rwc.remote)
		rwc.serverWriter.Close()
	}()
	return rwc
}

func (rwc *rwConn) Close() error {
	var err error
	rwc.closeOnce.Do(func() {
		readerErr := rwc.serverReader.Close()
		localErr := rwc.Conn.Close()
		rwc.wg.Wait()
		err = errors.Join(localErr, readerErr)
	})
	return err
}

var _ net.Conn = (*rwConn)(nil)
