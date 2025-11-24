package controlplane

import (
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/pprof"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

type DataBrokerClientProvider interface {
	GetLocalDatabrokerServiceClient() databroker.DataBrokerServiceClient
}

type debugServer struct {
	mux              atomic.Pointer[http.ServeMux]
	databrokerClient atomic.Pointer[DataBrokerClientProvider]
}

func newDebugServer(cfg *config.Config) *debugServer {
	srv := &debugServer{}
	srv.Update(cfg)
	return srv
}

func (srv *debugServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	srv.mux.Load().ServeHTTP(w, r)
}

func (srv *debugServer) SetDataBrokerClient(client DataBrokerClientProvider) {
	srv.databrokerClient.Store(&client)
}

func (srv *debugServer) Update(cfg *config.Config) {
	mux := http.NewServeMux()

	// only enable admin endpoints if the runtime flag is set
	if cfg.Options.IsRuntimeFlagSet(config.RuntimeFlagDebugAdminEndpoints) {
		// index
		mux.HandleFunc("GET /", srv.indexHandler())
		// config
		mux.HandleFunc("GET /config_dump", srv.configDumpHandler(cfg))
		// databroker
		mux.HandleFunc("GET /databroker/", srv.databrokerHandler())
	}

	// pprof
	mux.HandleFunc("GET /debug/pprof/", pprof.Index)
	mux.HandleFunc("GET /debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("GET /debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("GET /debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("GET /debug/pprof/trace", pprof.Trace)

	srv.mux.Store(mux)
}

func (srv *debugServer) configDumpHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		o := protojson.MarshalOptions{
			Multiline:     true,
			Indent:        "  ",
			AllowPartial:  true,
			UseProtoNames: true,
		}
		bs, err := o.Marshal(cfg.Options.ToProto())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write(bs)
	}
}

func (srv *debugServer) indexHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, `<html>
<head>
<title>Pomerium Debug</title>
</head>
<body>
		<ul>
			<li><a href="/config_dump">Config Dump</a></li>
			<li><a href="/databroker/">Databroker</a></li>
			<li><a href="/debug/pprof/">Go PProf</a></li>
		</ul>
</body>
`)
	}
}

func (srv *debugServer) databrokerHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientPtr := srv.databrokerClient.Load()
		if clientPtr == nil || *clientPtr == nil {
			http.Error(w, "databroker client not available", http.StatusServiceUnavailable)
			return
		}
		client := (*clientPtr).GetLocalDatabrokerServiceClient()

		path := r.URL.Path
		if r.URL.RawPath != "" {
			path = r.URL.RawPath
		}
		path = strings.TrimPrefix(path, "/databroker/")
		parts := strings.Split(path, "/")

		var cleanParts []string
		for _, p := range parts {
			if p != "" {
				cleanParts = append(cleanParts, p)
			}
		}
		parts = cleanParts

		if len(parts) == 0 {
			srv.serveDatabrokerIndex(w, r, client)
			return
		}

		recordType, err := url.PathUnescape(parts[0])
		if err != nil {
			http.Error(w, "invalid record type encoding", http.StatusBadRequest)
			return
		}

		if len(parts) == 1 {
			srv.serveDatabrokerList(w, r, client, recordType)
			return
		}

		recordID, err := url.PathUnescape(parts[1])
		if err != nil {
			http.Error(w, "invalid record id encoding", http.StatusBadRequest)
			return
		}
		srv.serveDatabrokerRecord(w, r, client, recordType, recordID)
	}
}

func (srv *debugServer) serveDatabrokerIndex(w http.ResponseWriter, r *http.Request, client databroker.DataBrokerServiceClient) {
	stream, err := client.SyncLatest(r.Context(), &databroker.SyncLatestRequest{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	types := make(map[string]int)
	for {
		res, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		switch r := res.Response.(type) {
		case *databroker.SyncLatestResponse_Record:
			if r.Record != nil {
				types[r.Record.Type]++
			}
		}
	}

	var typeList []string
	for t := range types {
		typeList = append(typeList, t)
	}
	sort.Strings(typeList)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<html><head><title>Databroker Types</title></head><body><ul>")
	for _, t := range typeList {
		fmt.Fprintf(w, "<li><a href=\"/databroker/%s\">%s (%d)</a></li>", url.PathEscape(t), html.EscapeString(t), types[t])
	}
	fmt.Fprintf(w, "</ul></body></html>")
}

func (srv *debugServer) serveDatabrokerList(w http.ResponseWriter, r *http.Request, client databroker.DataBrokerServiceClient, recordType string) {
	stream, err := client.SyncLatest(r.Context(), &databroker.SyncLatestRequest{
		Type: recordType,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<html><head><title>Databroker %s</title></head><body><ul>", html.EscapeString(recordType))

	for {
		res, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			fmt.Fprintf(w, "<li>error: %s</li>", html.EscapeString(err.Error()))
			break
		}
		switch r := res.Response.(type) {
		case *databroker.SyncLatestResponse_Record:
			if r.Record != nil {
				fmt.Fprintf(w, "<li><a href=\"/databroker/%s/%s\">%s</a></li>", url.PathEscape(recordType), url.PathEscape(r.Record.Id), html.EscapeString(r.Record.Id))
			}
		}
	}
	fmt.Fprintf(w, "</ul></body></html>")
}

func (srv *debugServer) serveDatabrokerRecord(w http.ResponseWriter, r *http.Request, client databroker.DataBrokerServiceClient, recordType, recordID string) {
	res, err := client.Get(r.Context(), &databroker.GetRequest{
		Type: recordType,
		Id:   recordID,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if res.Record == nil {
		http.Error(w, "record not found", http.StatusNotFound)
		return
	}

	o := protojson.MarshalOptions{
		Multiline:     true,
		Indent:        "  ",
		AllowPartial:  true,
		UseProtoNames: true,
	}
	bs, err := o.Marshal(res.Record)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(bs)
}
