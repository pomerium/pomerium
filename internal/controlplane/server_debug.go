package controlplane

import (
	"io"
	"net/http"
	"net/http/pprof"
	"sync/atomic"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/pomerium/pomerium/config"
)

type debugServer struct {
	mux atomic.Pointer[http.ServeMux]
}

func newDebugServer(cfg *config.Config) *debugServer {
	srv := &debugServer{}
	srv.Update(cfg)
	return srv
}

func (srv *debugServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	srv.mux.Load().ServeHTTP(w, r)
}

func (srv *debugServer) Update(cfg *config.Config) {
	mux := http.NewServeMux()

	// only enable admin endpoints if the runtime flag is set
	if cfg.Options.IsRuntimeFlagSet(config.RuntimeFlagDebugAdminEndpoints) {
		// index
		mux.HandleFunc("GET /", srv.indexHandler())
		// config
		mux.HandleFunc("GET /config_dump", srv.configDumpHandler(cfg))
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
			<li><a href="/debug/pprof/">Go PProf</a></li>
		</ul>
</body>
`)
	}
}
