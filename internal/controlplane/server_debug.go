package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"html/template"
	"io"
	"maps"
	"net/http"
	"net/http/pprof"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync/atomic"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/config"
	channelzdebugui "github.com/pomerium/pomerium/internal/debug/channelz/ui"
	"github.com/pomerium/pomerium/internal/version"
	"github.com/pomerium/pomerium/pkg/envoy/files"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

type DataBrokerClientProvider interface {
	GetLocalDatabrokerServiceClient() databroker.DataBrokerServiceClient
}

type debugServer struct {
	mux              atomic.Pointer[http.ServeMux]
	databrokerClient atomic.Pointer[DataBrokerClientProvider]
	channelZClient   channelzdebugui.ClientProvider
}

func newDebugServer(cfg *config.Config, channelzProv channelzdebugui.ClientProvider) *debugServer {
	srv := &debugServer{
		channelZClient: channelzProv,
	}
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
		mux.HandleFunc("GET /versioned_config", srv.versionedConfigHandler())
		// version
		mux.HandleFunc("GET /version", srv.versionHandler())
		// databroker(options)
		mux.HandleFunc("GET /options/", srv.databrokerOptionsHandler())
		// databroker
		mux.HandleFunc("GET /databroker/", srv.databrokerHandler())
		// Channelz
		// https://github.com/grpc/proposal/blob/master/A14-channelz.md
		// https://github.com/grpc/grpc/blob/master/doc/connectivity-semantics-and-api.md
		s := channelzdebugui.NewServer(srv.channelZClient)
		s.Register(mux, "channelz")

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

func (srv *debugServer) versionHandler() http.HandlerFunc {
	type pomeriumVersion struct {
		Version     string `json:"version"`
		FullVersion string `json:"full_version"`
		GitCommit   string `json:"git_commit"`
		BuildMeta   string `json:"build_meta"`
		BuildTime   string `json:"build_time"`
	}
	type envoyVersion struct {
		Version     string `json:"version"`
		FullVersion string `json:"full_version"`
	}
	type versionInfo struct {
		Pomerium   pomeriumVersion   `json:"pomerium"`
		Envoy      envoyVersion      `json:"envoy"`
		Components map[string]string `json:"components"`
	}

	return func(w http.ResponseWriter, _ *http.Request) {
		info := versionInfo{
			Pomerium: pomeriumVersion{
				Version:     version.Version,
				FullVersion: version.FullVersion(),
				GitCommit:   version.GitCommit,
				BuildMeta:   version.BuildMeta,
				BuildTime:   version.BuildTime(),
			},
			Envoy: envoyVersion{
				Version:     files.Version(),
				FullVersion: files.FullVersion(),
			},
			Components: version.Components(),
		}

		bs, err := json.MarshalIndent(info, "", "  ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write(bs)
	}
}

func (srv *debugServer) versionedConfigHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := readVersionedConfigData(r.Context(), &srv.databrokerClient)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		data.Render(w)
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
			<li><a href="/versioned_config">Versioned Config</a></li>
			<li><a href="/version">Version</a></li>
			<li><a href="/databroker/">Databroker</a></li>
			<li><a href="/options"> Databroker (options)</a></li>
			<li><a href="/debug/pprof/">Go PProf</a></li>
			<li><a href="/channelz">ChannelZ</li>
		</ul>
</body>
`)
	}
}

func (srv *debugServer) databrokerOptionsHandler() http.HandlerFunc {
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
		path = strings.TrimPrefix(path, "/options/")
		parts := strings.Split(path, "/")
		var cleanParts []string
		for _, p := range parts {
			if p != "" {
				cleanParts = append(cleanParts, p)
			}
		}
		parts = cleanParts
		if len(parts) == 0 {
			srv.serveDatabrokerOptionsIndex(w, r, client)
			return
		}
		if len(parts) != 1 {
			http.Error(w, "invalid databroker options request path", http.StatusBadRequest)
			return
		}
		recordType, err := url.PathUnescape(parts[0])
		if err != nil {
			http.Error(w, "invalid record type encoding", http.StatusBadRequest)
			return
		}
		srv.serveDatabrokerOptions(w, r, client, recordType)
	}
}

func (srv *debugServer) serveDatabrokerOptionsIndex(w http.ResponseWriter, r *http.Request, client databroker.DataBrokerServiceClient) {
	stream, err := client.SyncLatest(r.Context(), &databroker.SyncLatestRequest{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	types := make(map[string]struct{})
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
		case *databroker.SyncLatestResponse_Options:
			if r.Options != nil {
				types[r.Options.GetTypeURL()] = struct{}{}
			}
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<html><head><title>Databroker Types</title></head><body><ul>")
	ordTypes := slices.Collect(maps.Keys(types))
	slices.Sort(ordTypes)
	for _, typ := range ordTypes {
		fmt.Fprintf(w, "<li><a href=\"/options/%s\">%s</a></li>", url.PathEscape(typ), html.EscapeString(typ))
	}
	fmt.Fprintf(w, "</ul></body></html>")
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

func (srv *debugServer) serveDatabrokerOptions(w http.ResponseWriter, r *http.Request, client databroker.DataBrokerServiceClient, recordType string) {
	res, err := client.GetOptions(r.Context(), &databroker.GetOptionsRequest{
		Type: recordType,
	})
	if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	o := protojson.MarshalOptions{
		Multiline:     true,
		Indent:        "  ",
		AllowPartial:  true,
		UseProtoNames: true,
	}
	bs, err := o.Marshal(res.Options)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(bs)
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

type versionedConfigData struct {
	Configs  []*configpb.VersionedConfig
	versions map[string]string
}

func readVersionedConfigData(
	ctx context.Context,
	databrokerClient *atomic.Pointer[DataBrokerClientProvider],
) (*versionedConfigData, error) {
	clientPtr := databrokerClient.Load()
	if clientPtr == nil || *clientPtr == nil {
		return nil, fmt.Errorf("databroker client not available")
	}
	client := (*clientPtr).GetLocalDatabrokerServiceClient()

	stream, err := client.SyncLatest(ctx, &databroker.SyncLatestRequest{
		Type: protoutil.GetTypeURL((*configpb.VersionedConfig)(nil)),
	})
	if err != nil {
		return nil, err
	}

	var cfgs []*configpb.VersionedConfig
	for {
		res, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, err
		}
		switch r := res.Response.(type) {
		case *databroker.SyncLatestResponse_Record:
			if r.Record == nil {
				return nil, fmt.Errorf("unexpected empty databroker record")
			}
			var cfg configpb.VersionedConfig
			if err := r.Record.Data.UnmarshalTo(&cfg); err != nil {
				return nil, fmt.Errorf("couldn't unmarshal VersionedConfig: %w", err)
			}
			cfgs = append(cfgs, &cfg)
		}
	}

	versions := version.Components()
	versions[""] = version.Version
	return &versionedConfigData{
		Configs:  cfgs,
		versions: versions,
	}, nil
}

var versionedConfigPageTmpl = template.Must(template.New("versioned_config").Parse(`
<html>
	<head>
		<title>Versioned config</title>
		<style>
			.applicable {
				background-color: #d0ffd0;
			}
			.not-applicable {
				background-color: #ffd0d0;
			}
			.comment {
				color: #005c11;
				font-style: italic;
			}
		</style>
	</head>
	<body>
		<h4>Versioned config records:</h4>
		<ol>
		{{ range .Configs }}
		<li>{{ $.RenderVersionedConfig . }}
		{{ end }}
		</ol>
	</body>
</html>
`))

func (v *versionedConfigData) Render(w io.Writer) error {
	return versionedConfigPageTmpl.Execute(w, v)
}

var versionedConfigTmpl = template.Must(template.New("versioned_config_record").Parse(`
{{ if .Applicable }}✅{{ else }}❌ not{{ end }} applicable
<pre><code>{{ .ConfigJSON }},
  "conditions": [{{ range .Conditions }}
    {{ $.RenderCondition .}}
  {{ end }}]
}</code></pre>
`))

func (v *versionedConfigData) RenderVersionedConfig(cfg *configpb.VersionedConfig) template.HTML {
	applicable := cfg.IsApplicable(v.versions)

	// Remove the conditions field before marshaling to JSON, as we'll render
	// the conditions separately (so we can style them).
	conditions := cfg.Conditions
	cfg = proto.Clone(cfg).(*configpb.VersionedConfig)
	cfg.Conditions = nil

	marshaled, err := protojson.MarshalOptions{
		Multiline:     true,
		Indent:        "  ",
		AllowPartial:  true,
		UseProtoNames: true,
	}.Marshal(cfg)
	if err != nil {
		return template.HTML(
			fmt.Sprintf("[error marshaling VersionedConfig proto: %s]",
				html.EscapeString(err.Error())),
		)
	}
	configJSON := string(marshaled)
	configJSON, _ = strings.CutSuffix(configJSON, "\n}")

	data := struct {
		*versionedConfigData
		Applicable bool
		ConfigJSON string
		Conditions []*configpb.VersionedConfig_Condition
	}{
		versionedConfigData: v,
		Applicable:          applicable,
		ConfigJSON:          configJSON,
		Conditions:          conditions,
	}
	var b bytes.Buffer
	err = versionedConfigTmpl.Execute(&b, data)
	if err != nil {
		return template.HTML(
			fmt.Sprintf("[error rendering VersionedConfig proto: %s]",
				html.EscapeString(err.Error())),
		)
	}
	return template.HTML(b.String())
}

var versionedConfigConditionTmpl = template.Must(template.New("versioned_config_record").Parse(`<span
  class="{{ if .Applicable }}applicable{{ else }}not-applicable{{ end }}">{{ .JSON }}</span>, <span
  class="comment">// {{ .Feature }} = {{ .Version }}</span>`))

func (v *versionedConfigData) RenderCondition(c *configpb.VersionedConfig_Condition) template.HTML {
	conditionJSON, err := protojson.MarshalOptions{
		AllowPartial:  true,
		UseProtoNames: true,
	}.Marshal(c)
	if err != nil {
		return template.HTML(
			fmt.Sprintf("[error marshaling condition: %s]",
				html.EscapeString(err.Error())),
		)
	}
	// Re-indent to fit inside the marshaled VersionedConfig proto.
	var b bytes.Buffer
	json.Indent(&b, conditionJSON, "    ", "  ")

	featureVersion, exists := v.versions[c.GetFeature()]
	if !exists {
		featureVersion = "[unknown]"
	}

	data := struct {
		Applicable bool
		JSON       string
		Feature    string
		Version    string
	}{
		Applicable: c.IsApplicable(v.versions),
		JSON:       b.String(),
		Feature:    fmt.Sprintf("%q", c.GetFeature()),
		Version:    featureVersion,
	}
	b.Reset()
	err = versionedConfigConditionTmpl.Execute(&b, data)
	if err != nil {
		return template.HTML(
			fmt.Sprintf("[error rendering condition: %s]",
				html.EscapeString(err.Error())),
		)
	}
	return template.HTML(b.String())
}
