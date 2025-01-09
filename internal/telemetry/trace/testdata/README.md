These trace recordings are generated as follows:

- recording_01_single_trace.json:

`go test -v -run "^TestOTLPTracing$" -env.trace-debug-flags=+32 github.com/pomerium/pomerium/internal/testenv/selftests | grep -ozP "(?s)(?<=All Events:\n).*?(?=\n=====)"`

- recording_02_multi_trace.json:

`go test -v -run "^TestOTLPTracing_TraceCorrelation$" -env.trace-debug-flags=+32 github.com/pomerium/pomerium/internal/testenv/selftests | grep -ozP "(?s)(?<=All Events:\n).*?(?=\n=====)"`
