package controlplane_test

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
)

// TestXDSListenerSurvivesInsecureServerFlip turns insecure_server on through a
// databroker config record and then off again. After each change, a public
// route must answer on the main address with the matching scheme.
func TestXDSListenerSurvivesInsecureServerFlip(t *testing.T) {
	const recoveryWait = 30 * time.Second

	e := newXDSEnv(t)
	route := e.route("flip")
	httpsURL := route.GetFrom()
	httpURL := strings.Replace(httpsURL, "https://", "http://", 1)
	e.putConfig("route", &configpb.Config{Name: "route", Routes: []*configpb.Route{route}})
	ok, last := e.reachable(recoveryWait, httpsURL)
	require.Truef(t, ok, "the route never answered over https, last status %v", last)

	setInsecureServer := func(insecure bool) {
		e.putConfig("settings", &configpb.Config{Name: "settings", Settings: &configpb.Settings{InsecureServer: &insecure}})
	}

	xdsLog := e.recordXDS()
	setInsecureServer(true)
	ok, last = e.reachable(recoveryWait, httpURL)
	if !ok {
		t.Fatalf("with insecure_server on, the route did not answer over http within %s, last status %v\nxDS log:%s",
			recoveryWait, last, formatXDSLog(xdsLog))
	}
	xdsLog.Close()

	xdsLog = e.recordXDS()
	setInsecureServer(false)
	ok, last = e.reachable(recoveryWait, httpsURL)
	if !ok {
		t.Fatalf("with insecure_server off again, the route did not answer over https within %s, last status %v\nxDS log:%s",
			recoveryWait, last, formatXDSLog(xdsLog))
	}
	xdsLog.Close()
}
