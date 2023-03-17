package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/pomerium/pomerium/config"
	hpke_handlers "github.com/pomerium/pomerium/pkg/hpke/handlers"

	"github.com/stretchr/testify/require"
)

func testOptions(t *testing.T) *config.Options {
	t.Helper()

	opts := config.NewDefaultOptions()

	to, err := config.ParseWeightedUrls("https://example.example")
	require.NoError(t, err)

	testPolicy := config.Policy{From: "https://corp.example.example", To: to}
	opts.Policies = []config.Policy{testPolicy}
	opts.InsecureServer = true
	opts.CookieSecure = false
	opts.Services = config.ServiceAll
	opts.SharedKey = "80ldlrU2d7w+wVpKNfevk6fmb8otEx6CqOfshj2LwhQ="
	opts.CookieSecret = "OromP1gurwGWjQPYb1nNgSxtbVB5NnLzX6z5WOKr0Yw="

	hpkePrivateKey, err := opts.GetHPKEPrivateKey()
	require.NoError(t, err)

	authnSrv := httptest.NewServer(hpke_handlers.HPKEPublicKeyHandler(hpkePrivateKey.PublicKey()))
	t.Cleanup(authnSrv.Close)
	opts.AuthenticateURLString = authnSrv.URL

	require.NoError(t, opts.Validate())

	return opts
}

func TestOptions_Validate(t *testing.T) {
	t.Parallel()

	good := testOptions(t)
	badAuthURL := testOptions(t)
	badAuthURL.AuthenticateURLString = "BAD_URL"
	authenticateBadScheme := testOptions(t)
	authenticateBadScheme.AuthenticateURLString = "authenticate.corp.beyondperimeter.com"
	invalidCookieSecret := testOptions(t)
	invalidCookieSecret.CookieSecret = "OromP1gurwGWjQPYb1nNgSxtbVB5NnLzX6z5WOKr0Yw^"
	shortCookieLength := testOptions(t)
	shortCookieLength.CookieSecret = "gN3xnvfsAwfCXxnJorGLKUG4l2wC8sS8nfLMhcStPg=="
	badSharedKey := testOptions(t)
	badSharedKey.Services = "proxy"
	badSharedKey.SharedKey = ""
	sharedKeyBadBas64 := testOptions(t)
	sharedKeyBadBas64.SharedKey = "%(*@389"
	missingPolicy := testOptions(t)
	missingPolicy.Policies = []config.Policy{}

	tests := []struct {
		name    string
		o       *config.Options
		wantErr bool
	}{
		{"good - minimum options", good, false},
		{"nil options", &config.Options{}, true},
		{"invalid cookie secret", invalidCookieSecret, true},
		{"short cookie secret", shortCookieLength, true},
		{"no shared secret", badSharedKey, true},
		{"shared secret bad base64", sharedKeyBadBas64, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := tt.o
			if err := ValidateOptions(o); (err != nil) != tt.wantErr {
				t.Errorf("Options.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	good := testOptions(t)
	shortCookieLength := testOptions(t)
	shortCookieLength.CookieSecret = "gN3xnvfsAwfCXxnJorGLKUG4l2wC8sS8nfLMhcStPg=="
	badCookie := testOptions(t)
	badCookie.CookieName = ""

	tests := []struct {
		name      string
		opts      *config.Options
		wantProxy bool
		wantErr   bool
	}{
		{"good", good, true, false},
		{"empty options", &config.Options{}, false, true},
		{"short secret/validate sanity check", shortCookieLength, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(&config.Config{Options: tt.opts})
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got == nil && tt.wantProxy == true {
				t.Errorf("New() expected valid proxy struct")
			}
		})
	}
}

func Test_UpdateOptions(t *testing.T) {
	t.Parallel()

	good := testOptions(t)
	to, err := config.ParseWeightedUrls("http://foo.example")
	require.NoError(t, err)

	newPolicy := config.Policy{To: to, From: "http://bar.example"}
	newPolicies := testOptions(t)
	newPolicies.Policies = []config.Policy{newPolicy}
	require.NoError(t, newPolicy.Validate())

	toFoo, err := config.ParseWeightedUrls("http://foo.example")
	require.NoError(t, err)

	badPolicyURL := config.Policy{To: []config.WeightedURL{{URL: url.URL{Scheme: "http", Path: "/"}}}, From: "http://bar.example"}
	badNewPolicy := testOptions(t)
	badNewPolicy.Policies = []config.Policy{
		badPolicyURL,
	}
	disableTLSPolicy := config.Policy{To: toFoo, From: "http://bar.example", TLSSkipVerify: true}
	disableTLSPolicies := testOptions(t)
	disableTLSPolicies.Policies = []config.Policy{disableTLSPolicy}

	customCAPolicies := testOptions(t)
	customCAPolicies.Policies = []config.Policy{{To: toFoo, From: "http://bar.example", TLSCustomCA: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURlVENDQW1HZ0F3SUJBZ0lKQUszMmhoR0JIcmFtTUEwR0NTcUdTSWIzRFFFQkN3VUFNR0l4Q3pBSkJnTlYKQkFZVEFsVlRNUk13RVFZRFZRUUlEQXBEWVd4cFptOXlibWxoTVJZd0ZBWURWUVFIREExVFlXNGdSbkpoYm1OcApjMk52TVE4d0RRWURWUVFLREFaQ1lXUlRVMHd4RlRBVEJnTlZCQU1NRENvdVltRmtjM05zTG1OdmJUQWVGdzB4Ck9UQTJNVEl4TlRNeE5UbGFGdzB5TVRBMk1URXhOVE14TlRsYU1HSXhDekFKQmdOVkJBWVRBbFZUTVJNd0VRWUQKVlFRSURBcERZV3hwWm05eWJtbGhNUll3RkFZRFZRUUhEQTFUWVc0Z1JuSmhibU5wYzJOdk1ROHdEUVlEVlFRSwpEQVpDWVdSVFUwd3hGVEFUQmdOVkJBTU1EQ291WW1Ga2MzTnNMbU52YlRDQ0FTSXdEUVlKS29aSWh2Y05BUUVCCkJRQURnZ0VQQURDQ0FRb0NnZ0VCQU1JRTdQaU03Z1RDczloUTFYQll6Sk1ZNjF5b2FFbXdJclg1bFo2eEt5eDIKUG16QVMyQk1UT3F5dE1BUGdMYXcrWExKaGdMNVhFRmRFeXQvY2NSTHZPbVVMbEEzcG1jY1lZejJRVUxGUnRNVwpoeWVmZE9zS25SRlNKaUZ6YklSTWVWWGswV3ZvQmoxSUZWS3RzeWpicXY5dS8yQ1ZTbmRyT2ZFazBURzIzVTNBCnhQeFR1VzFDcmJWOC9xNzFGZEl6U09jaWNjZkNGSHBzS09vM1N0L3FiTFZ5dEg1YW9oYmNhYkZYUk5zS0VxdmUKd3c5SGRGeEJJdUdhK1J1VDVxMGlCaWt1c2JwSkhBd25ucVA3aS9kQWNnQ3NrZ2paakZlRVU0RUZ5K2IrYTFTWQpRQ2VGeHhDN2MzRHZhUmhCQjBWVmZQbGtQejBzdzZsODY1TWFUSWJSeW9VQ0F3RUFBYU15TURBd0NRWURWUjBUCkJBSXdBREFqQmdOVkhSRUVIREFhZ2d3cUxtSmhaSE56YkM1amIyMkNDbUpoWkhOemJDNWpiMjB3RFFZSktvWkkKaHZjTkFRRUxCUUFEZ2dFQkFJaTV1OXc4bWdUNnBwQ2M3eHNHK0E5ZkkzVzR6K3FTS2FwaHI1bHM3MEdCS2JpWQpZTEpVWVpoUGZXcGgxcXRra1UwTEhGUG04M1ZhNTJlSUhyalhUMFZlNEt0TzFuMElBZkl0RmFXNjJDSmdoR1luCmp6dzByeXpnQzRQeUZwTk1uTnRCcm9QdS9iUGdXaU1nTE9OcEVaaGlneDRROHdmMVkvVTlzK3pDQ3hvSmxhS1IKTVhidVE4N1g3bS85VlJueHhvNk56NVpmN09USFRwTk9JNlZqYTBCeGJtSUFVNnlyaXc5VXJnaWJYZk9qM2o2bgpNVExCdWdVVklCMGJCYWFzSnNBTUsrdzRMQU52YXBlWjBET1NuT1I0S0syNEowT3lvRjVmSG1wNTllTTE3SW9GClFxQmh6cG1RVWd1bmVjRVc4QlRxck5wRzc5UjF1K1YrNHd3Y2tQYz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="}}

	badCustomCAPolicies := testOptions(t)
	badCustomCAPolicies.Policies = []config.Policy{{To: toFoo, From: "http://bar.example", TLSCustomCA: "=@@"}}

	goodClientCertPolicies := testOptions(t)
	goodClientCertPolicies.Policies = []config.Policy{{To: toFoo, From: "http://bar.example", TLSClientKey: "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcGdJQkFBS0NBUUVBNjdLanFtUVlHcTBNVnRBQ1ZwZUNtWG1pbmxRYkRQR0xtc1pBVUV3dWVIUW5ydDNXCnR2cERPbTZBbGFKTVVuVytIdTU1ampva2FsS2VWalRLbWdZR2JxVXpWRG9NYlBEYUhla2x0ZEJUTUdsT1VGc1AKNFVKU0RyTzR6ZE4rem80MjhUWDJQbkcyRkNkVktHeTRQRThpbEhiV0xjcjg3MVlqVjUxZnc4Q0xEWDlQWkpOdQo4NjFDRjdWOWlFSm02c1NmUWxtbmhOOGozK1d6VmJQUU55MVdzUjdpOWU5ajYzRXFLdDIyUTlPWEwrV0FjS3NrCm9JU21DTlZSVUFqVThZUlZjZ1FKQit6UTM0QVFQbHowT3A1Ty9RTi9NZWRqYUY4d0xTK2l2L3p2aVM4Y3FQYngKbzZzTHE2Rk5UbHRrL1FreGVDZUtLVFFlLzNrUFl2UUFkbmw2NVFJREFRQUJBb0lCQVFEQVQ0eXN2V2pSY3pxcgpKcU9SeGFPQTJEY3dXazJML1JXOFhtQWhaRmRTWHV2MkNQbGxhTU1yelBmTG41WUlmaHQzSDNzODZnSEdZc3pnClo4aWJiYWtYNUdFQ0t5N3lRSDZuZ3hFS3pRVGpiampBNWR3S0h0UFhQUnJmamQ1Y2FMczVpcDcxaWxCWEYxU3IKWERIaXUycnFtaC9kVTArWGRMLzNmK2VnVDl6bFQ5YzRyUm84dnZueWNYejFyMnVhRVZ2VExsWHVsb2NpeEVrcgoySjlTMmxveWFUb2tFTnNlMDNpSVdaWnpNNElZcVowOGJOeG9IWCszQXVlWExIUStzRkRKMlhaVVdLSkZHMHUyClp3R2w3YlZpRTFQNXdiQUdtZzJDeDVCN1MrdGQyUEpSV3Frb2VxY3F2RVdCc3RFL1FEcDFpVThCOHpiQXd0Y3IKZHc5TXZ6Q2hBb0dCQVBObzRWMjF6MGp6MWdEb2tlTVN5d3JnL2E4RkJSM2R2Y0xZbWV5VXkybmd3eHVucnFsdwo2U2IrOWdrOGovcXEvc3VQSDhVdzNqSHNKYXdGSnNvTkVqNCt2b1ZSM3UrbE5sTEw5b21rMXBoU0dNdVp0b3huCm5nbUxVbkJUMGI1M3BURkJ5WGsveE5CbElreWdBNlg5T2MreW5na3RqNlRyVnMxUERTdnVJY0s1QW9HQkFQZmoKcEUzR2F6cVFSemx6TjRvTHZmQWJBdktCZ1lPaFNnemxsK0ZLZkhzYWJGNkdudFd1dWVhY1FIWFpYZTA1c2tLcApXN2xYQ3dqQU1iUXI3QmdlazcrOSszZElwL1RnYmZCYnN3Syt6Vng3Z2doeWMrdytXRWExaHByWTZ6YXdxdkFaCkhRU2lMUEd1UGp5WXBQa1E2ZFdEczNmWHJGZ1dlTmd4SkhTZkdaT05Bb0dCQUt5WTF3MUM2U3Y2c3VuTC8vNTcKQ2Z5NTAwaXlqNUZBOWRqZkRDNWt4K1JZMnlDV0ExVGsybjZyVmJ6dzg4czBTeDMrYS9IQW1CM2dMRXBSRU5NKwo5NHVwcENFWEQ3VHdlcGUxUnlrTStKbmp4TzlDSE41c2J2U25sUnBQWlMvZzJRTVhlZ3grK2trbkhXNG1ITkFyCndqMlRrMXBBczFXbkJ0TG9WaGVyY01jSkFvR0JBSTYwSGdJb0Y5SysvRUcyY21LbUg5SDV1dGlnZFU2eHEwK0IKWE0zMWMzUHE0amdJaDZlN3pvbFRxa2d0dWtTMjBraE45dC9ibkI2TmhnK1N1WGVwSXFWZldVUnlMejVwZE9ESgo2V1BMTTYzcDdCR3cwY3RPbU1NYi9VRm5Yd0U4OHlzRlNnOUF6VjdVVUQvU0lDYkI5ZHRVMWh4SHJJK0pZRWdWCkFrZWd6N2lCQW9HQkFJRncrQVFJZUIwM01UL0lCbGswNENQTDJEak0rNDhoVGRRdjgwMDBIQU9mUWJrMEVZUDEKQ2FLR3RDbTg2MXpBZjBzcS81REtZQ0l6OS9HUzNYRk00Qm1rRk9nY1NXVENPNmZmTGdLM3FmQzN4WDJudlpIOQpYZGNKTDQrZndhY0x4c2JJKzhhUWNOVHRtb3pkUjEzQnNmUmIrSGpUL2o3dkdrYlFnSkhCT0syegotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=", TLSClientCert: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUVJVENDQWdtZ0F3SUJBZ0lSQVBqTEJxS1lwcWU0ekhQc0dWdFR6T0F3RFFZSktvWklodmNOQVFFTEJRQXcKRWpFUU1BNEdBMVVFQXhNSFoyOXZaQzFqWVRBZUZ3MHhPVEE0TVRBeE9EUTVOREJhRncweU1UQXlNVEF4TnpRdwpNREZhTUJNeEVUQVBCZ05WQkFNVENIQnZiV1Z5YVhWdE1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBCk1JSUJDZ0tDQVFFQTY3S2pxbVFZR3EwTVZ0QUNWcGVDbVhtaW5sUWJEUEdMbXNaQVVFd3VlSFFucnQzV3R2cEQKT202QWxhSk1VblcrSHU1NWpqb2thbEtlVmpUS21nWUdicVV6VkRvTWJQRGFIZWtsdGRCVE1HbE9VRnNQNFVKUwpEck80emROK3pvNDI4VFgyUG5HMkZDZFZLR3k0UEU4aWxIYldMY3I4NzFZalY1MWZ3OENMRFg5UFpKTnU4NjFDCkY3VjlpRUptNnNTZlFsbW5oTjhqMytXelZiUFFOeTFXc1I3aTllOWo2M0VxS3QyMlE5T1hMK1dBY0tza29JU20KQ05WUlVBalU4WVJWY2dRSkIrelEzNEFRUGx6ME9wNU8vUU4vTWVkamFGOHdMUytpdi96dmlTOGNxUGJ4bzZzTApxNkZOVGx0ay9Ra3hlQ2VLS1RRZS8za1BZdlFBZG5sNjVRSURBUUFCbzNFd2J6QU9CZ05WSFE4QkFmOEVCQU1DCkE3Z3dIUVlEVlIwbEJCWXdGQVlJS3dZQkJRVUhBd0VHQ0NzR0FRVUZCd01DTUIwR0ExVWREZ1FXQkJRQ1FYbWIKc0hpcS9UQlZUZVhoQ0dpNjhrVy9DakFmQmdOVkhTTUVHREFXZ0JSNTRKQ3pMRlg0T0RTQ1J0dWNBUGZOdVhWegpuREFOQmdrcWhraUc5dzBCQVFzRkFBT0NBZ0VBcm9XL2trMllleFN5NEhaQXFLNDVZaGQ5ay9QVTFiaDlFK1BRCk5jZFgzTUdEY2NDRUFkc1k4dll3NVE1cnhuMGFzcSt3VGFCcGxoYS9rMi9VVW9IQ1RqUVp1Mk94dEF3UTdPaWIKVE1tMEorU3NWT3d4YnFQTW9rK1RqVE16NFdXaFFUTzVwRmNoZDZXZXNCVHlJNzJ0aG1jcDd1c2NLU2h3YktIegpQY2h1QTQ4SzhPdi96WkxmZnduQVNZb3VCczJjd1ZiRDI3ZXZOMzdoMGFzR1BrR1VXdm1PSDduTHNVeTh3TTdqCkNGL3NwMmJmTC9OYVdNclJnTHZBMGZMS2pwWTQrVEpPbkVxQmxPcCsrbHlJTEZMcC9qMHNybjRNUnlKK0t6UTEKR1RPakVtQ1QvVEFtOS9XSThSL0FlYjcwTjEzTytYNEtaOUJHaDAxTzN3T1Vqd3BZZ3lxSnNoRnNRUG50VmMrSQpKQmF4M2VQU3NicUcwTFkzcHdHUkpRNmMrd1lxdGk2Y0tNTjliYlRkMDhCNUk1N1RRTHhNcUoycTFnWmw1R1VUCmVFZGNWRXltMnZmd0NPd0lrbGNBbThxTm5kZGZKV1FabE5VaHNOVWFBMkVINnlDeXdaZm9aak9hSDEwTXowV20KeTNpZ2NSZFQ3Mi9NR2VkZk93MlV0MVVvRFZmdEcxcysrditUQ1lpNmpUQU05dkZPckJ4UGlOeGFkUENHR2NZZAowakZIc2FWOGFPV1dQQjZBQ1JteHdDVDdRTnRTczM2MlpIOUlFWWR4Q00yMDUrZmluVHhkOUcwSmVRRTd2Kyt6CldoeWo2ZmJBWUIxM2wvN1hkRnpNSW5BOGxpekdrVHB2RHMxeTBCUzlwV3ppYmhqbVFoZGZIejdCZGpGTHVvc2wKZzlNZE5sND0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="}}
	goodClientCertPolicies.Validate()

	customServerName := testOptions(t)
	customServerName.Policies = []config.Policy{{To: toFoo, From: "http://bar.example", TLSServerName: "test"}}

	emptyPolicies := testOptions(t)
	emptyPolicies.Policies = nil

	allowWebSockets := testOptions(t)
	allowWebSockets.Policies = []config.Policy{{To: toFoo, From: "http://bar.example", AllowWebsockets: true}}
	customTimeout := testOptions(t)

	ten := 10 * time.Second
	customTimeout.Policies = []config.Policy{{To: toFoo, From: "http://bar.example", UpstreamTimeout: &ten}}
	corsPreflight := testOptions(t)
	corsPreflight.Policies = []config.Policy{{To: toFoo, From: "http://bar.example", CORSAllowPreflight: true}}
	disableAuth := testOptions(t)
	disableAuth.Policies = []config.Policy{{To: toFoo, From: "http://bar.example", AllowPublicUnauthenticatedAccess: true}}

	reqHeaders := testOptions(t)
	reqHeaders.Policies = []config.Policy{{To: toFoo, From: "http://bar.example", SetRequestHeaders: map[string]string{"x": "y"}}}
	preserveHostHeader := testOptions(t)
	preserveHostHeader.Policies = []config.Policy{{To: toFoo, From: "http://bar.example", PreserveHostHeader: true}}

	tests := []struct {
		name            string
		originalOptions *config.Options
		updatedOptions  *config.Options
		host            string
		wantErr         bool
		wantRoute       bool
	}{
		{"good no change", good, good, "https://corp.example.example", false, true},
		{"changed", good, newPolicies, "https://bar.example", false, true},
		{"changed and missing", good, newPolicies, "https://corp.example.example", false, false},
		{"disable tls verification", good, disableTLSPolicies, "https://bar.example", false, true},
		{"custom root ca", good, customCAPolicies, "https://bar.example", false, true},
		{"good client certs", good, goodClientCertPolicies, "https://bar.example", false, true},
		{"custom server name", customServerName, customServerName, "https://bar.example", false, true},
		{"good no policies to start", emptyPolicies, good, "https://corp.example.example", false, true},
		{"allow websockets", good, allowWebSockets, "https://corp.example.example", false, true},
		{"no websockets, custom timeout", good, customTimeout, "https://corp.example.example", false, true},
		{"enable cors preflight", good, corsPreflight, "https://corp.example.example", false, true},
		{"disable auth", good, disableAuth, "https://corp.example.example", false, true},
		{"set request headers", good, reqHeaders, "https://corp.example.example", false, true},
		{"preserve host headers", preserveHostHeader, preserveHostHeader, "https://corp.example.example", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := New(&config.Config{Options: tt.originalOptions})
			if err != nil {
				t.Fatal(err)
			}

			p.OnConfigChange(context.Background(), &config.Config{Options: tt.updatedOptions})
			r := httptest.NewRequest("GET", tt.host, nil)
			w := httptest.NewRecorder()
			p.ServeHTTP(w, r)
			if tt.wantRoute && w.Code != http.StatusNotFound {
				t.Errorf("Failed to find route handler")
				return
			}
		})
	}

	// Test nil
	var p *Proxy
	p.OnConfigChange(context.Background(), &config.Config{})
}
