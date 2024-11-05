package config_test

import (
	"encoding/json"
	"fmt"
	mathrand "math/rand/v2"
	"net/url"
	"runtime"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	"github.com/google/go-cmp/cmp"
	"github.com/pomerium/protoutil/protorand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/hashutil"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/policy/parser"

	_ "go4.org/unsafe/assume-no-moving-gc"
)

func Test_PolicyValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		policy  config.Policy
		wantErr bool
	}{
		{"good", config.Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://httpbin.corp.notatld")}, false},
		{"empty to host", config.Policy{From: "https://httpbin.corp.example", To: []config.WeightedURL{{URL: url.URL{Scheme: "https", Path: "/"}}}}, true},
		{"empty from host", config.Policy{From: "https://", To: mustParseWeightedURLs(t, "https://httpbin.corp.example")}, true},
		{"empty from scheme", config.Policy{From: "httpbin.corp.example", To: mustParseWeightedURLs(t, "https://httpbin.corp.example")}, true},
		{"empty to scheme", config.Policy{From: "https://httpbin.corp.example", To: []config.WeightedURL{{URL: url.URL{Host: "httpbin.corp.example"}}}}, true},
		{"path in from", config.Policy{From: "https://httpbin.corp.example/some/path", To: mustParseWeightedURLs(t, "https://httpbin.corp.example")}, true},
		{"cors policy", config.Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://httpbin.corp.notatld"), CORSAllowPreflight: true}, false},
		{"public policy", config.Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://httpbin.corp.notatld"), AllowPublicUnauthenticatedAccess: true}, false},
		{"public and whitelist", config.Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://httpbin.corp.notatld"), AllowPublicUnauthenticatedAccess: true, AllowedUsers: []string{"test@domain.example"}}, true},
		{"route must have", config.Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://httpbin.corp.notatld"), AllowPublicUnauthenticatedAccess: true, AllowedUsers: []string{"test@domain.example"}}, true},
		{"any authenticated user policy", config.Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://httpbin.corp.notatld"), AllowAnyAuthenticatedUser: true}, false},
		{"any authenticated user and whitelist", config.Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://httpbin.corp.notatld"), AllowAnyAuthenticatedUser: true, AllowedUsers: []string{"test@domain.example"}}, true},
		{"good client cert", config.Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://httpbin.corp.notatld"), TLSClientKey: "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcGdJQkFBS0NBUUVBNjdLanFtUVlHcTBNVnRBQ1ZwZUNtWG1pbmxRYkRQR0xtc1pBVUV3dWVIUW5ydDNXCnR2cERPbTZBbGFKTVVuVytIdTU1ampva2FsS2VWalRLbWdZR2JxVXpWRG9NYlBEYUhla2x0ZEJUTUdsT1VGc1AKNFVKU0RyTzR6ZE4rem80MjhUWDJQbkcyRkNkVktHeTRQRThpbEhiV0xjcjg3MVlqVjUxZnc4Q0xEWDlQWkpOdQo4NjFDRjdWOWlFSm02c1NmUWxtbmhOOGozK1d6VmJQUU55MVdzUjdpOWU5ajYzRXFLdDIyUTlPWEwrV0FjS3NrCm9JU21DTlZSVUFqVThZUlZjZ1FKQit6UTM0QVFQbHowT3A1Ty9RTi9NZWRqYUY4d0xTK2l2L3p2aVM4Y3FQYngKbzZzTHE2Rk5UbHRrL1FreGVDZUtLVFFlLzNrUFl2UUFkbmw2NVFJREFRQUJBb0lCQVFEQVQ0eXN2V2pSY3pxcgpKcU9SeGFPQTJEY3dXazJML1JXOFhtQWhaRmRTWHV2MkNQbGxhTU1yelBmTG41WUlmaHQzSDNzODZnSEdZc3pnClo4aWJiYWtYNUdFQ0t5N3lRSDZuZ3hFS3pRVGpiampBNWR3S0h0UFhQUnJmamQ1Y2FMczVpcDcxaWxCWEYxU3IKWERIaXUycnFtaC9kVTArWGRMLzNmK2VnVDl6bFQ5YzRyUm84dnZueWNYejFyMnVhRVZ2VExsWHVsb2NpeEVrcgoySjlTMmxveWFUb2tFTnNlMDNpSVdaWnpNNElZcVowOGJOeG9IWCszQXVlWExIUStzRkRKMlhaVVdLSkZHMHUyClp3R2w3YlZpRTFQNXdiQUdtZzJDeDVCN1MrdGQyUEpSV3Frb2VxY3F2RVdCc3RFL1FEcDFpVThCOHpiQXd0Y3IKZHc5TXZ6Q2hBb0dCQVBObzRWMjF6MGp6MWdEb2tlTVN5d3JnL2E4RkJSM2R2Y0xZbWV5VXkybmd3eHVucnFsdwo2U2IrOWdrOGovcXEvc3VQSDhVdzNqSHNKYXdGSnNvTkVqNCt2b1ZSM3UrbE5sTEw5b21rMXBoU0dNdVp0b3huCm5nbUxVbkJUMGI1M3BURkJ5WGsveE5CbElreWdBNlg5T2MreW5na3RqNlRyVnMxUERTdnVJY0s1QW9HQkFQZmoKcEUzR2F6cVFSemx6TjRvTHZmQWJBdktCZ1lPaFNnemxsK0ZLZkhzYWJGNkdudFd1dWVhY1FIWFpYZTA1c2tLcApXN2xYQ3dqQU1iUXI3QmdlazcrOSszZElwL1RnYmZCYnN3Syt6Vng3Z2doeWMrdytXRWExaHByWTZ6YXdxdkFaCkhRU2lMUEd1UGp5WXBQa1E2ZFdEczNmWHJGZ1dlTmd4SkhTZkdaT05Bb0dCQUt5WTF3MUM2U3Y2c3VuTC8vNTcKQ2Z5NTAwaXlqNUZBOWRqZkRDNWt4K1JZMnlDV0ExVGsybjZyVmJ6dzg4czBTeDMrYS9IQW1CM2dMRXBSRU5NKwo5NHVwcENFWEQ3VHdlcGUxUnlrTStKbmp4TzlDSE41c2J2U25sUnBQWlMvZzJRTVhlZ3grK2trbkhXNG1ITkFyCndqMlRrMXBBczFXbkJ0TG9WaGVyY01jSkFvR0JBSTYwSGdJb0Y5SysvRUcyY21LbUg5SDV1dGlnZFU2eHEwK0IKWE0zMWMzUHE0amdJaDZlN3pvbFRxa2d0dWtTMjBraE45dC9ibkI2TmhnK1N1WGVwSXFWZldVUnlMejVwZE9ESgo2V1BMTTYzcDdCR3cwY3RPbU1NYi9VRm5Yd0U4OHlzRlNnOUF6VjdVVUQvU0lDYkI5ZHRVMWh4SHJJK0pZRWdWCkFrZWd6N2lCQW9HQkFJRncrQVFJZUIwM01UL0lCbGswNENQTDJEak0rNDhoVGRRdjgwMDBIQU9mUWJrMEVZUDEKQ2FLR3RDbTg2MXpBZjBzcS81REtZQ0l6OS9HUzNYRk00Qm1rRk9nY1NXVENPNmZmTGdLM3FmQzN4WDJudlpIOQpYZGNKTDQrZndhY0x4c2JJKzhhUWNOVHRtb3pkUjEzQnNmUmIrSGpUL2o3dkdrYlFnSkhCT0syegotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=", TLSClientCert: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUVJVENDQWdtZ0F3SUJBZ0lSQVBqTEJxS1lwcWU0ekhQc0dWdFR6T0F3RFFZSktvWklodmNOQVFFTEJRQXcKRWpFUU1BNEdBMVVFQXhNSFoyOXZaQzFqWVRBZUZ3MHhPVEE0TVRBeE9EUTVOREJhRncweU1UQXlNVEF4TnpRdwpNREZhTUJNeEVUQVBCZ05WQkFNVENIQnZiV1Z5YVhWdE1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBCk1JSUJDZ0tDQVFFQTY3S2pxbVFZR3EwTVZ0QUNWcGVDbVhtaW5sUWJEUEdMbXNaQVVFd3VlSFFucnQzV3R2cEQKT202QWxhSk1VblcrSHU1NWpqb2thbEtlVmpUS21nWUdicVV6VkRvTWJQRGFIZWtsdGRCVE1HbE9VRnNQNFVKUwpEck80emROK3pvNDI4VFgyUG5HMkZDZFZLR3k0UEU4aWxIYldMY3I4NzFZalY1MWZ3OENMRFg5UFpKTnU4NjFDCkY3VjlpRUptNnNTZlFsbW5oTjhqMytXelZiUFFOeTFXc1I3aTllOWo2M0VxS3QyMlE5T1hMK1dBY0tza29JU20KQ05WUlVBalU4WVJWY2dRSkIrelEzNEFRUGx6ME9wNU8vUU4vTWVkamFGOHdMUytpdi96dmlTOGNxUGJ4bzZzTApxNkZOVGx0ay9Ra3hlQ2VLS1RRZS8za1BZdlFBZG5sNjVRSURBUUFCbzNFd2J6QU9CZ05WSFE4QkFmOEVCQU1DCkE3Z3dIUVlEVlIwbEJCWXdGQVlJS3dZQkJRVUhBd0VHQ0NzR0FRVUZCd01DTUIwR0ExVWREZ1FXQkJRQ1FYbWIKc0hpcS9UQlZUZVhoQ0dpNjhrVy9DakFmQmdOVkhTTUVHREFXZ0JSNTRKQ3pMRlg0T0RTQ1J0dWNBUGZOdVhWegpuREFOQmdrcWhraUc5dzBCQVFzRkFBT0NBZ0VBcm9XL2trMllleFN5NEhaQXFLNDVZaGQ5ay9QVTFiaDlFK1BRCk5jZFgzTUdEY2NDRUFkc1k4dll3NVE1cnhuMGFzcSt3VGFCcGxoYS9rMi9VVW9IQ1RqUVp1Mk94dEF3UTdPaWIKVE1tMEorU3NWT3d4YnFQTW9rK1RqVE16NFdXaFFUTzVwRmNoZDZXZXNCVHlJNzJ0aG1jcDd1c2NLU2h3YktIegpQY2h1QTQ4SzhPdi96WkxmZnduQVNZb3VCczJjd1ZiRDI3ZXZOMzdoMGFzR1BrR1VXdm1PSDduTHNVeTh3TTdqCkNGL3NwMmJmTC9OYVdNclJnTHZBMGZMS2pwWTQrVEpPbkVxQmxPcCsrbHlJTEZMcC9qMHNybjRNUnlKK0t6UTEKR1RPakVtQ1QvVEFtOS9XSThSL0FlYjcwTjEzTytYNEtaOUJHaDAxTzN3T1Vqd3BZZ3lxSnNoRnNRUG50VmMrSQpKQmF4M2VQU3NicUcwTFkzcHdHUkpRNmMrd1lxdGk2Y0tNTjliYlRkMDhCNUk1N1RRTHhNcUoycTFnWmw1R1VUCmVFZGNWRXltMnZmd0NPd0lrbGNBbThxTm5kZGZKV1FabE5VaHNOVWFBMkVINnlDeXdaZm9aak9hSDEwTXowV20KeTNpZ2NSZFQ3Mi9NR2VkZk93MlV0MVVvRFZmdEcxcysrditUQ1lpNmpUQU05dkZPckJ4UGlOeGFkUENHR2NZZAowakZIc2FWOGFPV1dQQjZBQ1JteHdDVDdRTnRTczM2MlpIOUlFWWR4Q00yMDUrZmluVHhkOUcwSmVRRTd2Kyt6CldoeWo2ZmJBWUIxM2wvN1hkRnpNSW5BOGxpekdrVHB2RHMxeTBCUzlwV3ppYmhqbVFoZGZIejdCZGpGTHVvc2wKZzlNZE5sND0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="}, false},
		{"bad base64 client cert", config.Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://httpbin.corp.notatld"), TLSClientKey: "!=", TLSClientCert: "!="}, true},
		{"bad one client cert empty", config.Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://httpbin.corp.notatld"), TLSClientKey: "", TLSClientCert: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUVJVENDQWdtZ0F3SUJBZ0lSQVBqTEJxS1lwcWU0ekhQc0dWdFR6T0F3RFFZSktvWklodmNOQVFFTEJRQXcKRWpFUU1BNEdBMVVFQXhNSFoyOXZaQzFqWVRBZUZ3MHhPVEE0TVRBeE9EUTVOREJhRncweU1UQXlNVEF4TnpRdwpNREZhTUJNeEVUQVBCZ05WQkFNVENIQnZiV1Z5YVhWdE1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBCk1JSUJDZ0tDQVFFQTY3S2pxbVFZR3EwTVZ0QUNWcGVDbVhtaW5sUWJEUEdMbXNaQVVFd3VlSFFucnQzV3R2cEQKT202QWxhSk1VblcrSHU1NWpqb2thbEtlVmpUS21nWUdicVV6VkRvTWJQRGFIZWtsdGRCVE1HbE9VRnNQNFVKUwpEck80emROK3pvNDI4VFgyUG5HMkZDZFZLR3k0UEU4aWxIYldMY3I4NzFZalY1MWZ3OENMRFg5UFpKTnU4NjFDCkY3VjlpRUptNnNTZlFsbW5oTjhqMytXelZiUFFOeTFXc1I3aTllOWo2M0VxS3QyMlE5T1hMK1dBY0tza29JU20KQ05WUlVBalU4WVJWY2dRSkIrelEzNEFRUGx6ME9wNU8vUU4vTWVkamFGOHdMUytpdi96dmlTOGNxUGJ4bzZzTApxNkZOVGx0ay9Ra3hlQ2VLS1RRZS8za1BZdlFBZG5sNjVRSURBUUFCbzNFd2J6QU9CZ05WSFE4QkFmOEVCQU1DCkE3Z3dIUVlEVlIwbEJCWXdGQVlJS3dZQkJRVUhBd0VHQ0NzR0FRVUZCd01DTUIwR0ExVWREZ1FXQkJRQ1FYbWIKc0hpcS9UQlZUZVhoQ0dpNjhrVy9DakFmQmdOVkhTTUVHREFXZ0JSNTRKQ3pMRlg0T0RTQ1J0dWNBUGZOdVhWegpuREFOQmdrcWhraUc5dzBCQVFzRkFBT0NBZ0VBcm9XL2trMllleFN5NEhaQXFLNDVZaGQ5ay9QVTFiaDlFK1BRCk5jZFgzTUdEY2NDRUFkc1k4dll3NVE1cnhuMGFzcSt3VGFCcGxoYS9rMi9VVW9IQ1RqUVp1Mk94dEF3UTdPaWIKVE1tMEorU3NWT3d4YnFQTW9rK1RqVE16NFdXaFFUTzVwRmNoZDZXZXNCVHlJNzJ0aG1jcDd1c2NLU2h3YktIegpQY2h1QTQ4SzhPdi96WkxmZnduQVNZb3VCczJjd1ZiRDI3ZXZOMzdoMGFzR1BrR1VXdm1PSDduTHNVeTh3TTdqCkNGL3NwMmJmTC9OYVdNclJnTHZBMGZMS2pwWTQrVEpPbkVxQmxPcCsrbHlJTEZMcC9qMHNybjRNUnlKK0t6UTEKR1RPakVtQ1QvVEFtOS9XSThSL0FlYjcwTjEzTytYNEtaOUJHaDAxTzN3T1Vqd3BZZ3lxSnNoRnNRUG50VmMrSQpKQmF4M2VQU3NicUcwTFkzcHdHUkpRNmMrd1lxdGk2Y0tNTjliYlRkMDhCNUk1N1RRTHhNcUoycTFnWmw1R1VUCmVFZGNWRXltMnZmd0NPd0lrbGNBbThxTm5kZGZKV1FabE5VaHNOVWFBMkVINnlDeXdaZm9aak9hSDEwTXowV20KeTNpZ2NSZFQ3Mi9NR2VkZk93MlV0MVVvRFZmdEcxcysrditUQ1lpNmpUQU05dkZPckJ4UGlOeGFkUENHR2NZZAowakZIc2FWOGFPV1dQQjZBQ1JteHdDVDdRTnRTczM2MlpIOUlFWWR4Q00yMDUrZmluVHhkOUcwSmVRRTd2Kyt6CldoeWo2ZmJBWUIxM2wvN1hkRnpNSW5BOGxpekdrVHB2RHMxeTBCUzlwV3ppYmhqbVFoZGZIejdCZGpGTHVvc2wKZzlNZE5sND0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="}, true},
		{"bad th other client cert empty", config.Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://httpbin.corp.notatld"), TLSClientKey: "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcGdJQkFBS0NBUUVBNjdLanFtUVlHcTBNVnRBQ1ZwZUNtWG1pbmxRYkRQR0xtc1pBVUV3dWVIUW5ydDNXCnR2cERPbTZBbGFKTVVuVytIdTU1ampva2FsS2VWalRLbWdZR2JxVXpWRG9NYlBEYUhla2x0ZEJUTUdsT1VGc1AKNFVKU0RyTzR6ZE4rem80MjhUWDJQbkcyRkNkVktHeTRQRThpbEhiV0xjcjg3MVlqVjUxZnc4Q0xEWDlQWkpOdQo4NjFDRjdWOWlFSm02c1NmUWxtbmhOOGozK1d6VmJQUU55MVdzUjdpOWU5ajYzRXFLdDIyUTlPWEwrV0FjS3NrCm9JU21DTlZSVUFqVThZUlZjZ1FKQit6UTM0QVFQbHowT3A1Ty9RTi9NZWRqYUY4d0xTK2l2L3p2aVM4Y3FQYngKbzZzTHE2Rk5UbHRrL1FreGVDZUtLVFFlLzNrUFl2UUFkbmw2NVFJREFRQUJBb0lCQVFEQVQ0eXN2V2pSY3pxcgpKcU9SeGFPQTJEY3dXazJML1JXOFhtQWhaRmRTWHV2MkNQbGxhTU1yelBmTG41WUlmaHQzSDNzODZnSEdZc3pnClo4aWJiYWtYNUdFQ0t5N3lRSDZuZ3hFS3pRVGpiampBNWR3S0h0UFhQUnJmamQ1Y2FMczVpcDcxaWxCWEYxU3IKWERIaXUycnFtaC9kVTArWGRMLzNmK2VnVDl6bFQ5YzRyUm84dnZueWNYejFyMnVhRVZ2VExsWHVsb2NpeEVrcgoySjlTMmxveWFUb2tFTnNlMDNpSVdaWnpNNElZcVowOGJOeG9IWCszQXVlWExIUStzRkRKMlhaVVdLSkZHMHUyClp3R2w3YlZpRTFQNXdiQUdtZzJDeDVCN1MrdGQyUEpSV3Frb2VxY3F2RVdCc3RFL1FEcDFpVThCOHpiQXd0Y3IKZHc5TXZ6Q2hBb0dCQVBObzRWMjF6MGp6MWdEb2tlTVN5d3JnL2E4RkJSM2R2Y0xZbWV5VXkybmd3eHVucnFsdwo2U2IrOWdrOGovcXEvc3VQSDhVdzNqSHNKYXdGSnNvTkVqNCt2b1ZSM3UrbE5sTEw5b21rMXBoU0dNdVp0b3huCm5nbUxVbkJUMGI1M3BURkJ5WGsveE5CbElreWdBNlg5T2MreW5na3RqNlRyVnMxUERTdnVJY0s1QW9HQkFQZmoKcEUzR2F6cVFSemx6TjRvTHZmQWJBdktCZ1lPaFNnemxsK0ZLZkhzYWJGNkdudFd1dWVhY1FIWFpYZTA1c2tLcApXN2xYQ3dqQU1iUXI3QmdlazcrOSszZElwL1RnYmZCYnN3Syt6Vng3Z2doeWMrdytXRWExaHByWTZ6YXdxdkFaCkhRU2lMUEd1UGp5WXBQa1E2ZFdEczNmWHJGZ1dlTmd4SkhTZkdaT05Bb0dCQUt5WTF3MUM2U3Y2c3VuTC8vNTcKQ2Z5NTAwaXlqNUZBOWRqZkRDNWt4K1JZMnlDV0ExVGsybjZyVmJ6dzg4czBTeDMrYS9IQW1CM2dMRXBSRU5NKwo5NHVwcENFWEQ3VHdlcGUxUnlrTStKbmp4TzlDSE41c2J2U25sUnBQWlMvZzJRTVhlZ3grK2trbkhXNG1ITkFyCndqMlRrMXBBczFXbkJ0TG9WaGVyY01jSkFvR0JBSTYwSGdJb0Y5SysvRUcyY21LbUg5SDV1dGlnZFU2eHEwK0IKWE0zMWMzUHE0amdJaDZlN3pvbFRxa2d0dWtTMjBraE45dC9ibkI2TmhnK1N1WGVwSXFWZldVUnlMejVwZE9ESgo2V1BMTTYzcDdCR3cwY3RPbU1NYi9VRm5Yd0U4OHlzRlNnOUF6VjdVVUQvU0lDYkI5ZHRVMWh4SHJJK0pZRWdWCkFrZWd6N2lCQW9HQkFJRncrQVFJZUIwM01UL0lCbGswNENQTDJEak0rNDhoVGRRdjgwMDBIQU9mUWJrMEVZUDEKQ2FLR3RDbTg2MXpBZjBzcS81REtZQ0l6OS9HUzNYRk00Qm1rRk9nY1NXVENPNmZmTGdLM3FmQzN4WDJudlpIOQpYZGNKTDQrZndhY0x4c2JJKzhhUWNOVHRtb3pkUjEzQnNmUmIrSGpUL2o3dkdrYlFnSkhCT0syegotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=", TLSClientCert: ""}, true},
		{"good root ca pool", config.Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://httpbin.corp.notatld"), TLSCustomCA: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUU1RENDQXN5Z0F3SUJBZ0lCQVRBTkJna3Foa2lHOXcwQkFRc0ZBREFTTVJBd0RnWURWUVFERXdkbmIyOWsKTFdOaE1CNFhEVEU1TURneE1ERTNOREF3TWxvWERUSXhNREl4TURFM05EQXdNbG93RWpFUU1BNEdBMVVFQXhNSApaMjl2WkMxallUQ0NBaUl3RFFZSktvWklodmNOQVFFQkJRQURnZ0lQQURDQ0Fnb0NnZ0lCQUw3b2VldEovNmNFCkdicTcvanNtcU9FM2VyVE1aRHR0eFM4STVGV1c0TkRXbWNpOE5IdWRMZDhlM1JtOEh6Y09jSjRQL0ErcDVsYmsKTjhySzY4OUlsQzhqM28yaEhSdEk2T21saFY3NEoxaUlIOGtkSXU2V2xPMWtOdUx5dGRrbjhRaytJOUNEWjlGSAorZzhRbnVka0tMUWJkZFdDVXJzUjR4cEcyK0VkNWdua0JJNG4zbmNLMFgvWEZocWhDTEU1eFBaQk5OWktGbHJxCm1lYUl4dHoyc2ZvWVY1NmcwMnNGS1QxSUlMNTVFMG14djRUa2JtSWw5Rk9qZEtCdkhFZnJHeXl5OFRGTHErUzMKTXo2em9xNDhuOEhGMUc5cHBLVk9OMUp0Mks1UWEvV2hpbjVrcWNhYTNwNE0vN2tiNmtxU0tMWG1iN0gyN3kvVQpEYjZDUG01d2lodjA2c1FobXN2MHhuS2hqMm8vQzhlcWxzNzZZWDF1Y2NqMzlmSTRlQ1E4cENFbTlVcDh5ZkkvCkxlYVpXbGE0NEZneWw3N1lyc2MvM0U5dk1hS0ZVeGRjR3VtMXQrNUZZYWpkY0EvTlFreTJBeTJqcHRwVXV1SFUKNnhYSzdEcXY5Z01jQS8zM1VYOFpHZklPRk0rY3FlOTQxaTVPT1hGSHJoRDlqeTRQR2M4Z2kxSTRyK1VXd0tCYgoxSGg1clQ3ckJZK1NLTTBzZmtpQlZ1RU9pbnk2dDF1Z2tEdjY4dXNFWFlIWlZXaWl6b1hmcDVHbjZmckUvd1IxCkRkak13TGEvT2tQTnVEVVQ4eU1GS2hWRnFHcXdHQzY2bys1cjQyMlVwa0s4SHJ5K2tsQ3pUTys3U0RodTJiWk4KUVFGT0NLSVVldnR3bGdabVBNck1BNTZ3dzVSSnNhVnhBZ01CQUFHalJUQkRNQTRHQTFVZER3RUIvd1FFQXdJQgpCakFTQmdOVkhSTUJBZjhFQ0RBR0FRSC9BZ0VBTUIwR0ExVWREZ1FXQkJSNTRKQ3pMRlg0T0RTQ1J0dWNBUGZOCnVYVnpuREFOQmdrcWhraUc5dzBCQVFzRkFBT0NBZ0VBZituUmpBVnZuT0pSckpBQWpKWVY3aVF3bHExUXZYRGcKbHZhY0JoVFJyWFh4OW5GaVRZUzV4MkFMbXZ5WHhubTdIS2VDSUZEclJwOE5MVFkyYjJXR01BcTFxc3JBT0QvegpTNmNSSW1OQ21QNmd0UHNUNDlabzBYajNrZjZyTXBPeHBiSUlnSmZMY056UGZpL25jeC9oRDNBOHl6Zk4wQTZZCnFFd2QvSkZPajdEa3RaQmdlSXZETlJXS0pveEpJRlZ4anJqLzFiVmkxZTRWVjVvWmhOako4SzlyV1FRK1EvK3QKZ3lGK0sycGxDQ1RiRWR6eU9heDY1djh5UDJ5RCs2WkFIRk9sRjI2TnZpUkw4OWJ1VHIwaEpZa0N5VXZ3MmJZaQo4Q3MyWDZkd0NDdXVhZUdVR2VRemszMGxQeUdWSmVKL3ZJMGJRSzlpZ2I5dFozY3d0WHBQdjN6a1B1TDE3d01WCitCMXo2RW1HZVVLNXlTQ0xFWjc2aVliNU0vY3ZjTUVOMWdoeFNIN0FmaDhMS0c0eWszT21SQ253akVqdTFhaWoKZGs3cjJuc0xmYU9KWFBRNU1wMzRYU1ltdTlpTVl0VytMbWZiSDJxMW9vS3dKZDhHNVhhRWRmQmpHUEQ5Q3FkWAphSlh0MDA0cVdsalJOS3p1MFNFRmJ6UldGNHRoeXlUTzE4QVI4eTNHV0Vwak95amdKSzlFeU1sQm9Qa3RYQVVVCjZzTFhqT3ZZU0ovd202NUhxVVZBTTVsRy96WVN3TGdCTDAwc1pJKzVGa0QwblU0Rkx6QWRLV05LWkRXZFVNbUwKVi9lV0ZGNGwwVFBvNTVhM0pUL1BGc2J0RFBLVWxvWVFXeTFybmFqR3J1L0Y5bGRCcHB1bUVUa2FOS2ZWT05Jcgp4cERnc1FhVkVXOD0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="}, false},
		{"bad root ca pool", config.Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://httpbin.corp.notatld"), TLSCustomCA: "!"}, true},
		{"good custom ca file", config.Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://httpbin.corp.notatld"), TLSCustomCAFile: "testdata/ca.pem"}, false},
		{"bad custom ca file", config.Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://httpbin.corp.notatld"), TLSCustomCAFile: "testdata/404.pem"}, true},
		{"good client certificate files", config.Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://httpbin.corp.notatld"), TLSClientCertFile: "testdata/example-cert.pem", TLSClientKeyFile: "testdata/example-key.pem"}, false},
		{"bad certificate file", config.Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://httpbin.corp.notatld"), TLSClientCertFile: "testdata/example-cert-404.pem", TLSClientKeyFile: "testdata/example-key.pem"}, true},
		{"bad key file", config.Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://httpbin.corp.notatld"), TLSClientCertFile: "testdata/example-cert.pem", TLSClientKeyFile: "testdata/example-key-404.pem"}, true},
		{"good tls server name", config.Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://internal-host-name"), TLSServerName: "httpbin.corp.notatld"}, false},
		{"good kube service account token file", config.Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://internal-host-name"), KubernetesServiceAccountTokenFile: "testdata/kubeserviceaccount.token"}, false},
		{"good kube service account token", config.Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://internal-host-name"), KubernetesServiceAccountToken: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE1OTY1MDk4MjIsImV4cCI6MTYyODA0NTgyMiwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsIkdpdmVuTmFtZSI6IkpvaG5ueSIsIlN1cm5hbWUiOiJSb2NrZXQiLCJFbWFpbCI6Impyb2NrZXRAZXhhbXBsZS5jb20iLCJSb2xlIjpbIk1hbmFnZXIiLCJQcm9qZWN0IEFkbWluaXN0cmF0b3IiXX0.H0I6ccQrL6sKobsKQj9dqNcLw_INhU9_xJsVyCkgkiY"}, false},
		{"bad kube service account token and file", config.Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://internal-host-name"), KubernetesServiceAccountToken: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE1OTY1MDk4MjIsImV4cCI6MTYyODA0NTgyMiwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsIkdpdmVuTmFtZSI6IkpvaG5ueSIsIlN1cm5hbWUiOiJSb2NrZXQiLCJFbWFpbCI6Impyb2NrZXRAZXhhbXBsZS5jb20iLCJSb2xlIjpbIk1hbmFnZXIiLCJQcm9qZWN0IEFkbWluaXN0cmF0b3IiXX0.H0I6ccQrL6sKobsKQj9dqNcLw_INhU9_xJsVyCkgkiY", KubernetesServiceAccountTokenFile: "testdata/kubeserviceaccount.token"}, true},
		{"TCP To URLs", config.Policy{From: "tcp+https://httpbin.corp.example:4000", To: mustParseWeightedURLs(t, "tcp://one.example.com:5000", "tcp://two.example.com:5000")}, false},
		{"mix of TCP and non-TCP To URLs", config.Policy{From: "tcp+https://httpbin.corp.example:4000", To: mustParseWeightedURLs(t, "https://example.com", "tcp://example.com:5000")}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.policy.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func Test_PolicyValidate_RedirectResponseCode(t *testing.T) {
	t.Parallel()

	var r config.PolicyRedirect
	p := config.Policy{
		From:     "http://example.com",
		Redirect: &r,
	}

	cases := []struct {
		Code          *int32
		ExpectedError string
	}{
		{nil, ""},
		{proto.Int32(0), "unsupported redirect response code 0"},
		{proto.Int32(100), "unsupported redirect response code 100"},
		{proto.Int32(200), "unsupported redirect response code 200"},
		{proto.Int32(300), "unsupported redirect response code 300"},
		{proto.Int32(301), ""},
		{proto.Int32(302), ""},
		{proto.Int32(303), ""},
		{proto.Int32(304), "unsupported redirect response code 304"},
		{proto.Int32(305), "unsupported redirect response code 305"},
		{proto.Int32(306), "unsupported redirect response code 306"},
		{proto.Int32(307), ""},
		{proto.Int32(308), ""},
		{proto.Int32(309), "unsupported redirect response code 309"},
		{proto.Int32(400), "unsupported redirect response code 400"},
		{proto.Int32(500), "unsupported redirect response code 500"},
		{proto.Int32(600), "unsupported redirect response code 600"},
	}

	for i := range cases {
		c := &cases[i]
		t.Run(fmt.Sprint(c.Code), func(t *testing.T) {
			r.ResponseCode = c.Code
			err := p.Validate()
			if c.ExpectedError != "" {
				assert.ErrorContains(t, err, c.ExpectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func mustParseWeightedURLs(t testing.TB, urls ...string) []config.WeightedURL {
	wu, err := config.ParseWeightedUrls(urls...)
	require.NoError(t, err)
	return wu
}

func TestPolicy_String(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		From     string
		To       []config.WeightedURL
		want     string
		wantFrom string
	}{
		{"good", "https://pomerium.io", []config.WeightedURL{{URL: url.URL{Scheme: "https", Host: "localhost"}}}, "https://pomerium.io → https://localhost", `"https://pomerium.io"`},
		{"invalid", "https://pomerium.io", nil, "https://pomerium.io → ?", `"https://pomerium.io"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &config.Policy{
				From: tt.From,
				To:   tt.To,
			}
			p.Validate()
			if got := p.String(); got != tt.want {
				t.Errorf("Policy.String() = %v, want %v", got, tt.want)
			}
			out, err := json.Marshal(p.From)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(string(out), tt.wantFrom); diff != "" {
				t.Errorf("json diff() = %s", diff)
			}
		})
	}
}

func Test_PolicyRouteID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		basePolicy    *config.Policy
		comparePolicy *config.Policy
		wantSame      bool
	}{
		{
			"same",
			&config.Policy{From: "https://pomerium.io", To: mustParseWeightedURLs(t, "http://localhost"), AllowedUsers: []string{"foo@bar.com"}},
			&config.Policy{From: "https://pomerium.io", To: mustParseWeightedURLs(t, "http://localhost")},
			true,
		},
		{
			"different from",
			&config.Policy{From: "https://pomerium.io", To: mustParseWeightedURLs(t, "http://localhost")},
			&config.Policy{From: "https://notpomerium.io", To: mustParseWeightedURLs(t, "http://localhost")},
			false,
		},
		{
			"different path",
			&config.Policy{From: "https://pomerium.io", To: mustParseWeightedURLs(t, "http://localhost")},
			&config.Policy{From: "https://pomerium.io", To: mustParseWeightedURLs(t, "http://localhost"), Path: "/foo"},
			false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.NoError(t, tt.basePolicy.Validate())
			assert.NoError(t, tt.comparePolicy.Validate())

			id1, err := tt.basePolicy.RouteID()
			assert.NoError(t, err)

			id2, err := tt.comparePolicy.RouteID()
			assert.NoError(t, err)

			assert.Equal(t, tt.wantSame, id1 == id2)
		})
	}
}

func TestPolicy_Checksum(t *testing.T) {
	t.Parallel()
	p := &config.Policy{From: "https://pomerium.io", To: mustParseWeightedURLs(t, "http://localhost"), AllowedUsers: []string{"foo@bar.com"}}
	oldChecksum := p.Checksum()
	p.AllowedUsers = []string{"foo@pomerium.io"}
	newChecksum := p.Checksum()

	if newChecksum == oldChecksum {
		t.Errorf("Checksum() failed to update old = %d, new = %d", oldChecksum, newChecksum)
	}

	if newChecksum == 0 || oldChecksum == 0 {
		t.Error("Checksum() not returning data")
	}

	newChecksum2 := p.Checksum()
	if newChecksum2 != newChecksum {
		t.Error("Checksum() inconsistent")
	}
}

func TestPolicy_FromToPb(t *testing.T) {
	t.Parallel()

	t.Run("normal", func(t *testing.T) {
		p := &config.Policy{
			From:         "https://pomerium.io",
			To:           mustParseWeightedURLs(t, "http://localhost"),
			AllowedUsers: []string{"foo@bar.com"},
			SubPolicies: []config.SubPolicy{
				{
					ID:   "sub_policy_id",
					Name: "sub_policy",
					Rego: []string{"deny = true"},
				},
			},
			EnableGoogleCloudServerlessAuthentication: true,
		}
		pbPolicy, err := p.AsProto()
		require.NoError(t, err)

		policyFromPb, err := config.NewPolicyFromProto(pbPolicy)
		assert.NoError(t, err)
		assert.NoError(t, policyFromPb.Validate())
		assert.Equal(t, p.From, policyFromPb.From)
		assert.Equal(t, p.To, policyFromPb.To)
		assert.Equal(t, p.AllowedUsers, policyFromPb.AllowedUsers)
	})

	t.Run("envoy cluster name", func(t *testing.T) {
		p := &config.Policy{
			From:         "https://pomerium.io",
			To:           mustParseWeightedURLs(t, "http://localhost"),
			AllowedUsers: []string{"foo@bar.com"},
		}

		pbPolicy, err := p.AsProto()
		require.NoError(t, err)

		cases := []struct {
			pbPolicyName       string
			pbEnvoyOpts        *envoy_config_cluster_v3.Cluster
			expectedPolicyName string
		}{
			{"", nil, ""},
			{"pb-name", nil, "pb-name"},
			{"", &envoy_config_cluster_v3.Cluster{Name: "pb-envoy-name"}, "pb-envoy-name"},
			{"pb-name", &envoy_config_cluster_v3.Cluster{Name: "pb-envoy-name"}, "pb-envoy-name"},
		}

		for _, tc := range cases {
			pbPolicy.Name = tc.pbPolicyName
			pbPolicy.EnvoyOpts = tc.pbEnvoyOpts

			policyFromPb, err := config.NewPolicyFromProto(pbPolicy)
			assert.NoError(t, err)
			assert.NoError(t, policyFromPb.Validate())
			assert.Equal(t, tc.expectedPolicyName, policyFromPb.EnvoyOpts.Name)
		}
	})

	t.Run("redirect route", func(t *testing.T) {
		p := &config.Policy{
			From: "https://pomerium.io",
			Redirect: &config.PolicyRedirect{
				HTTPSRedirect: proto.Bool(true),
			},
		}

		pbPolicy, err := p.AsProto()
		require.NoError(t, err)

		policyFromProto, err := config.NewPolicyFromProto(pbPolicy)
		assert.NoError(t, err)
		assert.NoError(t, policyFromProto.Validate())
		assert.Equal(t, p.Redirect.HTTPSRedirect, policyFromProto.Redirect.HTTPSRedirect)
	})
}

func TestPolicy_Matches(t *testing.T) {
	t.Run("full", func(t *testing.T) {
		p := &config.Policy{
			From:  "https://www.example.com",
			To:    mustParseWeightedURLs(t, "https://localhost"),
			Regex: `/foo`,
		}
		assert.NoError(t, p.Validate())

		assert.False(t, p.Matches(urlutil.MustParseAndValidateURL(`https://www.example.com/foo/bar`), true),
			"regex should only match full string")
	})
	t.Run("issue2952", func(t *testing.T) {
		p := &config.Policy{
			From:  "https://www.example.com",
			To:    mustParseWeightedURLs(t, "https://localhost"),
			Regex: `^\/foo\/bar\/[0-9a-f]\/{0,1}$`,
		}
		assert.NoError(t, p.Validate())

		assert.True(t, p.Matches(urlutil.MustParseAndValidateURL(`https://www.example.com/foo/bar/0`), true))
	})
	t.Run("issue2592-test2", func(t *testing.T) {
		p := &config.Policy{
			From:  "https://www.example.com",
			To:    mustParseWeightedURLs(t, "https://localhost"),
			Regex: `/admin/.*`,
		}
		assert.NoError(t, p.Validate())

		assert.True(t, p.Matches(urlutil.MustParseAndValidateURL(`https://www.example.com/admin/foo`), true))
		assert.True(t, p.Matches(urlutil.MustParseAndValidateURL(`https://www.example.com/admin/bar`), true))
	})
	t.Run("tcp", func(t *testing.T) {
		p := &config.Policy{
			From: "tcp+https://proxy.example.com/tcp.example.com:6379",
			To:   mustParseWeightedURLs(t, "tcp://localhost:6379"),
		}
		assert.NoError(t, p.Validate())

		assert.True(t, p.Matches(urlutil.MustParseAndValidateURL(`https://tcp.example.com:6379`), true))
	})
}

func TestPolicy_SortOrder(t *testing.T) {
	ptr := func(i int64) *int64 {
		return &i
	}

	testCases := []struct {
		name     string
		policies []config.Policy
		wantIDs  []string
	}{
		{
			name: "regexPriorityOrder DESC NULLS LAST",
			policies: []config.Policy{
				{From: "a", Path: "/a", RegexPriorityOrder: nil, ID: "3"},
				{From: "a", Path: "/a", RegexPriorityOrder: ptr(2), ID: "2"},
				{From: "a", Path: "/a", RegexPriorityOrder: ptr(1), ID: "1"},
			},
			wantIDs: []string{"2", "1", "3"},
		},
		{
			name: "from ASC",
			policies: []config.Policy{
				{From: "", Path: "", RegexPriorityOrder: nil, ID: "B"},
				{From: "", Path: "", RegexPriorityOrder: ptr(0), ID: "C"},
				{From: "source", Path: "/a", RegexPriorityOrder: ptr(1), ID: "A"},
			},
			wantIDs: []string{"C", "B", "A"},
		},
		{
			name: "id ASC",
			policies: []config.Policy{
				{From: "source", Path: "/a", RegexPriorityOrder: ptr(1), Regex: "regex", Prefix: "prefix", ID: "2"},
				{From: "source", Path: "/a", RegexPriorityOrder: ptr(1), Regex: "regex", Prefix: "prefix", ID: "1"},
			},
			wantIDs: []string{"1", "2"},
		},
		{
			name: "path DESC",
			policies: []config.Policy{
				{From: "source", Path: "/b", RegexPriorityOrder: ptr(1), ID: "3"},
				{From: "source", Path: "/a", RegexPriorityOrder: nil, ID: "2"},
				{From: "source", Path: "/a", RegexPriorityOrder: ptr(2), ID: "1"},
			},
			wantIDs: []string{"3", "1", "2"},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			config.SortPolicies(tt.policies)

			gotIDs := make([]string, 0, len(tt.policies))
			for _, entity := range tt.policies {
				gotIDs = append(gotIDs, entity.ID)
			}

			assert.Equal(t, tt.wantIDs, gotIDs)
		})
	}
}

func TestPolicy_IsTCP(t *testing.T) {
	p1 := config.Policy{From: "https://example.com"}
	assert.False(t, p1.IsTCP())

	p2 := config.Policy{From: "tcp+https://example.com"}
	assert.True(t, p2.IsTCP())
}

func TestPolicy_IsTCPUpstream(t *testing.T) {
	p1 := config.Policy{
		From: "tcp+https://example.com:1234",
		To:   mustParseWeightedURLs(t, "https://one.example.com", "https://two.example.com"),
	}
	assert.False(t, p1.IsTCPUpstream())

	p2 := config.Policy{
		From: "tcp+https://example.com:1234",
		To:   mustParseWeightedURLs(t, "tcp://one.example.com:4000", "tcp://two.example.com:4000"),
	}
	assert.True(t, p2.IsTCPUpstream())

	p3 := config.Policy{
		From: "tcp+https://example.com:1234",
	}
	assert.False(t, p3.IsTCPUpstream())
}

func BenchmarkChecksum(b *testing.B) {
	p := config.Policy{
		ID:        "a",
		From:      "b",
		To:        mustParseWeightedURLs(b, "https://localhost"),
		LbWeights: []uint32{1, 2, 3},
		// these are deprecated
		// AllowedUsers:   []string{"a", "b", "c"},
		// AllowedDomains: []string{"a", "b", "c"},
		// AllowedIDPClaims: map[string][]any{
		// 	"a": {1, 2, 3},
		// 	"b": {4, 5, 6},
		// },
		Prefix:                           "c",
		Path:                             "d",
		Regex:                            "e",
		RegexPriorityOrder:               new(int64),
		PrefixRewrite:                    "f",
		RegexRewritePattern:              "g",
		RegexRewriteSubstitution:         "h",
		HostRewrite:                      "i",
		HostRewriteHeader:                "j",
		HostPathRegexRewritePattern:      "k",
		HostPathRegexRewriteSubstitution: "l",
		CORSAllowPreflight:               true,
		AllowPublicUnauthenticatedAccess: false,
		AllowAnyAuthenticatedUser:        true,
		UpstreamTimeout:                  new(time.Duration),
		IdleTimeout:                      new(time.Duration),
		AllowWebsockets:                  false,
		AllowSPDY:                        true,
		TLSSkipVerify:                    false,
		TLSServerName:                    "m",
		TLSDownstreamServerName:          "n",
		TLSUpstreamServerName:            "o",
		TLSCustomCA:                      "p",
		TLSCustomCAFile:                  "q",
		TLSClientCert:                    "r",
		TLSClientKey:                     "s",
		TLSClientCertFile:                "t",
		TLSClientKeyFile:                 "u",
		TLSDownstreamClientCA:            "v",
		TLSDownstreamClientCAFile:        "w",
		TLSUpstreamAllowRenegotiation:    true,
		SetRequestHeaders: map[string]string{
			"a": "1",
			"b": "2",
			"c": "3",
		},
		RemoveRequestHeaders: []string{
			"a",
			"b",
			"c",
		},
		PreserveHostHeader:                        true,
		PassIdentityHeaders:                       new(bool),
		KubernetesServiceAccountToken:             "x",
		KubernetesServiceAccountTokenFile:         "y",
		EnableGoogleCloudServerlessAuthentication: true,
		SubPolicies:                               []config.SubPolicy{},
		EnvoyOpts:                                 &envoy_config_cluster_v3.Cluster{},
		RewriteResponseHeaders: []config.RewriteHeader{
			{
				Header: "a",
				Prefix: "b",
				Value:  "c",
			},
		},
		SetResponseHeaders: map[string]string{
			"a": "1",
			"b": "2",
			"c": "3",
		},
		IDPClientID:      "z",
		IDPClientSecret:  "zz",
		ShowErrorDetails: true,
		Policy: &config.PPLPolicy{
			Policy: &parser.Policy{
				Rules: []parser.Rule{
					{
						Action: parser.ActionAllow,
						And:    []parser.Criterion{{Name: "foo"}},
					},
				},
			},
		},
	}
	pRouteID, err := p.RouteID()
	require.NoError(b, err)
	b.Run("route id", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			p.RouteID()
		}
	})
	pNoMapFields := p
	pNoMapFields.SetRequestHeaders = nil
	pNoMapFields.SetResponseHeaders = nil
	pNoMapFieldsRouteID, err := pNoMapFields.RouteID()
	require.NoError(b, err)
	b.ResetTimer()
	b.Run("(old) hashstructure checksum", func(b *testing.B) {
		b.Run("with map fields", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				hashutil.MustHash(p)
			}
		})
		b.Run("without map fields", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				hashutil.MustHash(pNoMapFields)
			}
		})
	})
	b.Run("(new) proto-wire checksum", func(b *testing.B) {
		b.Run("with map fields", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				p.ChecksumWithID(pRouteID)
			}
		})
		b.Run("without map fields", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				pNoMapFields.ChecksumWithID(pNoMapFieldsRouteID)
			}
		})
	})
}

func BenchmarkChecksumZeroAlloc(b *testing.B) {
	// best case is using redirect/direct-response, no sub-policies, and no
	// response header rewrite config. using To requires one unavoidable(?) url to
	// string conversion, sub-policies require allocations, and response header
	// rewrites require allocating each object
	p := &config.Policy{
		ID:   "a",
		From: "b",
		Redirect: &config.PolicyRedirect{
			HTTPSRedirect: proto.Bool(true),
			PathRedirect:  proto.String("/bar"),
			StripQuery:    proto.Bool(true),
		},
		Prefix:                           "c",
		Path:                             "d",
		Regex:                            "e",
		RegexPriorityOrder:               new(int64),
		PrefixRewrite:                    "f",
		RegexRewritePattern:              "g",
		RegexRewriteSubstitution:         "h",
		HostRewrite:                      "i",
		HostRewriteHeader:                "j",
		HostPathRegexRewritePattern:      "k",
		HostPathRegexRewriteSubstitution: "l",
		CORSAllowPreflight:               true,
		AllowPublicUnauthenticatedAccess: false,
		AllowAnyAuthenticatedUser:        true,
		UpstreamTimeout:                  new(time.Duration),
		IdleTimeout:                      new(time.Duration),
		AllowWebsockets:                  false,
		AllowSPDY:                        true,
		TLSSkipVerify:                    false,
		TLSServerName:                    "m",
		TLSDownstreamServerName:          "n",
		TLSUpstreamServerName:            "o",
		TLSCustomCA:                      "p",
		TLSCustomCAFile:                  "q",
		TLSClientCert:                    "r",
		TLSClientKey:                     "s",
		TLSClientCertFile:                "t",
		TLSClientKeyFile:                 "u",
		TLSDownstreamClientCA:            "v",
		TLSDownstreamClientCAFile:        "w",
		TLSUpstreamAllowRenegotiation:    true,
		SetRequestHeaders: map[string]string{
			"a": "1",
			"b": "2",
			"c": "3",
		},
		RemoveRequestHeaders: []string{
			"a",
			"b",
			"c",
		},
		SetResponseHeaders: map[string]string{
			"a": "1",
			"b": "2",
			"c": "3",
		},
		PreserveHostHeader:                        true,
		PassIdentityHeaders:                       new(bool),
		KubernetesServiceAccountToken:             "x",
		KubernetesServiceAccountTokenFile:         "y",
		EnableGoogleCloudServerlessAuthentication: true,
		IDPClientID:                               "z",
		IDPClientSecret:                           "zz",
		ShowErrorDetails:                          true,
	}
	pRouteID, err := p.RouteID()
	require.NoError(b, err)
	b.Run("route id", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			p.RouteID()
		}
	})
	pNoMapFields := p
	pNoMapFields.SetRequestHeaders = nil
	pNoMapFields.SetResponseHeaders = nil
	pNoMapFieldsRouteID, err := pNoMapFields.RouteID()
	require.NoError(b, err)

	// these should both report 0 allocs/op
	b.Run("(new) proto-wire checksum, best case", func(b *testing.B) {
		b.Run("with map fields", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				p.ChecksumWithID(pRouteID) // p.Checksum() is still zero-alloc, but this is faster
			}
		})
		b.Run("without map fields", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				pNoMapFields.ChecksumWithID(pNoMapFieldsRouteID)
			}
		})
	})
}

func TestUnsafe(t *testing.T) {
	newStaticPolicy := func() *config.Policy {
		return &config.Policy{
			ID:             "a",
			From:           "b",
			To:             mustParseWeightedURLs(t, "https://localhost"),
			LbWeights:      []uint32{1, 2, 3},
			AllowedUsers:   []string{"a", "b", "c"},
			AllowedDomains: []string{"a", "b", "c"},
			AllowedIDPClaims: map[string][]any{
				"a": {1, 2, 3},
				"b": {4, 5, 6},
			},
			Prefix:                           "c",
			Path:                             "d",
			Regex:                            "e",
			RegexPriorityOrder:               new(int64),
			PrefixRewrite:                    "f",
			RegexRewritePattern:              "g",
			RegexRewriteSubstitution:         "h",
			HostRewrite:                      "i",
			HostRewriteHeader:                "j",
			HostPathRegexRewritePattern:      "k",
			HostPathRegexRewriteSubstitution: "l",
			CORSAllowPreflight:               true,
			AllowPublicUnauthenticatedAccess: false,
			AllowAnyAuthenticatedUser:        true,
			UpstreamTimeout:                  new(time.Duration),
			IdleTimeout:                      new(time.Duration),
			AllowWebsockets:                  false,
			AllowSPDY:                        true,
			TLSSkipVerify:                    false,
			TLSServerName:                    "m",
			TLSDownstreamServerName:          "n",
			TLSUpstreamServerName:            "o",
			TLSCustomCA:                      "p",
			TLSCustomCAFile:                  "q",
			TLSClientCert:                    "r",
			TLSClientKey:                     "s",
			TLSClientCertFile:                "t",
			TLSClientKeyFile:                 "u",
			TLSDownstreamClientCA:            "v",
			TLSDownstreamClientCAFile:        "w",
			TLSUpstreamAllowRenegotiation:    true,
			SetRequestHeaders: map[string]string{
				"a": "1",
				"b": "2",
				"c": "3",
			},
			RemoveRequestHeaders: []string{
				"a",
				"b",
				"c",
			},
			PreserveHostHeader:                        true,
			PassIdentityHeaders:                       new(bool),
			KubernetesServiceAccountToken:             "x",
			KubernetesServiceAccountTokenFile:         "y",
			EnableGoogleCloudServerlessAuthentication: true,
			RewriteResponseHeaders: []config.RewriteHeader{
				{
					Header: "a",
					Prefix: "b",
					Value:  "c",
				},
			},
			SetResponseHeaders: map[string]string{
				"a": "1",
				"b": "2",
				"c": "3",
			},
			IDPClientID:      "z",
			IDPClientSecret:  "zz",
			ShowErrorDetails: true,
			Policy: &config.PPLPolicy{
				Policy: &parser.Policy{
					Rules: []parser.Rule{
						{
							Action: parser.ActionAllow,
							And:    []parser.Criterion{{Name: "foo"}},
						},
					},
				},
			},
		}
	}

	randomString := func(rand *mathrand.Rand) string {
		size := rand.Int32N(16) + 16
		bytes := make([]rune, size)
		for i := range bytes {
			bytes[i] = rand.Int32N('~'-' ') + ' '
		}
		return string(bytes)
	}
	newRandomPolicy := func(rand *mathrand.Rand) *config.Policy {
		p := &config.Policy{
			From:               randomString(rand),
			UpstreamTimeout:    (*time.Duration)(proto.Int64(rand.Int64())),
			IdleTimeout:        (*time.Duration)(proto.Int64(rand.Int64())),
			RegexPriorityOrder: proto.Int64(rand.Int64()),
			SetRequestHeaders: map[string]string{
				randomString(rand): randomString(rand),
				randomString(rand): randomString(rand),
			},
			SetResponseHeaders: map[string]string{
				randomString(rand): randomString(rand),
				randomString(rand): randomString(rand),
			},
			RewriteResponseHeaders: []config.RewriteHeader{
				{
					Header: randomString(rand),
					Prefix: randomString(rand),
					Value:  randomString(rand),
				},
				{
					Header: randomString(rand),
					Prefix: randomString(rand),
					Value:  randomString(rand),
				},
			},
			SubPolicies: []config.SubPolicy{
				{
					ID:   randomString(rand),
					Name: randomString(rand),
					AllowedIDPClaims: identity.FlattenedClaims{
						randomString(rand): []any{1, "foo", new(struct{})},
					},
				},
			},
			PassIdentityHeaders: proto.Bool(rand.IntN(2) == 0),
		}
		switch rand.IntN(3) {
		case 0:
			p.To = mustParseWeightedURLs(t, "https://foo.bar/baz", "https://foo.baz/bar?testing=1")
		case 1:
			p.Redirect = &config.PolicyRedirect{
				HTTPSRedirect:  proto.Bool(rand.IntN(2) == 0),
				SchemeRedirect: proto.String(randomString(rand)),
				HostRedirect:   proto.String(randomString(rand)),
				PortRedirect:   proto.Uint32(rand.Uint32()),
				PathRedirect:   proto.String(randomString(rand)),
				PrefixRewrite:  proto.String(randomString(rand)),
				ResponseCode:   proto.Int32(rand.Int32()),
				StripQuery:     proto.Bool(rand.IntN(2) == 0),
			}
		case 2:
			p.Response = &config.DirectResponse{
				Status: rand.Int(),
				Body:   randomString(rand),
			}
		}
		return p
	}
	t.Run("RouteID/ChecksumWithID", func(t *testing.T) {
		debug.SetGCPercent(-1)
		t.Cleanup(func() {
			debug.SetGCPercent(100)
		})

		// The following test is repeated several times, using a fixed seed so as
		// to generate the same random policies each time. Each iteration of the
		// test runs two passes over identical sets of policies.
		seed1, seed2 := mathrand.Uint64(), mathrand.Uint64()
		t.Logf("seed 1: %d; seed 2: %d", seed1, seed2)
		const (
			numPolicies           = 500
			numChecksumIterations = 50000
			forward               = 0
			backward              = 1
		)

		runTest := func(t *testing.T, injectFault bool) {
			var faultInjectionErrorCount atomic.Int32
			if injectFault {
				defer func() {
					require.Equal(t, faultInjectionErrorCount.Load(), int32(1), "expected exactly one fault injection error")
				}()
			}

			// On the first pass, free each policy in the list in forward order, then
			// on the second pass, free the policies in reverse order. If one policy
			// has memory aliased to a field in a different policy, the order in which
			// they are freed determines the behavior of the GC. So, try both ways.
			var expectedChecksums [numPolicies]uint64 // populated on the first pass only
			for pass := range 2 {
				config.DebugResetPools() // reset the pools before each pass
				rand := mathrand.New(mathrand.NewPCG(seed1, seed2))

				var policies [numPolicies]*config.Policy
				var finalizerCount atomic.Int32
				for i := range numPolicies {
					p := newRandomPolicy(rand)
					runtime.SetFinalizer(p, func(*config.Policy) {
						finalizerCount.Add(1)
					})
					policies[i] = p
					routeID, err := p.RouteID()
					require.NoError(t, err)
					switch pass {
					case forward:
						expectedChecksums[i] = p.ChecksumWithID(routeID)
					case backward:
						require.Equal(t, expectedChecksums[i], p.ChecksumWithID(routeID)) // rng sanity check
					}
				}

				var handleFailure func(policyIndex int)
				if !injectFault {
					handleFailure = func(policyIndex int) {
						t.Errorf("expected policy %d to be freed", policyIndex)
					}
					// compute checksums and routes a bunch of times randomly
					for i := range numChecksumIterations {
						idx := rand.IntN(numPolicies)
						routeID, err := policies[idx].RouteID()
						require.NoError(t, err)
						assert.NotZero(t, policies[idx].ChecksumWithID(routeID))
						assert.Equal(t, expectedChecksums[idx], policies[idx].ChecksumWithID(routeID))
						if i%1000 == 0 {
							runtime.GC()
						}
					}
				} else {
					// to simulate a potential bug, pick two policies at random and update
					// a pointer field in one of the policies to point to a (non-pointer)
					// field in the other policy.
					// important to use the seeded rng here, because we can only catch the
					// error in one of the two directions.
					faultP1, faultP2 := rand.IntN(numPolicies), rand.IntN(numPolicies)
					for faultP2 == faultP1 {
						faultP2 = rand.IntN(numPolicies)
					}
					policies[faultP1].PassIdentityHeaders = &policies[faultP2].PreserveHostHeader

					handleFailure = func(policyIdx int) {
						// p2 keeps p1 alive, so the error could only occur when trying to
						// free p2 before p1. if p1 is freed first, the error is not
						// detected (but will be when iterating in the opposite order)
						if policyIdx != faultP2 {
							t.Errorf("wrong failure index (faultP1=%d, faultP2=%d, policyIdx=%d)", faultP1, faultP2, policyIdx)
						}
						faultInjectionErrorCount.Add(1)
					}
				}

				// zero each policy one at a time, then run GC. if the policy's memory is not
				// aliased somewhere else or held up in a pool, it should free it and increase
				// the counter by 1 in its finalizer.
				var start, end, inc int
				switch pass {
				case forward:
					start, end, inc = 0, numPolicies, 1
				case backward:
					start, end, inc = numPolicies-1, -1, -1
				}

				i := int32(0)
				for policyIdx := start; policyIdx != end; policyIdx += inc {
					require.Equal(t, finalizerCount.Load(), i)
					policies[policyIdx] = nil
					gcWaitFinalizers()
					if count := finalizerCount.Load(); count != i+1 {
						handleFailure(policyIdx)
						break
					}
					i++
				}

				// keep the slice itself alive, otherwise everything will get GC'd in the
				// loop above
				runtime.KeepAlive(policies)
				runtime.GC()
			}
		}

		// run the entire test once normally, and once with a deliberate fault
		// injected to make sure it is caught
		t.Run("Normal", func(t *testing.T) {
			runTest(t, false)
		})
		t.Run("Fault Injection", func(t *testing.T) {
			runTest(t, true)
		})
	})

	t.Run("AsProto", func(t *testing.T) {
		// we need to manually trigger GC in this test to avoid an unlucky automatic
		// GC running during the time in which the only pointer to an object we intend
		// to use later is stored in a uintptr
		debug.SetGCPercent(-1)
		t.Cleanup(func() {
			debug.SetGCPercent(100)
		})

		{
			p := newStaticPolicy()
			checksum := p.Checksum()
			lp := uintptr(unsafe.Pointer(p)) // launder a copy of p so the GC can't see it
			conv, err := p.AsProto()
			require.NoError(t, err)

			// conv holds interior pointers to *p, so zeroing p should not GC it
			assertNotGarbageCollected(t, &p)
			// zeroing conv should allow p to be GC'd in the following cycle
			assertGarbageCollected(t, &conv)
			// restore lp back into a reachable pointer
			// NB: this only works if heap objects cannot move. also, if the GC runs
			// again before we initialize p2 on the line below, it will trigger a
			// fatal error when the sweeper checks for zombies
			p2 := unsafeReinterpretUintptr[config.Policy](lp)
			require.Equal(t, checksum, p2.Checksum()) // this is just a sanity check
			assertGarbageCollected(t, &p2)
		}

		// to make sure the above trick is doing what we expect, try the same thing
		// but reverse the order of which object is zeroed
		{
			p := newStaticPolicy()
			lp := uintptr(unsafe.Pointer(p))
			conv, err := p.AsProto()
			require.NoError(t, err)

			assertGarbageCollected(t, &conv)
			assertGarbageCollected(t, &p)

			// at this point, lp points to garbage
			runtime.KeepAlive(lp)
		}
	})
}

// Sets the given pointer to nil, then runs one GC cycle and asserts that the
// pointer is freed.
func assertGarbageCollected[T any](t testing.TB, p **T) {
	t.Helper()
	gc := make(chan struct{})
	runtime.SetFinalizer(*p, func(*T) {
		close(gc)
	})
	*p = nil
	gcWaitFinalizers()
	select {
	case <-gc:
		t.Log("finalizer hit")
		return
	default:
		t.Error("expected finalizer to run")
	}
}

// Sets the given pointer to nil, then runs one GC cycle and asserts that the
// pointer is *not* freed.
func assertNotGarbageCollected[T any](t testing.TB, p **T) {
	t.Helper()
	gc := make(chan struct{})
	lp := uintptr(unsafe.Pointer(*p))
	runtime.SetFinalizer(*p, func(*T) {
		close(gc)
	})
	*p = nil
	gcWaitFinalizers()
	select {
	case <-gc:
		t.Error("expected finalizer not to run")
		return
	default:
		// clear the finalizer so a different one can be set later on
		runtime.SetFinalizer(unsafeReinterpretUintptr[T](lp), nil)
	}
}

//go:linkname blockUntilEmptyFinalizerQueue runtime.blockUntilEmptyFinalizerQueue
func blockUntilEmptyFinalizerQueue(int64) bool

// runs the GC and waits for all queued finalizers to be called.
func gcWaitFinalizers() {
	runtime.GC()
	blockUntilEmptyFinalizerQueue(int64(1 * time.Second))
}

// converts a uintptr back into a valid *T.
func unsafeReinterpretUintptr[T any](lp uintptr) *T {
	// this extra pointer indirection prevents the go vet warning that usually
	// happens when you try to convert a uintptr back into an unsafe.Pointer
	return *(**T)(unsafe.Pointer(&lp))
}

func TestRouteID(t *testing.T) {
	randomString := func() string {
		return strings.TrimSuffix(cryptutil.NewRandomStringN(mathrand.IntN(31)+1), "=")
	}
	randomBool := func() bool {
		return mathrand.N(2) == 0
	}
	randomURL := func() *url.URL {
		u, err := url.Parse(fmt.Sprintf("https://%s.example.com/%s?foo=%s#%s",
			randomString(), randomString(), randomString(), randomString()))
		require.NoError(t, err)
		return u
	}
	baseFieldMutators := []func(p *config.Policy){
		func(p *config.Policy) { p.From = randomString() },
		func(p *config.Policy) { p.Prefix = randomString() },
		func(p *config.Policy) { p.Path = randomString() },
		func(p *config.Policy) { p.Regex = randomString() },
	}
	toMutators := func(p *config.Policy) {
		p.To = make(config.WeightedURLs, mathrand.N(9)+1)
		for i := 0; i < len(p.To); i++ {
			p.To[i] = config.WeightedURL{URL: *randomURL(), LbWeight: mathrand.Uint32()}
		}
	}
	redirectMutators := []func(p *config.PolicyRedirect){
		func(p *config.PolicyRedirect) { p.HTTPSRedirect = randomPtr(10, randomBool()) },
		func(p *config.PolicyRedirect) { p.SchemeRedirect = randomPtr(10, randomString()) },
		func(p *config.PolicyRedirect) { p.HostRedirect = randomPtr(10, randomString()) },
		func(p *config.PolicyRedirect) { p.PortRedirect = randomPtr(10, mathrand.Uint32()) },
		func(p *config.PolicyRedirect) { p.PathRedirect = randomPtr(10, randomString()) },
		func(p *config.PolicyRedirect) { p.PrefixRewrite = randomPtr(10, randomString()) },
		func(p *config.PolicyRedirect) { p.ResponseCode = randomPtr(10, mathrand.Int32()) },
		func(p *config.PolicyRedirect) { p.StripQuery = randomPtr(10, randomBool()) },
	}
	responseMutators := []func(p *config.DirectResponse){
		func(p *config.DirectResponse) { p.Status = mathrand.Int() },
		func(p *config.DirectResponse) { p.Body = randomString() },
	}

	t.Run("random policies", func(t *testing.T) {
		hashes := make(map[uint64]struct{}, 10000)
		for i := 0; i < 10000; i++ {
			p := config.Policy{}
			for _, m := range baseFieldMutators {
				m(&p)
			}
			switch mathrand.IntN(3) {
			case 0:
				toMutators(&p)
			case 1:
				p.Redirect = &config.PolicyRedirect{}
				for _, m := range redirectMutators {
					m(p.Redirect)
				}
			case 2:
				p.Response = &config.DirectResponse{}
				for _, m := range responseMutators {
					m(p.Response)
				}
			}

			routeID, err := p.RouteID()
			require.NoError(t, err)
			hashes[routeID] = struct{}{} // odds of a collision should be pretty low here

			// check that computing the route id again results in the same value
			routeID2, err := p.RouteID()
			require.NoError(t, err)
			assert.Equal(t, routeID, routeID2)
		}
		assert.Len(t, hashes, 10000)
	})
	t.Run("incremental policy", func(t *testing.T) {
		hashes := make(map[uint64]config.Policy, 5000)

		p := config.Policy{}

		checkAdd := func(p *config.Policy) {
			routeID, err := p.RouteID()
			require.NoError(t, err)
			if existing, ok := hashes[routeID]; ok {
				require.Equal(t, existing, *p)
			} else {
				hashes[routeID] = *p
			}

			// check that computing the route id again results in the same value
			routeID2, err := p.RouteID()
			require.NoError(t, err)
			assert.Equal(t, routeID, routeID2)
		}

		// to
		toMutators(&p)
		checkAdd(&p)

		// set base fields
		for _, m := range baseFieldMutators {
			m(&p)
			checkAdd(&p)
		}

		// redirect
		p.To = nil
		p.Redirect = &config.PolicyRedirect{}
		for range 1000 {
			for _, m := range redirectMutators {
				m(p.Redirect)
				checkAdd(&p)
			}
		}

		// update base fields
		for _, m := range baseFieldMutators {
			m(&p)
			checkAdd(&p)
		}

		// direct response
		p.Redirect = nil
		p.Response = &config.DirectResponse{}
		for range 1000 {
			for _, m := range responseMutators {
				m(p.Response)
				checkAdd(&p)
			}
		}

		// update base fields
		for _, m := range baseFieldMutators {
			m(&p)
			checkAdd(&p)
		}

		// sanity check
		assert.Greater(t, len(hashes), 2000)
	})
	t.Run("field separation", func(t *testing.T) {
		cases := []struct {
			a, b *config.Policy
		}{
			{
				&config.Policy{From: "foo", Prefix: "bar"},
				&config.Policy{From: "f", Prefix: "oobar"},
			},
			{
				&config.Policy{From: "foo", Prefix: "bar"},
				&config.Policy{From: "foobar", Prefix: ""},
			},
			{
				&config.Policy{From: "foobar", Prefix: ""},
				&config.Policy{From: "", Prefix: "foobar"},
			},
			{
				&config.Policy{From: "foo", Prefix: "", Path: "bar"},
				&config.Policy{From: "foo", Prefix: "bar", Path: ""},
			},
			{
				&config.Policy{From: "", Prefix: "foo", Path: "bar"},
				&config.Policy{From: "foo", Prefix: "bar", Path: ""},
			},
			{
				&config.Policy{From: "", Prefix: "foo", Path: "bar"},
				&config.Policy{From: "foo", Prefix: "", Path: "bar"},
			},
		}
		for _, c := range cases {
			c.a.To = mustParseWeightedURLs(t, "https://foo")
			c.b.To = mustParseWeightedURLs(t, "https://foo")
		}

		for _, c := range cases {
			a, err := c.a.RouteID()
			require.NoError(t, err)
			b, err := c.b.RouteID()
			require.NoError(t, err)
			assert.NotEqual(t, a, b)
		}
	})
}

func randomPtr[T any](nilChance int, t T) *T {
	if mathrand.N(nilChance) == 0 {
		return nil
	}
	return &t
}

func TestRoute_FromToProto(t *testing.T) {
	routeGen := protorand.New[*configpb.Route]()
	routeGen.MaxCollectionElements = 2
	routeGen.UseGoDurationLimits = true
	routeGen.ExcludeMask(&fieldmaskpb.FieldMask{
		Paths: []string{
			"from", "to", "load_balancing_weights", "redirect", "response", // set below
			"ppl_policies", "name", // no equivalent field
			"envoy_opts",
		},
	})
	redirectGen := protorand.New[*configpb.RouteRedirect]()
	responseGen := protorand.New[*configpb.RouteDirectResponse]()

	randomDomain := func() string {
		numSegments := mathrand.IntN(5) + 1
		segments := make([]string, numSegments)
		for i := range segments {
			b := make([]rune, mathrand.IntN(10)+10)
			for j := range b {
				b[j] = rune(mathrand.IntN(26) + 'a')
			}
			segments[i] = string(b)
		}
		return strings.Join(segments, ".")
	}

	newCompleteRoute := func() *configpb.Route {
		pb, err := routeGen.Gen()

		require.NoError(t, err)
		pb.From = "https://" + randomDomain()
		// EnvoyOpts is set to an empty non-nil message during conversion, if nil
		pb.EnvoyOpts = &envoy_config_cluster_v3.Cluster{}

		switch mathrand.IntN(3) {
		case 0:
			pb.To = make([]string, mathrand.IntN(3)+1)
			for i := range pb.To {
				pb.To[i] = "https://" + randomDomain()
			}
			pb.LoadBalancingWeights = make([]uint32, len(pb.To))
			for i := range pb.LoadBalancingWeights {
				pb.LoadBalancingWeights[i] = mathrand.Uint32N(10000) + 1
			}
		case 1:
			pb.Redirect, err = redirectGen.Gen()
			require.NoError(t, err)
		case 2:
			pb.Response, err = responseGen.Gen()
			require.NoError(t, err)
		}
		return pb
	}

	t.Run("Round Trip", func(t *testing.T) {
		for range 100 {
			route := newCompleteRoute()

			policy, err := config.NewPolicyFromProto(route)
			require.NoError(t, err)

			route2 := &configpb.Route{}
			policy.ShallowCopyToProto(route2)

			testutil.AssertProtoEqual(t, route, route2)

			empty := config.Policy{}
			empty.ShallowCopyToProto(route2)

			testutil.AssertProtoEqual(t, &configpb.Route{}, route2)
		}
	})

	t.Run("Repeated copy", func(t *testing.T) {
		for range 100 {
			route := newCompleteRoute()
			policy, err := config.NewPolicyFromProto(route)
			require.NoError(t, err)

			route2 := &configpb.Route{}
			policy.ShallowCopyToProto(route2)
			testutil.AssertProtoEqual(t, route, route2)
			policy.ShallowCopyToProto(route2)
			testutil.AssertProtoEqual(t, route, route2)
			policy.ShallowCopyToProto(route2)
			testutil.AssertProtoEqual(t, route, route2)

			empty := config.Policy{}
			empty.ShallowCopyToProto(route2)
			testutil.AssertProtoEqual(t, &configpb.Route{}, route2)
			empty.ShallowCopyToProto(route2)
			testutil.AssertProtoEqual(t, &configpb.Route{}, route2)
			empty.ShallowCopyToProto(route2)
			testutil.AssertProtoEqual(t, &configpb.Route{}, route2)
		}
	})

	t.Run("Multiple routes", func(t *testing.T) {
		for range 100 {
			route1 := newCompleteRoute()
			route2 := newCompleteRoute()

			target := &configpb.Route{}
			{
				// create a new policy every time, since reusing the target will mutate
				// the underlying route
				policy1, err := config.NewPolicyFromProto(route1)
				require.NoError(t, err)
				policy1.ShallowCopyToProto(target)
				testutil.AssertProtoEqual(t, route1, target)
			}
			{
				policy2, err := config.NewPolicyFromProto(route2)
				require.NoError(t, err)
				policy2.ShallowCopyToProto(target)
				testutil.AssertProtoEqual(t, route2, target)
			}
			{
				policy1, err := config.NewPolicyFromProto(route1)
				require.NoError(t, err)
				policy1.ShallowCopyToProto(target)
				testutil.AssertProtoEqual(t, route1, target)
			}
			{
				policy2, err := config.NewPolicyFromProto(route2)
				require.NoError(t, err)
				policy2.ShallowCopyToProto(target)
				testutil.AssertProtoEqual(t, route2, target)
			}
		}
	})
}
