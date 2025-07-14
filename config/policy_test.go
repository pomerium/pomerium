package config

import (
	"encoding/json"
	"fmt"
	mathrand "math/rand/v2"
	"net/url"
	"strings"
	"testing"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/config"
)

func Test_PolicyValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		policy  Policy
		wantErr bool
	}{
		{"good", Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://httpbin.corp.notatld")}, false},
		{"empty to host", Policy{From: "https://httpbin.corp.example", To: []WeightedURL{{URL: url.URL{Scheme: "https", Path: "/"}}}}, true},
		{"empty from host", Policy{From: "https://", To: mustParseWeightedURLs(t, "https://httpbin.corp.example")}, true},
		{"empty from scheme", Policy{From: "httpbin.corp.example", To: mustParseWeightedURLs(t, "https://httpbin.corp.example")}, true},
		{"empty to scheme", Policy{From: "https://httpbin.corp.example", To: []WeightedURL{{URL: url.URL{Host: "httpbin.corp.example"}}}}, true},
		{"path in from", Policy{From: "https://httpbin.corp.example/some/path", To: mustParseWeightedURLs(t, "https://httpbin.corp.example")}, true},
		{"cors policy", Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://httpbin.corp.notatld"), CORSAllowPreflight: true}, false},
		{"public policy", Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://httpbin.corp.notatld"), AllowPublicUnauthenticatedAccess: true}, false},
		{"public and whitelist", Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://httpbin.corp.notatld"), AllowPublicUnauthenticatedAccess: true, AllowedUsers: []string{"test@domain.example"}}, true},
		{"route must have", Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://httpbin.corp.notatld"), AllowPublicUnauthenticatedAccess: true, AllowedUsers: []string{"test@domain.example"}}, true},
		{"any authenticated user policy", Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://httpbin.corp.notatld"), AllowAnyAuthenticatedUser: true}, false},
		{"any authenticated user and whitelist", Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://httpbin.corp.notatld"), AllowAnyAuthenticatedUser: true, AllowedUsers: []string{"test@domain.example"}}, true},
		{"good client cert", Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://httpbin.corp.notatld"), TLSClientKey: "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcGdJQkFBS0NBUUVBNjdLanFtUVlHcTBNVnRBQ1ZwZUNtWG1pbmxRYkRQR0xtc1pBVUV3dWVIUW5ydDNXCnR2cERPbTZBbGFKTVVuVytIdTU1ampva2FsS2VWalRLbWdZR2JxVXpWRG9NYlBEYUhla2x0ZEJUTUdsT1VGc1AKNFVKU0RyTzR6ZE4rem80MjhUWDJQbkcyRkNkVktHeTRQRThpbEhiV0xjcjg3MVlqVjUxZnc4Q0xEWDlQWkpOdQo4NjFDRjdWOWlFSm02c1NmUWxtbmhOOGozK1d6VmJQUU55MVdzUjdpOWU5ajYzRXFLdDIyUTlPWEwrV0FjS3NrCm9JU21DTlZSVUFqVThZUlZjZ1FKQit6UTM0QVFQbHowT3A1Ty9RTi9NZWRqYUY4d0xTK2l2L3p2aVM4Y3FQYngKbzZzTHE2Rk5UbHRrL1FreGVDZUtLVFFlLzNrUFl2UUFkbmw2NVFJREFRQUJBb0lCQVFEQVQ0eXN2V2pSY3pxcgpKcU9SeGFPQTJEY3dXazJML1JXOFhtQWhaRmRTWHV2MkNQbGxhTU1yelBmTG41WUlmaHQzSDNzODZnSEdZc3pnClo4aWJiYWtYNUdFQ0t5N3lRSDZuZ3hFS3pRVGpiampBNWR3S0h0UFhQUnJmamQ1Y2FMczVpcDcxaWxCWEYxU3IKWERIaXUycnFtaC9kVTArWGRMLzNmK2VnVDl6bFQ5YzRyUm84dnZueWNYejFyMnVhRVZ2VExsWHVsb2NpeEVrcgoySjlTMmxveWFUb2tFTnNlMDNpSVdaWnpNNElZcVowOGJOeG9IWCszQXVlWExIUStzRkRKMlhaVVdLSkZHMHUyClp3R2w3YlZpRTFQNXdiQUdtZzJDeDVCN1MrdGQyUEpSV3Frb2VxY3F2RVdCc3RFL1FEcDFpVThCOHpiQXd0Y3IKZHc5TXZ6Q2hBb0dCQVBObzRWMjF6MGp6MWdEb2tlTVN5d3JnL2E4RkJSM2R2Y0xZbWV5VXkybmd3eHVucnFsdwo2U2IrOWdrOGovcXEvc3VQSDhVdzNqSHNKYXdGSnNvTkVqNCt2b1ZSM3UrbE5sTEw5b21rMXBoU0dNdVp0b3huCm5nbUxVbkJUMGI1M3BURkJ5WGsveE5CbElreWdBNlg5T2MreW5na3RqNlRyVnMxUERTdnVJY0s1QW9HQkFQZmoKcEUzR2F6cVFSemx6TjRvTHZmQWJBdktCZ1lPaFNnemxsK0ZLZkhzYWJGNkdudFd1dWVhY1FIWFpYZTA1c2tLcApXN2xYQ3dqQU1iUXI3QmdlazcrOSszZElwL1RnYmZCYnN3Syt6Vng3Z2doeWMrdytXRWExaHByWTZ6YXdxdkFaCkhRU2lMUEd1UGp5WXBQa1E2ZFdEczNmWHJGZ1dlTmd4SkhTZkdaT05Bb0dCQUt5WTF3MUM2U3Y2c3VuTC8vNTcKQ2Z5NTAwaXlqNUZBOWRqZkRDNWt4K1JZMnlDV0ExVGsybjZyVmJ6dzg4czBTeDMrYS9IQW1CM2dMRXBSRU5NKwo5NHVwcENFWEQ3VHdlcGUxUnlrTStKbmp4TzlDSE41c2J2U25sUnBQWlMvZzJRTVhlZ3grK2trbkhXNG1ITkFyCndqMlRrMXBBczFXbkJ0TG9WaGVyY01jSkFvR0JBSTYwSGdJb0Y5SysvRUcyY21LbUg5SDV1dGlnZFU2eHEwK0IKWE0zMWMzUHE0amdJaDZlN3pvbFRxa2d0dWtTMjBraE45dC9ibkI2TmhnK1N1WGVwSXFWZldVUnlMejVwZE9ESgo2V1BMTTYzcDdCR3cwY3RPbU1NYi9VRm5Yd0U4OHlzRlNnOUF6VjdVVUQvU0lDYkI5ZHRVMWh4SHJJK0pZRWdWCkFrZWd6N2lCQW9HQkFJRncrQVFJZUIwM01UL0lCbGswNENQTDJEak0rNDhoVGRRdjgwMDBIQU9mUWJrMEVZUDEKQ2FLR3RDbTg2MXpBZjBzcS81REtZQ0l6OS9HUzNYRk00Qm1rRk9nY1NXVENPNmZmTGdLM3FmQzN4WDJudlpIOQpYZGNKTDQrZndhY0x4c2JJKzhhUWNOVHRtb3pkUjEzQnNmUmIrSGpUL2o3dkdrYlFnSkhCT0syegotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=", TLSClientCert: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUVJVENDQWdtZ0F3SUJBZ0lSQVBqTEJxS1lwcWU0ekhQc0dWdFR6T0F3RFFZSktvWklodmNOQVFFTEJRQXcKRWpFUU1BNEdBMVVFQXhNSFoyOXZaQzFqWVRBZUZ3MHhPVEE0TVRBeE9EUTVOREJhRncweU1UQXlNVEF4TnpRdwpNREZhTUJNeEVUQVBCZ05WQkFNVENIQnZiV1Z5YVhWdE1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBCk1JSUJDZ0tDQVFFQTY3S2pxbVFZR3EwTVZ0QUNWcGVDbVhtaW5sUWJEUEdMbXNaQVVFd3VlSFFucnQzV3R2cEQKT202QWxhSk1VblcrSHU1NWpqb2thbEtlVmpUS21nWUdicVV6VkRvTWJQRGFIZWtsdGRCVE1HbE9VRnNQNFVKUwpEck80emROK3pvNDI4VFgyUG5HMkZDZFZLR3k0UEU4aWxIYldMY3I4NzFZalY1MWZ3OENMRFg5UFpKTnU4NjFDCkY3VjlpRUptNnNTZlFsbW5oTjhqMytXelZiUFFOeTFXc1I3aTllOWo2M0VxS3QyMlE5T1hMK1dBY0tza29JU20KQ05WUlVBalU4WVJWY2dRSkIrelEzNEFRUGx6ME9wNU8vUU4vTWVkamFGOHdMUytpdi96dmlTOGNxUGJ4bzZzTApxNkZOVGx0ay9Ra3hlQ2VLS1RRZS8za1BZdlFBZG5sNjVRSURBUUFCbzNFd2J6QU9CZ05WSFE4QkFmOEVCQU1DCkE3Z3dIUVlEVlIwbEJCWXdGQVlJS3dZQkJRVUhBd0VHQ0NzR0FRVUZCd01DTUIwR0ExVWREZ1FXQkJRQ1FYbWIKc0hpcS9UQlZUZVhoQ0dpNjhrVy9DakFmQmdOVkhTTUVHREFXZ0JSNTRKQ3pMRlg0T0RTQ1J0dWNBUGZOdVhWegpuREFOQmdrcWhraUc5dzBCQVFzRkFBT0NBZ0VBcm9XL2trMllleFN5NEhaQXFLNDVZaGQ5ay9QVTFiaDlFK1BRCk5jZFgzTUdEY2NDRUFkc1k4dll3NVE1cnhuMGFzcSt3VGFCcGxoYS9rMi9VVW9IQ1RqUVp1Mk94dEF3UTdPaWIKVE1tMEorU3NWT3d4YnFQTW9rK1RqVE16NFdXaFFUTzVwRmNoZDZXZXNCVHlJNzJ0aG1jcDd1c2NLU2h3YktIegpQY2h1QTQ4SzhPdi96WkxmZnduQVNZb3VCczJjd1ZiRDI3ZXZOMzdoMGFzR1BrR1VXdm1PSDduTHNVeTh3TTdqCkNGL3NwMmJmTC9OYVdNclJnTHZBMGZMS2pwWTQrVEpPbkVxQmxPcCsrbHlJTEZMcC9qMHNybjRNUnlKK0t6UTEKR1RPakVtQ1QvVEFtOS9XSThSL0FlYjcwTjEzTytYNEtaOUJHaDAxTzN3T1Vqd3BZZ3lxSnNoRnNRUG50VmMrSQpKQmF4M2VQU3NicUcwTFkzcHdHUkpRNmMrd1lxdGk2Y0tNTjliYlRkMDhCNUk1N1RRTHhNcUoycTFnWmw1R1VUCmVFZGNWRXltMnZmd0NPd0lrbGNBbThxTm5kZGZKV1FabE5VaHNOVWFBMkVINnlDeXdaZm9aak9hSDEwTXowV20KeTNpZ2NSZFQ3Mi9NR2VkZk93MlV0MVVvRFZmdEcxcysrditUQ1lpNmpUQU05dkZPckJ4UGlOeGFkUENHR2NZZAowakZIc2FWOGFPV1dQQjZBQ1JteHdDVDdRTnRTczM2MlpIOUlFWWR4Q00yMDUrZmluVHhkOUcwSmVRRTd2Kyt6CldoeWo2ZmJBWUIxM2wvN1hkRnpNSW5BOGxpekdrVHB2RHMxeTBCUzlwV3ppYmhqbVFoZGZIejdCZGpGTHVvc2wKZzlNZE5sND0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="}, false},
		{"bad base64 client cert", Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://httpbin.corp.notatld"), TLSClientKey: "!=", TLSClientCert: "!="}, true},
		{"bad one client cert empty", Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://httpbin.corp.notatld"), TLSClientKey: "", TLSClientCert: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUVJVENDQWdtZ0F3SUJBZ0lSQVBqTEJxS1lwcWU0ekhQc0dWdFR6T0F3RFFZSktvWklodmNOQVFFTEJRQXcKRWpFUU1BNEdBMVVFQXhNSFoyOXZaQzFqWVRBZUZ3MHhPVEE0TVRBeE9EUTVOREJhRncweU1UQXlNVEF4TnpRdwpNREZhTUJNeEVUQVBCZ05WQkFNVENIQnZiV1Z5YVhWdE1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBCk1JSUJDZ0tDQVFFQTY3S2pxbVFZR3EwTVZ0QUNWcGVDbVhtaW5sUWJEUEdMbXNaQVVFd3VlSFFucnQzV3R2cEQKT202QWxhSk1VblcrSHU1NWpqb2thbEtlVmpUS21nWUdicVV6VkRvTWJQRGFIZWtsdGRCVE1HbE9VRnNQNFVKUwpEck80emROK3pvNDI4VFgyUG5HMkZDZFZLR3k0UEU4aWxIYldMY3I4NzFZalY1MWZ3OENMRFg5UFpKTnU4NjFDCkY3VjlpRUptNnNTZlFsbW5oTjhqMytXelZiUFFOeTFXc1I3aTllOWo2M0VxS3QyMlE5T1hMK1dBY0tza29JU20KQ05WUlVBalU4WVJWY2dRSkIrelEzNEFRUGx6ME9wNU8vUU4vTWVkamFGOHdMUytpdi96dmlTOGNxUGJ4bzZzTApxNkZOVGx0ay9Ra3hlQ2VLS1RRZS8za1BZdlFBZG5sNjVRSURBUUFCbzNFd2J6QU9CZ05WSFE4QkFmOEVCQU1DCkE3Z3dIUVlEVlIwbEJCWXdGQVlJS3dZQkJRVUhBd0VHQ0NzR0FRVUZCd01DTUIwR0ExVWREZ1FXQkJRQ1FYbWIKc0hpcS9UQlZUZVhoQ0dpNjhrVy9DakFmQmdOVkhTTUVHREFXZ0JSNTRKQ3pMRlg0T0RTQ1J0dWNBUGZOdVhWegpuREFOQmdrcWhraUc5dzBCQVFzRkFBT0NBZ0VBcm9XL2trMllleFN5NEhaQXFLNDVZaGQ5ay9QVTFiaDlFK1BRCk5jZFgzTUdEY2NDRUFkc1k4dll3NVE1cnhuMGFzcSt3VGFCcGxoYS9rMi9VVW9IQ1RqUVp1Mk94dEF3UTdPaWIKVE1tMEorU3NWT3d4YnFQTW9rK1RqVE16NFdXaFFUTzVwRmNoZDZXZXNCVHlJNzJ0aG1jcDd1c2NLU2h3YktIegpQY2h1QTQ4SzhPdi96WkxmZnduQVNZb3VCczJjd1ZiRDI3ZXZOMzdoMGFzR1BrR1VXdm1PSDduTHNVeTh3TTdqCkNGL3NwMmJmTC9OYVdNclJnTHZBMGZMS2pwWTQrVEpPbkVxQmxPcCsrbHlJTEZMcC9qMHNybjRNUnlKK0t6UTEKR1RPakVtQ1QvVEFtOS9XSThSL0FlYjcwTjEzTytYNEtaOUJHaDAxTzN3T1Vqd3BZZ3lxSnNoRnNRUG50VmMrSQpKQmF4M2VQU3NicUcwTFkzcHdHUkpRNmMrd1lxdGk2Y0tNTjliYlRkMDhCNUk1N1RRTHhNcUoycTFnWmw1R1VUCmVFZGNWRXltMnZmd0NPd0lrbGNBbThxTm5kZGZKV1FabE5VaHNOVWFBMkVINnlDeXdaZm9aak9hSDEwTXowV20KeTNpZ2NSZFQ3Mi9NR2VkZk93MlV0MVVvRFZmdEcxcysrditUQ1lpNmpUQU05dkZPckJ4UGlOeGFkUENHR2NZZAowakZIc2FWOGFPV1dQQjZBQ1JteHdDVDdRTnRTczM2MlpIOUlFWWR4Q00yMDUrZmluVHhkOUcwSmVRRTd2Kyt6CldoeWo2ZmJBWUIxM2wvN1hkRnpNSW5BOGxpekdrVHB2RHMxeTBCUzlwV3ppYmhqbVFoZGZIejdCZGpGTHVvc2wKZzlNZE5sND0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="}, true},
		{"bad th other client cert empty", Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://httpbin.corp.notatld"), TLSClientKey: "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcGdJQkFBS0NBUUVBNjdLanFtUVlHcTBNVnRBQ1ZwZUNtWG1pbmxRYkRQR0xtc1pBVUV3dWVIUW5ydDNXCnR2cERPbTZBbGFKTVVuVytIdTU1ampva2FsS2VWalRLbWdZR2JxVXpWRG9NYlBEYUhla2x0ZEJUTUdsT1VGc1AKNFVKU0RyTzR6ZE4rem80MjhUWDJQbkcyRkNkVktHeTRQRThpbEhiV0xjcjg3MVlqVjUxZnc4Q0xEWDlQWkpOdQo4NjFDRjdWOWlFSm02c1NmUWxtbmhOOGozK1d6VmJQUU55MVdzUjdpOWU5ajYzRXFLdDIyUTlPWEwrV0FjS3NrCm9JU21DTlZSVUFqVThZUlZjZ1FKQit6UTM0QVFQbHowT3A1Ty9RTi9NZWRqYUY4d0xTK2l2L3p2aVM4Y3FQYngKbzZzTHE2Rk5UbHRrL1FreGVDZUtLVFFlLzNrUFl2UUFkbmw2NVFJREFRQUJBb0lCQVFEQVQ0eXN2V2pSY3pxcgpKcU9SeGFPQTJEY3dXazJML1JXOFhtQWhaRmRTWHV2MkNQbGxhTU1yelBmTG41WUlmaHQzSDNzODZnSEdZc3pnClo4aWJiYWtYNUdFQ0t5N3lRSDZuZ3hFS3pRVGpiampBNWR3S0h0UFhQUnJmamQ1Y2FMczVpcDcxaWxCWEYxU3IKWERIaXUycnFtaC9kVTArWGRMLzNmK2VnVDl6bFQ5YzRyUm84dnZueWNYejFyMnVhRVZ2VExsWHVsb2NpeEVrcgoySjlTMmxveWFUb2tFTnNlMDNpSVdaWnpNNElZcVowOGJOeG9IWCszQXVlWExIUStzRkRKMlhaVVdLSkZHMHUyClp3R2w3YlZpRTFQNXdiQUdtZzJDeDVCN1MrdGQyUEpSV3Frb2VxY3F2RVdCc3RFL1FEcDFpVThCOHpiQXd0Y3IKZHc5TXZ6Q2hBb0dCQVBObzRWMjF6MGp6MWdEb2tlTVN5d3JnL2E4RkJSM2R2Y0xZbWV5VXkybmd3eHVucnFsdwo2U2IrOWdrOGovcXEvc3VQSDhVdzNqSHNKYXdGSnNvTkVqNCt2b1ZSM3UrbE5sTEw5b21rMXBoU0dNdVp0b3huCm5nbUxVbkJUMGI1M3BURkJ5WGsveE5CbElreWdBNlg5T2MreW5na3RqNlRyVnMxUERTdnVJY0s1QW9HQkFQZmoKcEUzR2F6cVFSemx6TjRvTHZmQWJBdktCZ1lPaFNnemxsK0ZLZkhzYWJGNkdudFd1dWVhY1FIWFpYZTA1c2tLcApXN2xYQ3dqQU1iUXI3QmdlazcrOSszZElwL1RnYmZCYnN3Syt6Vng3Z2doeWMrdytXRWExaHByWTZ6YXdxdkFaCkhRU2lMUEd1UGp5WXBQa1E2ZFdEczNmWHJGZ1dlTmd4SkhTZkdaT05Bb0dCQUt5WTF3MUM2U3Y2c3VuTC8vNTcKQ2Z5NTAwaXlqNUZBOWRqZkRDNWt4K1JZMnlDV0ExVGsybjZyVmJ6dzg4czBTeDMrYS9IQW1CM2dMRXBSRU5NKwo5NHVwcENFWEQ3VHdlcGUxUnlrTStKbmp4TzlDSE41c2J2U25sUnBQWlMvZzJRTVhlZ3grK2trbkhXNG1ITkFyCndqMlRrMXBBczFXbkJ0TG9WaGVyY01jSkFvR0JBSTYwSGdJb0Y5SysvRUcyY21LbUg5SDV1dGlnZFU2eHEwK0IKWE0zMWMzUHE0amdJaDZlN3pvbFRxa2d0dWtTMjBraE45dC9ibkI2TmhnK1N1WGVwSXFWZldVUnlMejVwZE9ESgo2V1BMTTYzcDdCR3cwY3RPbU1NYi9VRm5Yd0U4OHlzRlNnOUF6VjdVVUQvU0lDYkI5ZHRVMWh4SHJJK0pZRWdWCkFrZWd6N2lCQW9HQkFJRncrQVFJZUIwM01UL0lCbGswNENQTDJEak0rNDhoVGRRdjgwMDBIQU9mUWJrMEVZUDEKQ2FLR3RDbTg2MXpBZjBzcS81REtZQ0l6OS9HUzNYRk00Qm1rRk9nY1NXVENPNmZmTGdLM3FmQzN4WDJudlpIOQpYZGNKTDQrZndhY0x4c2JJKzhhUWNOVHRtb3pkUjEzQnNmUmIrSGpUL2o3dkdrYlFnSkhCT0syegotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=", TLSClientCert: ""}, true},
		{"good root ca pool", Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://httpbin.corp.notatld"), TLSCustomCA: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUU1RENDQXN5Z0F3SUJBZ0lCQVRBTkJna3Foa2lHOXcwQkFRc0ZBREFTTVJBd0RnWURWUVFERXdkbmIyOWsKTFdOaE1CNFhEVEU1TURneE1ERTNOREF3TWxvWERUSXhNREl4TURFM05EQXdNbG93RWpFUU1BNEdBMVVFQXhNSApaMjl2WkMxallUQ0NBaUl3RFFZSktvWklodmNOQVFFQkJRQURnZ0lQQURDQ0Fnb0NnZ0lCQUw3b2VldEovNmNFCkdicTcvanNtcU9FM2VyVE1aRHR0eFM4STVGV1c0TkRXbWNpOE5IdWRMZDhlM1JtOEh6Y09jSjRQL0ErcDVsYmsKTjhySzY4OUlsQzhqM28yaEhSdEk2T21saFY3NEoxaUlIOGtkSXU2V2xPMWtOdUx5dGRrbjhRaytJOUNEWjlGSAorZzhRbnVka0tMUWJkZFdDVXJzUjR4cEcyK0VkNWdua0JJNG4zbmNLMFgvWEZocWhDTEU1eFBaQk5OWktGbHJxCm1lYUl4dHoyc2ZvWVY1NmcwMnNGS1QxSUlMNTVFMG14djRUa2JtSWw5Rk9qZEtCdkhFZnJHeXl5OFRGTHErUzMKTXo2em9xNDhuOEhGMUc5cHBLVk9OMUp0Mks1UWEvV2hpbjVrcWNhYTNwNE0vN2tiNmtxU0tMWG1iN0gyN3kvVQpEYjZDUG01d2lodjA2c1FobXN2MHhuS2hqMm8vQzhlcWxzNzZZWDF1Y2NqMzlmSTRlQ1E4cENFbTlVcDh5ZkkvCkxlYVpXbGE0NEZneWw3N1lyc2MvM0U5dk1hS0ZVeGRjR3VtMXQrNUZZYWpkY0EvTlFreTJBeTJqcHRwVXV1SFUKNnhYSzdEcXY5Z01jQS8zM1VYOFpHZklPRk0rY3FlOTQxaTVPT1hGSHJoRDlqeTRQR2M4Z2kxSTRyK1VXd0tCYgoxSGg1clQ3ckJZK1NLTTBzZmtpQlZ1RU9pbnk2dDF1Z2tEdjY4dXNFWFlIWlZXaWl6b1hmcDVHbjZmckUvd1IxCkRkak13TGEvT2tQTnVEVVQ4eU1GS2hWRnFHcXdHQzY2bys1cjQyMlVwa0s4SHJ5K2tsQ3pUTys3U0RodTJiWk4KUVFGT0NLSVVldnR3bGdabVBNck1BNTZ3dzVSSnNhVnhBZ01CQUFHalJUQkRNQTRHQTFVZER3RUIvd1FFQXdJQgpCakFTQmdOVkhSTUJBZjhFQ0RBR0FRSC9BZ0VBTUIwR0ExVWREZ1FXQkJSNTRKQ3pMRlg0T0RTQ1J0dWNBUGZOCnVYVnpuREFOQmdrcWhraUc5dzBCQVFzRkFBT0NBZ0VBZituUmpBVnZuT0pSckpBQWpKWVY3aVF3bHExUXZYRGcKbHZhY0JoVFJyWFh4OW5GaVRZUzV4MkFMbXZ5WHhubTdIS2VDSUZEclJwOE5MVFkyYjJXR01BcTFxc3JBT0QvegpTNmNSSW1OQ21QNmd0UHNUNDlabzBYajNrZjZyTXBPeHBiSUlnSmZMY056UGZpL25jeC9oRDNBOHl6Zk4wQTZZCnFFd2QvSkZPajdEa3RaQmdlSXZETlJXS0pveEpJRlZ4anJqLzFiVmkxZTRWVjVvWmhOako4SzlyV1FRK1EvK3QKZ3lGK0sycGxDQ1RiRWR6eU9heDY1djh5UDJ5RCs2WkFIRk9sRjI2TnZpUkw4OWJ1VHIwaEpZa0N5VXZ3MmJZaQo4Q3MyWDZkd0NDdXVhZUdVR2VRemszMGxQeUdWSmVKL3ZJMGJRSzlpZ2I5dFozY3d0WHBQdjN6a1B1TDE3d01WCitCMXo2RW1HZVVLNXlTQ0xFWjc2aVliNU0vY3ZjTUVOMWdoeFNIN0FmaDhMS0c0eWszT21SQ253akVqdTFhaWoKZGs3cjJuc0xmYU9KWFBRNU1wMzRYU1ltdTlpTVl0VytMbWZiSDJxMW9vS3dKZDhHNVhhRWRmQmpHUEQ5Q3FkWAphSlh0MDA0cVdsalJOS3p1MFNFRmJ6UldGNHRoeXlUTzE4QVI4eTNHV0Vwak95amdKSzlFeU1sQm9Qa3RYQVVVCjZzTFhqT3ZZU0ovd202NUhxVVZBTTVsRy96WVN3TGdCTDAwc1pJKzVGa0QwblU0Rkx6QWRLV05LWkRXZFVNbUwKVi9lV0ZGNGwwVFBvNTVhM0pUL1BGc2J0RFBLVWxvWVFXeTFybmFqR3J1L0Y5bGRCcHB1bUVUa2FOS2ZWT05Jcgp4cERnc1FhVkVXOD0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="}, false},
		{"bad root ca pool", Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://httpbin.corp.notatld"), TLSCustomCA: "!"}, true},
		{"good custom ca file", Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://httpbin.corp.notatld"), TLSCustomCAFile: "testdata/ca.pem"}, false},
		{"bad custom ca file", Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://httpbin.corp.notatld"), TLSCustomCAFile: "testdata/404.pem"}, true},
		{"good client certificate files", Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://httpbin.corp.notatld"), TLSClientCertFile: "testdata/example-cert.pem", TLSClientKeyFile: "testdata/example-key.pem"}, false},
		{"bad certificate file", Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://httpbin.corp.notatld"), TLSClientCertFile: "testdata/example-cert-404.pem", TLSClientKeyFile: "testdata/example-key.pem"}, true},
		{"bad key file", Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://httpbin.corp.notatld"), TLSClientCertFile: "testdata/example-cert.pem", TLSClientKeyFile: "testdata/example-key-404.pem"}, true},
		{"good tls server name", Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://internal-host-name"), TLSServerName: "httpbin.corp.notatld"}, false},
		{"good kube service account token file", Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://internal-host-name"), KubernetesServiceAccountTokenFile: "testdata/kubeserviceaccount.token"}, false},
		{"good kube service account token", Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://internal-host-name"), KubernetesServiceAccountToken: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE1OTY1MDk4MjIsImV4cCI6MTYyODA0NTgyMiwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsIkdpdmVuTmFtZSI6IkpvaG5ueSIsIlN1cm5hbWUiOiJSb2NrZXQiLCJFbWFpbCI6Impyb2NrZXRAZXhhbXBsZS5jb20iLCJSb2xlIjpbIk1hbmFnZXIiLCJQcm9qZWN0IEFkbWluaXN0cmF0b3IiXX0.H0I6ccQrL6sKobsKQj9dqNcLw_INhU9_xJsVyCkgkiY"}, false},
		{"bad kube service account token and file", Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://internal-host-name"), KubernetesServiceAccountToken: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE1OTY1MDk4MjIsImV4cCI6MTYyODA0NTgyMiwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsIkdpdmVuTmFtZSI6IkpvaG5ueSIsIlN1cm5hbWUiOiJSb2NrZXQiLCJFbWFpbCI6Impyb2NrZXRAZXhhbXBsZS5jb20iLCJSb2xlIjpbIk1hbmFnZXIiLCJQcm9qZWN0IEFkbWluaXN0cmF0b3IiXX0.H0I6ccQrL6sKobsKQj9dqNcLw_INhU9_xJsVyCkgkiY", KubernetesServiceAccountTokenFile: "testdata/kubeserviceaccount.token"}, true},
		{"TCP To URLs", Policy{From: "tcp+https://httpbin.corp.example:4000", To: mustParseWeightedURLs(t, "tcp://one.example.com:5000", "tcp://two.example.com:5000")}, false},
		{"mix of TCP and non-TCP To URLs", Policy{From: "tcp+https://httpbin.corp.example:4000", To: mustParseWeightedURLs(t, "https://example.com", "tcp://example.com:5000")}, true},
		{"UDP To URLs", Policy{From: "udp+https://httpbin.corp.example:4000", To: mustParseWeightedURLs(t, "udp://one.example.com:5000", "udp://two.example.com:5000")}, false},
		{"too many depends_on hosts", Policy{From: "https://httpbin.corp.example", To: mustParseWeightedURLs(t, "https://httpbin.corp.notatld"), DependsOn: []string{"a", "b", "c", "d", "e", "f"}}, true},
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

	var r PolicyRedirect
	p := Policy{
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

func Test_PolicyValidate_DependsOn(t *testing.T) {
	p := Policy{
		From: "https://example.com",
		To:   []WeightedURL{{URL: url.URL{Scheme: "https", Host: "localhost"}}},
	}

	t.Run("normalize", func(t *testing.T) {
		p.DependsOn = []string{
			"https://other-domain-1.localhost",
			"https://other-domain-2.localhost:1234",
			"other-domain-3.localhost",
			"other-domain-4.localhost:1234",
		}
		assert.NoError(t, p.Validate())
		assert.Equal(t, []string{
			"other-domain-1.localhost",
			"other-domain-2.localhost:1234",
			"other-domain-3.localhost",
			"other-domain-4.localhost:1234",
		}, p.DependsOn)
	})
	t.Run("invalid", func(t *testing.T) {
		p.DependsOn = []string{
			"domain.localhost/with/path",
		}
		assert.ErrorContains(t, p.Validate(), "unsupported depends_on value")
	})
}

func TestPolicy_String(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		From     string
		To       []WeightedURL
		want     string
		wantFrom string
	}{
		{"good", "https://pomerium.io", []WeightedURL{{URL: url.URL{Scheme: "https", Host: "localhost"}}}, "https://pomerium.io → https://localhost", `"https://pomerium.io"`},
		{"invalid", "https://pomerium.io", nil, "https://pomerium.io → ?", `"https://pomerium.io"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Policy{
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
		basePolicy    *Policy
		comparePolicy *Policy
		wantSame      bool
	}{
		{
			"same",
			&Policy{From: "https://pomerium.io", To: mustParseWeightedURLs(t, "http://localhost"), AllowedUsers: []string{"foo@bar.com"}},
			&Policy{From: "https://pomerium.io", To: mustParseWeightedURLs(t, "http://localhost")},
			true,
		},
		{
			"different from",
			&Policy{From: "https://pomerium.io", To: mustParseWeightedURLs(t, "http://localhost")},
			&Policy{From: "https://notpomerium.io", To: mustParseWeightedURLs(t, "http://localhost")},
			false,
		},
		{
			"different path",
			&Policy{From: "https://pomerium.io", To: mustParseWeightedURLs(t, "http://localhost")},
			&Policy{From: "https://pomerium.io", To: mustParseWeightedURLs(t, "http://localhost"), Path: "/foo"},
			false,
		},
	}

	for _, tt := range tests {
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
	p := &Policy{From: "https://pomerium.io", To: mustParseWeightedURLs(t, "http://localhost"), AllowedUsers: []string{"foo@bar.com"}}
	oldChecksum := p.Checksum()
	p.AllowedUsers = []string{"foo@pomerium.io"}
	newChecksum := p.Checksum()

	if newChecksum == oldChecksum {
		t.Errorf("Checksum() failed to update old = %d, new = %d", oldChecksum, newChecksum)
	}

	if newChecksum == 0 || oldChecksum == 0 {
		t.Error("Checksum() not returning data")
	}

	if p.Checksum() != newChecksum {
		t.Error("Checksum() inconsistent")
	}
}

func TestNewPolicyFromProto(t *testing.T) {
	t.Parallel()

	p, err := NewPolicyFromProto(&config.Route{
		To: []string{"http://127.0.0.1:1234,1", "http://127.0.0.1:1234,2"},
	})
	assert.NoError(t, err)
	assert.Equal(t, mustParseWeightedURLs(t, "http://127.0.0.1:1234,1", "http://127.0.0.1:1234,2"), p.To)

	p, err = NewPolicyFromProto(&config.Route{
		To:                   []string{"http://127.0.0.1:1234,1", "http://127.0.0.1:1234,2"},
		LoadBalancingWeights: []uint32{3, 4},
	})
	assert.NoError(t, err)
	assert.Equal(t, mustParseWeightedURLs(t, "http://127.0.0.1:1234,3", "http://127.0.0.1:1234,4"), p.To)
}

func TestPolicy_FromToPb(t *testing.T) {
	t.Parallel()

	t.Run("normal", func(t *testing.T) {
		p := &Policy{
			Name:         "ROUTE_NAME",
			Description:  "DESCRIPTION",
			LogoURL:      "LOGO_URL",
			From:         "https://pomerium.io",
			To:           mustParseWeightedURLs(t, "http://localhost"),
			AllowedUsers: []string{"foo@bar.com"},
			SubPolicies: []SubPolicy{
				{
					ID:   "sub_policy_id",
					Name: "sub_policy",
					Rego: []string{"deny = true"},
				},
			},
			EnableGoogleCloudServerlessAuthentication: true,
		}
		pbPolicy, err := p.ToProto()
		require.NoError(t, err)

		policyFromPb, err := NewPolicyFromProto(pbPolicy)
		assert.NoError(t, err)
		assert.Equal(t, p.Name, policyFromPb.Name)
		assert.Equal(t, p.Description, policyFromPb.Description)
		assert.Equal(t, p.LogoURL, policyFromPb.LogoURL)
		assert.Equal(t, p.From, policyFromPb.From)
		assert.Equal(t, p.To, policyFromPb.To)
		assert.Equal(t, p.AllowedUsers, policyFromPb.AllowedUsers)
	})

	t.Run("envoy cluster name", func(t *testing.T) {
		p := &Policy{
			From:         "https://pomerium.io",
			To:           mustParseWeightedURLs(t, "http://localhost"),
			AllowedUsers: []string{"foo@bar.com"},
		}

		pbPolicy, err := p.ToProto()
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

			policyFromPb, err := NewPolicyFromProto(pbPolicy)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedPolicyName, policyFromPb.EnvoyOpts.Name)
		}
	})

	t.Run("redirect route", func(t *testing.T) {
		p := &Policy{
			From: "https://pomerium.io",
			Redirect: &PolicyRedirect{
				HTTPSRedirect: proto.Bool(true),
			},
		}

		pbPolicy, err := p.ToProto()
		require.NoError(t, err)

		policyFromProto, err := NewPolicyFromProto(pbPolicy)
		assert.NoError(t, err)
		assert.Equal(t, p.Redirect.HTTPSRedirect, policyFromProto.Redirect.HTTPSRedirect)
	})

	t.Run("JWT issuer format", func(t *testing.T) {
		for f := range knownJWTIssuerFormats {
			p := &Policy{
				From:            "https://pomerium.io",
				To:              mustParseWeightedURLs(t, "http://localhost"),
				JWTIssuerFormat: f,
			}
			pbPolicy, err := p.ToProto()
			require.NoError(t, err)

			policyFromPb, err := NewPolicyFromProto(pbPolicy)
			assert.NoError(t, err)
			assert.Equal(t, f, policyFromPb.JWTIssuerFormat)
		}
	})
}

func TestPolicy_Matches(t *testing.T) {
	t.Run("full", func(t *testing.T) {
		p := &Policy{
			From:  "https://www.example.com",
			To:    mustParseWeightedURLs(t, "https://localhost"),
			Regex: `/foo`,
		}
		assert.NoError(t, p.Validate())

		assert.False(t, p.Matches(urlutil.MustParseAndValidateURL(`https://www.example.com/foo/bar`), true),
			"regex should only match full string")
	})
	t.Run("issue2952", func(t *testing.T) {
		p := &Policy{
			From:  "https://www.example.com",
			To:    mustParseWeightedURLs(t, "https://localhost"),
			Regex: `^\/foo\/bar\/[0-9a-f]\/{0,1}$`,
		}
		assert.NoError(t, p.Validate())

		assert.True(t, p.Matches(urlutil.MustParseAndValidateURL(`https://www.example.com/foo/bar/0`), true))
	})
	t.Run("issue2592-test2", func(t *testing.T) {
		p := &Policy{
			From:  "https://www.example.com",
			To:    mustParseWeightedURLs(t, "https://localhost"),
			Regex: `/admin/.*`,
		}
		assert.NoError(t, p.Validate())

		assert.True(t, p.Matches(urlutil.MustParseAndValidateURL(`https://www.example.com/admin/foo`), true))
		assert.True(t, p.Matches(urlutil.MustParseAndValidateURL(`https://www.example.com/admin/bar`), true))
	})
	t.Run("tcp", func(t *testing.T) {
		p := &Policy{
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
		policies []Policy
		wantIDs  []string
	}{
		{
			name: "regexPriorityOrder DESC NULLS LAST",
			policies: []Policy{
				{From: "a", Path: "/a", RegexPriorityOrder: nil, ID: "3"},
				{From: "a", Path: "/a", RegexPriorityOrder: ptr(2), ID: "2"},
				{From: "a", Path: "/a", RegexPriorityOrder: ptr(1), ID: "1"},
			},
			wantIDs: []string{"2", "1", "3"},
		},
		{
			name: "from ASC",
			policies: []Policy{
				{From: "", Path: "", RegexPriorityOrder: nil, ID: "B"},
				{From: "", Path: "", RegexPriorityOrder: ptr(0), ID: "C"},
				{From: "source", Path: "/a", RegexPriorityOrder: ptr(1), ID: "A"},
			},
			wantIDs: []string{"C", "B", "A"},
		},
		{
			name: "id ASC",
			policies: []Policy{
				{From: "source", Path: "/a", RegexPriorityOrder: ptr(1), Regex: "regex", Prefix: "prefix", ID: "2"},
				{From: "source", Path: "/a", RegexPriorityOrder: ptr(1), Regex: "regex", Prefix: "prefix", ID: "1"},
			},
			wantIDs: []string{"1", "2"},
		},
		{
			name: "path DESC",
			policies: []Policy{
				{From: "source", Path: "/b", RegexPriorityOrder: ptr(1), ID: "3"},
				{From: "source", Path: "/a", RegexPriorityOrder: nil, ID: "2"},
				{From: "source", Path: "/a", RegexPriorityOrder: ptr(2), ID: "1"},
			},
			wantIDs: []string{"3", "1", "2"},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			SortPolicies(tt.policies)

			gotIDs := make([]string, 0, len(tt.policies))
			for _, entity := range tt.policies {
				gotIDs = append(gotIDs, entity.ID)
			}

			assert.Equal(t, tt.wantIDs, gotIDs)
		})
	}
}

func TestPolicy_IsTCP(t *testing.T) {
	p1 := Policy{From: "https://example.com"}
	assert.False(t, p1.IsTCP())

	p2 := Policy{From: "tcp+https://example.com"}
	assert.True(t, p2.IsTCP())
}

func TestPolicy_IsTCPUpstream(t *testing.T) {
	p1 := Policy{
		From: "tcp+https://example.com:1234",
		To:   mustParseWeightedURLs(t, "https://one.example.com", "https://two.example.com"),
	}
	assert.False(t, p1.IsTCPUpstream())

	p2 := Policy{
		From: "tcp+https://example.com:1234",
		To:   mustParseWeightedURLs(t, "tcp://one.example.com:4000", "tcp://two.example.com:4000"),
	}
	assert.True(t, p2.IsTCPUpstream())

	p3 := Policy{
		From: "tcp+https://example.com:1234",
	}
	assert.False(t, p3.IsTCPUpstream())
}

func TestPolicy_IsSSH(t *testing.T) {
	p1 := Policy{From: "https://example.com"}
	assert.False(t, p1.IsSSH())

	p2 := Policy{From: "ssh://example.com"}
	assert.True(t, p2.IsSSH())
}

func mustParseWeightedURLs(t testing.TB, urls ...string) WeightedURLs {
	wu, err := ParseWeightedUrls(urls...)
	require.NoError(t, err)
	return wu
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
	baseFieldMutators := []func(p *Policy){
		func(p *Policy) { p.From = randomString() },
		func(p *Policy) { p.Prefix = randomString() },
		func(p *Policy) { p.Path = randomString() },
		func(p *Policy) { p.Regex = randomString() },
	}
	toMutators := func(p *Policy) {
		p.To = make(WeightedURLs, mathrand.N(9)+1)
		for i := 0; i < len(p.To); i++ {
			p.To[i] = WeightedURL{URL: *randomURL(), LbWeight: mathrand.Uint32()}
		}
	}
	redirectMutators := []func(p *PolicyRedirect){
		func(p *PolicyRedirect) { p.HTTPSRedirect = randomPtr(10, randomBool()) },
		func(p *PolicyRedirect) { p.SchemeRedirect = randomPtr(10, randomString()) },
		func(p *PolicyRedirect) { p.HostRedirect = randomPtr(10, randomString()) },
		func(p *PolicyRedirect) { p.PortRedirect = randomPtr(10, mathrand.Uint32()) },
		func(p *PolicyRedirect) { p.PathRedirect = randomPtr(10, randomString()) },
		func(p *PolicyRedirect) { p.PrefixRewrite = randomPtr(10, randomString()) },
		func(p *PolicyRedirect) { p.ResponseCode = randomPtr(10, mathrand.Int32()) },
		func(p *PolicyRedirect) { p.StripQuery = randomPtr(10, randomBool()) },
	}
	responseMutators := []func(p *DirectResponse){
		func(p *DirectResponse) { p.Status = mathrand.Int() },
		func(p *DirectResponse) { p.Body = randomString() },
	}

	t.Run("random policies", func(t *testing.T) {
		hashes := make(map[string]struct{}, 10000)
		for i := 0; i < 10000; i++ {
			p := Policy{}
			for _, m := range baseFieldMutators {
				m(&p)
			}
			switch mathrand.IntN(3) {
			case 0:
				toMutators(&p)
			case 1:
				p.Redirect = &PolicyRedirect{}
				for _, m := range redirectMutators {
					m(p.Redirect)
				}
			case 2:
				p.Response = &DirectResponse{}
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
		hashes := make(map[string]Policy, 5000)

		p := Policy{}

		checkAdd := func(p *Policy) {
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
		p.Redirect = &PolicyRedirect{}
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
		p.Response = &DirectResponse{}
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
			a, b *Policy
		}{
			{
				&Policy{From: "foo", Prefix: "bar"},
				&Policy{From: "f", Prefix: "oobar"},
			},
			{
				&Policy{From: "foo", Prefix: "bar"},
				&Policy{From: "foobar", Prefix: ""},
			},
			{
				&Policy{From: "foobar", Prefix: ""},
				&Policy{From: "", Prefix: "foobar"},
			},
			{
				&Policy{From: "foo", Prefix: "", Path: "bar"},
				&Policy{From: "foo", Prefix: "bar", Path: ""},
			},
			{
				&Policy{From: "", Prefix: "foo", Path: "bar"},
				&Policy{From: "foo", Prefix: "bar", Path: ""},
			},
			{
				&Policy{From: "", Prefix: "foo", Path: "bar"},
				&Policy{From: "foo", Prefix: "", Path: "bar"},
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

func TestMCPServerPath(t *testing.T) {
	t.Parallel()
	t.Run("default path", func(t *testing.T) {
		t.Parallel()
		server := &config.MCPServer{}
		require.Equal(t, "/", server.GetPath())
	})

	t.Run("custom path", func(t *testing.T) {
		t.Parallel()
		customPath := "/api/v1"
		server := &config.MCPServer{Path: &customPath}
		require.Equal(t, "/api/v1", server.GetPath())
	})

	t.Run("nil pointer safety", func(t *testing.T) {
		t.Parallel()
		var nilServer *config.MCPServer
		require.Equal(t, "/", nilServer.GetPath())
	})

	t.Run("nil parent safety", func(t *testing.T) {
		t.Parallel()
		var nilMCP *config.MCP
		require.Equal(t, "/", nilMCP.GetServer().GetPath())
	})
}
