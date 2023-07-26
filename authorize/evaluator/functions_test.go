package evaluator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	testCA = `
-----BEGIN CERTIFICATE-----
MIIEtjCCAx6gAwIBAgIRAJFkXxMjoQzoojykk6CiiGkwDQYJKoZIhvcNAQELBQAw
czEeMBwGA1UEChMVbWtjZXJ0IGRldmVsb3BtZW50IENBMSQwIgYDVQQLDBtjYWxl
YkBwb3Atb3MgKENhbGViIERveHNleSkxKzApBgNVBAMMIm1rY2VydCBjYWxlYkBw
b3Atb3MgKENhbGViIERveHNleSkwHhcNMjAwNDI0MTY1MzEwWhcNMzAwNDI0MTY1
MzEwWjBzMR4wHAYDVQQKExVta2NlcnQgZGV2ZWxvcG1lbnQgQ0ExJDAiBgNVBAsM
G2NhbGViQHBvcC1vcyAoQ2FsZWIgRG94c2V5KTErMCkGA1UEAwwibWtjZXJ0IGNh
bGViQHBvcC1vcyAoQ2FsZWIgRG94c2V5KTCCAaIwDQYJKoZIhvcNAQEBBQADggGP
ADCCAYoCggGBAL2QSyQGjaGD97K7HSExJfMcuyEoh+ewAkPZ/HZR4n12zwAn1sLK
RqusKSfMe8qG6KgsojXrJ9AXEkD7x3bmK5j/4M/lwlNGulg+k5MSu3leoLpOZwfX
JQTu+HDzWubu5cjy7taHyeZc35VbOBWEaDJgVxmJvE9TJIOr8POZ7DD/rlkbgQas
s6G/8cg2mRX0Rh3O20/1bvi9Uen/kraBgGMOyG5MfuiiTl3KsrGST848Q+jiSbu3
5F5MAzdO4tlR6kqEZk/Igog6OPkTb82vMli/R+mR37JYncQcj0WNYS4PkfjofVpb
FwrHtfdkVYJ9T2yNvQnJVu6MF9fhj9FqWQbsdbYKlUDow5KwI+BxmCAmGwgzmCOy
ONkglj76fPKFkoF4s+DSFocbAwhdazaViAcCB+x6yohOUjgG7H9NJo0MasPHuqUO
8d56Bf0BTXfNX6nOgYYisrOoEATCbs729vHMaQ/7pG2zf9dnEuw95gZTSr9Rv3dx
2NjmM6+tNOMCzwIDAQABo0UwQzAOBgNVHQ8BAf8EBAMCAgQwEgYDVR0TAQH/BAgw
BgEB/wIBADAdBgNVHQ4EFgQUShofXNkcXh2q4wnnWZ2bco24XEQwDQYJKoZIhvcN
AQELBQADggGBAJQzfmr84xtvoUgnq8T4ND0Q166dlnbDnASRFhbmyZcxzvDJsPs4
N45HbIg0xOsXOaBaE+jTSV4GmZ/vtyP8WbQrhabL2zpnjnLF1d9B0qx/RlIzoDEa
e/0zc0R6RAd64/aE/jHNDhfTNXD/NmnI25RqgnsZXXXRVMTl+PzQ1A8XQghZVWHN
vbyFFd3GE5Qs+vxMzwKCqp6f3MI8KyI2aM4hZZ+zULdEuSw0hWzMOkeZY6LC0flW
/rpkT+GLA3uZ357iehSISLqnkIozw92ldov5oZDthoy3i1I6gIDkngk7BGKr42pD
L2sWi1MEEIhymy4K1DnRkGre3mqzus2y/nE4ruuJlctq6QXcCSnko717vukVtoE8
o5SkW4usivU8yZeBLt56sySRyCpe/T1XAFTQZ5Q4S5ssGmNpOLS9Aa5iOUz9/62S
uvjFyvOEE3yqd/d3py8qm6olcjaMooVA8j5G+QF/UiH951azGIez6/Ui1lg1m0T6
+YLkPqNIt0o9dQ==
-----END CERTIFICATE-----
`
	testValidCert = `
-----BEGIN CERTIFICATE-----
MIIESDCCArCgAwIBAgIQG/h9GflpINqLLv4Tde9+STANBgkqhkiG9w0BAQsFADBz
MR4wHAYDVQQKExVta2NlcnQgZGV2ZWxvcG1lbnQgQ0ExJDAiBgNVBAsMG2NhbGVi
QHBvcC1vcyAoQ2FsZWIgRG94c2V5KTErMCkGA1UEAwwibWtjZXJ0IGNhbGViQHBv
cC1vcyAoQ2FsZWIgRG94c2V5KTAeFw0xOTA2MDEwMDAwMDBaFw0zMDA1MjAyMDM4
NDRaME8xJzAlBgNVBAoTHm1rY2VydCBkZXZlbG9wbWVudCBjZXJ0aWZpY2F0ZTEk
MCIGA1UECwwbY2FsZWJAcG9wLW9zIChDYWxlYiBEb3hzZXkpMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5ouz2dlXHALdxiLcLwAvxg02CN/Jdcrmyyzm
bzKHqIpknotZSlbPgE/mp5wMwIoyMqFIEm3IzXFEf3cjFYYG4b6wp4zlFrx7jCOa
vhEHpH3yM71xt1I/BME6VrmX7sRKO90dwpTxCOadx9aGEn1AlHuPfhMMm/WTLynD
d5hbsHKp7eZMYHvQnferTelq5NnBySBP/HaAtF76qTSQzHev5K/cgioDZAaM0dnP
bicl0Zay+f5INrDr9XtQo/FHwGI/YLMW5TWXYmHjYmdD8s4Tg/KUoRMgJp4mlkkF
9t1pwArbNFU/4wQWPbpWBLh1gcnQxojSZ3a6aI+V+REDzV/PVQIDAQABo3wwejAO
BgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMAwG
A1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUShofXNkcXh2q4wnnWZ2bco24XEQwGgYD
VR0RBBMwEYIPZXhhbXBsZS1zdWJqZWN0MA0GCSqGSIb3DQEBCwUAA4IBgQC78S2n
6jcKfWbm24g/U5tkWiBVnBk1jphH7Ct69Lw2JNstGLtNs4AiE9lKmXDQ82MiAFYg
gaeiHRhTebkOTF9Kx3Jwq7bwhhzONqPp5a0SkY4EWjZ7c5k/fZc8DkrRE71hOgMf
rFbRBZCywBVtGbXIA1uMsCijTe4sQF1ZA918NmfjhpIhRHljQJM16RJ753s+0CZ8
WomOW4JrtjJefRuV97PRADvRNQbtZYelnoTfbp1afGhbQpKjyylCDGlpJS4mGrSA
lPaRVhEB+wI8gA3lzpa6adXsc1yueZ19++dxQNYxAawCMQNjjxy3aLWzy8aPWxxq
Qo/Q9rqjre3SpJfARLOV9ezQNbqsXvJW+5DcoG5dx8s6jAhMusNjUHpf6oVgnv65
3Bvl124bZyf9q4lW9g8pvZkrgQ3Fx2IahqhXhyF5zrqf2r9+1l0fXocIUP2GQ+Fr
b9j9bWWhov5aidEjPwpFeTmzcGqCWQBEA4H+yo/4YaIN0sOfE2yaAmc3gcU=
-----END CERTIFICATE-----
`
	testUnsignedCert = `
-----BEGIN CERTIFICATE-----
MIIESTCCArGgAwIBAgIRAIE9860UHBIVofXB5cu/aWAwDQYJKoZIhvcNAQELBQAw
czEeMBwGA1UEChMVbWtjZXJ0IGRldmVsb3BtZW50IENBMSQwIgYDVQQLDBtjYWxl
YkBwb3Atb3MgKENhbGViIERveHNleSkxKzApBgNVBAMMIm1rY2VydCBjYWxlYkBw
b3Atb3MgKENhbGViIERveHNleSkwHhcNMTkwNjAxMDAwMDAwWhcNMzAwNTIwMjIw
NDAxWjBPMScwJQYDVQQKEx5ta2NlcnQgZGV2ZWxvcG1lbnQgY2VydGlmaWNhdGUx
JDAiBgNVBAsMG2NhbGViQHBvcC1vcyAoQ2FsZWIgRG94c2V5KTCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAKPgWHAJ58p7ZZ6MHA6QHA9rQQWKSvYbN9zz
fCCURqHFbQHCCJs2D39XPioo9EMZcD6J7ldwEOJsdSNw3+dzBCvIl7wP6fqtbo/3
SNgRaLAB+Mb4S8oek6P6zHkjuOXzodhCZjLO7oxY9pjGREy6hC/SjylJFgw9mKEG
SYmsyCqeP5BfW9DghRgd5uJe0HtwlBZLPS91Mk5whn7YOxnWslS/REwZdd12s3DI
WQdmvGhMakIAiMKmx+LX9qS3Ua2gUArHnSFXcOAg9iK+MM68T1KsQTCYnRZVK4v5
Na4qEjiPhmkzzEExZa787ClL6UXfoXB+jXy2sXu0CDD4tv2D7R8CAwEAAaN8MHow
DgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAM
BgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFH8wenPOF2tE2EIksItmlkWfgEMkMBoG
A1UdEQQTMBGCD2ludmFsaWQtc3ViamVjdDANBgkqhkiG9w0BAQsFAAOCAYEAJCdl
c6J/x/UY6vEDzplwR8iZ5s7dyKKF7bwNdjEvBREgkTY6GmwDC9HOmWWPs7vENqEX
jUwHEK+v7A7AUIS4WeJrJgogzEDPI7ZlVtzQNviqMavzk/I1Us00WYtMQQFb1Sgz
xIRskug5wH6vPcR4XbCftx6NP9UFG8pJLPTJ67ZUaTP23ccsToMM/Dd17LFrtleE
9xAvdqA54vcBiJ99uts+xWlQznjIgdauNC6sOmL3JAflyj6aBy+Dcos9R35ERIXz
3rRl25yXjtidPDo8YxmtHs+Ijw4R3iJ44NCcc/+LfACYUcua0cBF2Ixk2JrFYx8n
wwRJukrHXI+RFBmSOlUripyyJH92H5vXvj8lO5wM8wVVVe8anr5TOvxFOAjNC5a3
vJByvJQTUEkx8rT7zZi8eSQJHP3Eoqr9g4ajqIU22yrCxiiQXpZLJ4JFQQEgyD9A
Y+E5W+FKfIBv9yvdNBYZsL6IZ0Yh1ctKwB5gnajO8+swx5BeaCIbBrCtOBSB
-----END CERTIFICATE-----
`
)

func Test_isValidClientCertificate(t *testing.T) {
	t.Run("no ca", func(t *testing.T) {
		valid, err := isValidClientCertificate("", ClientCertificateInfo{Leaf: "WHATEVER!"})
		assert.NoError(t, err, "should not return an error")
		assert.True(t, valid, "should return true")
	})
	t.Run("no cert", func(t *testing.T) {
		valid, err := isValidClientCertificate(testCA, ClientCertificateInfo{})
		assert.NoError(t, err, "should not return an error")
		assert.False(t, valid, "should return false")
	})
	t.Run("valid cert", func(t *testing.T) {
		valid, err := isValidClientCertificate(testCA, ClientCertificateInfo{
			Presented: true,
			Validated: true,
			Leaf:      testValidCert,
		})
		assert.NoError(t, err, "should not return an error")
		assert.True(t, valid, "should return true")
	})
	t.Run("cert not externally validated", func(t *testing.T) {
		valid, err := isValidClientCertificate(testCA, ClientCertificateInfo{
			Presented: true,
			Validated: false,
			Leaf:      testValidCert,
		})
		assert.NoError(t, err, "should not return an error")
		assert.False(t, valid, "should return false")
	})
	t.Run("unsigned cert", func(t *testing.T) {
		valid, err := isValidClientCertificate(testCA, ClientCertificateInfo{
			Presented: true,
			Validated: true,
			Leaf:      testUnsignedCert,
		})
		assert.NoError(t, err, "should not return an error")
		assert.False(t, valid, "should return false")
	})
	t.Run("not a cert", func(t *testing.T) {
		valid, err := isValidClientCertificate(testCA, ClientCertificateInfo{
			Presented: true,
			Validated: true,
			Leaf:      "WHATEVER!",
		})
		assert.Error(t, err, "should return an error")
		assert.False(t, valid, "should return false")
	})
}
