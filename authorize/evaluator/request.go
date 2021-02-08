package evaluator

type (
	// Request is the request data used for the evaluator.
	Request struct {
		HTTP           RequestHTTP    `json:"http"`
		Session        RequestSession `json:"session"`
		CustomPolicies []string
		ClientCA       string // pem-encoded certificate authority
	}

	// RequestHTTP is the HTTP field in the request.
	RequestHTTP struct {
		Method            string            `json:"method"`
		URL               string            `json:"url"`
		Headers           map[string]string `json:"headers"`
		ClientCertificate string            `json:"client_certificate"`
	}

	// RequestSession is the session field in the request.
	RequestSession struct {
		ID string `json:"id"`
	}
)
