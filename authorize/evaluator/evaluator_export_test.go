package evaluator

import "maps"

func (c *EvaluatorCache) Clone() *EvaluatorCache {
	c.evalsMu.Lock()
	defer c.evalsMu.Unlock()
	return &EvaluatorCache{
		evaluatorsByRouteID: maps.Clone(c.evaluatorsByRouteID),
	}
}

func (e *Evaluator) Cache() *EvaluatorCache {
	return e.evalCache
}

var (
	GetGoogleCloudServerlessTokenSource = getGoogleCloudServerlessTokenSource
	IsValidClientCertificate            = isValidClientCertificate
	NormalizeServiceAccount             = normalizeServiceAccount
)
