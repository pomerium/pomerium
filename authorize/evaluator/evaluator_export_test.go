package evaluator

import (
	"maps"
)

func (c *EvaluatorCache) XClone() *EvaluatorCache {
	c.evalsMu.Lock()
	defer c.evalsMu.Unlock()
	return &EvaluatorCache{
		evaluatorsByRouteID: maps.Clone(c.evaluatorsByRouteID),
	}
}

func (e *Evaluator) XEvaluatorCache() *EvaluatorCache {
	return e.evalCache
}

func (e *Evaluator) XQueryCache() *QueryCache {
	return e.queryCache
}

var (
	XGetGoogleCloudServerlessTokenSource = getGoogleCloudServerlessTokenSource
	XIsValidClientCertificate            = isValidClientCertificate
	XNormalizeServiceAccount             = normalizeServiceAccount
	XWorkerPoolSize                      = workerPoolSize
)
