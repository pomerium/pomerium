package evaluator

import (
	"maps"
)

func (c *PolicyEvaluatorCache) XClone() *PolicyEvaluatorCache {
	c.evalsMu.Lock()
	defer c.evalsMu.Unlock()
	return &PolicyEvaluatorCache{
		evaluatorsByRouteID: maps.Clone(c.evaluatorsByRouteID),
	}
}

func (e *Evaluator) XEvaluatorCache() *PolicyEvaluatorCache {
	return e.evalCache
}

func (e *Evaluator) XQueryCache() *QueryCache {
	return e.queryCache
}

var (
	XGetGoogleCloudServerlessTokenSource = getGoogleCloudServerlessTokenSource
	XIsValidClientCertificate            = isValidClientCertificate
	XNormalizeServiceAccount             = normalizeServiceAccount
	XBestChunkSize                       = bestChunkSize
	XGetUserPrincipalNamesFromSAN        = getUserPrincipalNamesFromSAN
)

var OIDUserPrincipalName = oidUserPrincipalName

func XWorkerPoolSize() int {
	return workerPoolSize
}

func OverrideWorkerPoolSizeForTesting(newSize int) {
	if newSize == workerPoolSize {
		return
	}
	workerPoolMu.Lock()
	workerPoolSize = newSize
	close(workerPoolTaskQueue) // this will stop existing workers
	workerPoolTaskQueue = make(chan func(), (workerPoolSize+1)*2)
	workerPoolMu.Unlock()
	for i := 0; i < workerPoolSize; i++ {
		go worker()
	}
}
