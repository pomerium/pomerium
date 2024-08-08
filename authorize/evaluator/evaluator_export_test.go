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
	XBestChunkSize                       = bestChunkSize
)

func XWorkerPoolSize() int {
	return workerPoolSize
}

func OverrideWorkerPoolSizeForTesting(newSize int) {
	if newSize == workerPoolSize {
		return
	}
	workerPoolSize = newSize
	close(workerPoolTaskQueue) // this will stop existing workers
	workerPoolTaskQueue = make(chan func(), (workerPoolSize+1)*2)
	for i := 0; i < workerPoolSize; i++ {
		go worker()
	}
}
