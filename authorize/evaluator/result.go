package evaluator

import (
	"fmt"
	"strconv"

	"github.com/open-policy-agent/opa/rego"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
)

// Result is the result of evaluation.
type Result struct {
	Status         int
	Message        string
	Headers        map[string]string
	MatchingPolicy *config.Policy

	DataBrokerServerVersion, DataBrokerRecordVersion uint64
}

func getMatchingPolicy(vars rego.Vars, policies []config.Policy) *config.Policy {
	result, ok := vars["result"].(map[string]interface{})
	if !ok {
		return nil
	}

	idx, err := strconv.Atoi(fmt.Sprint(result["route_policy_idx"]))
	if err != nil {
		return nil
	}

	if idx >= len(policies) {
		return nil
	}

	return &policies[idx]
}

func getAllowVar(vars rego.Vars) bool {
	result, ok := vars["result"].(map[string]interface{})
	if !ok {
		return false
	}

	allow, ok := result["allow"].(bool)
	if !ok {
		return false
	}
	return allow
}

func getDenyVar(vars rego.Vars) []Result {
	result, ok := vars["result"].(map[string]interface{})
	if !ok {
		return nil
	}

	denials, ok := result["deny"].([]interface{})
	if !ok {
		return nil
	}

	results := make([]Result, 0, len(denials))
	for _, denial := range denials {
		denial, ok := denial.([]interface{})
		if !ok || len(denial) != 2 {
			continue
		}

		status, err := strconv.Atoi(fmt.Sprint(denial[0]))
		if err != nil {
			log.Error().Err(err).Msg("invalid type in deny")
			continue
		}
		msg := fmt.Sprint(denial[1])

		results = append(results, Result{
			Status:  status,
			Message: msg,
		})
	}
	return results
}

func getHeadersVar(vars rego.Vars) map[string]string {
	headers := make(map[string]string)

	result, ok := vars["result"].(map[string]interface{})
	if !ok {
		return headers
	}

	m, ok := result["identity_headers"].(map[string]interface{})
	if !ok {
		return headers
	}

	for k, v := range m {
		headers[k] = fmt.Sprint(v)
	}

	return headers
}

func getDataBrokerVersions(vars rego.Vars) (serverVersion, recordVersion uint64) {
	result, ok := vars["result"].(map[string]interface{})
	if !ok {
		return 0, 0
	}
	serverVersion, _ = strconv.ParseUint(fmt.Sprint(result["databroker_server_version"]), 10, 64)
	recordVersion, _ = strconv.ParseUint(fmt.Sprint(result["databroker_record_version"]), 10, 64)
	return serverVersion, recordVersion
}
