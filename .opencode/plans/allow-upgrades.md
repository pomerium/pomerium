# Allow Upgrades Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a new configuration key `allow_upgrades` to Pomerium routes to support custom HTTP upgrade types (e.g., `tailscale-control-protocol`).

**Architecture:** 
1. Add `allow_upgrades` to the `Route` proto message.
2. Map the proto field to the internal `Policy` struct and implement validation.
3. Update the Envoy configuration generator to include the custom upgrades in the `RouteAction` and ensure appropriate timeouts and protocols are used.

**Tech Stack:** Go, Protobuf, Envoy API v3.

---

### Task 1: Update Proto Definition

**Files:**
- Modify: `pkg/grpc/config/config.proto`

**Step 1: Add allow_upgrades field**

Add `repeated string allow_upgrades = 93;` to the `Route` message.

```proto
  // The name of the namespace for the route.
  optional string namespace_name = 92;

  repeated string allow_upgrades = 93;
}
```

**Step 2: Generate Go code**

Run: `make proto`

### Task 2: Update Policy Configuration

**Files:**
- Modify: `config/policy.go`

**Step 1: Update Policy struct**

Add `AllowUpgrades []string` to the `Policy` struct with proper mapstructure and yaml tags.

```go
	// AllowUpgrades enables custom HTTP upgrade types
	AllowUpgrades []string `mapstructure:"allow_upgrades" yaml:"allow_upgrades,omitempty"`
```

**Step 2: Update NewPolicyFromProto**

Map the field from `configpb.Route`.

```go
		AllowUpgrades:                     pb.GetAllowUpgrades(),
```

**Step 3: Update ToProto**

Map the field back to `configpb.Route`.

```go
		AllowUpgrades:                     p.AllowUpgrades,
```

**Step 4: Update Validate**

Add validation to ensure it's not used with direct TCP/UDP.

```go
	if len(p.AllowUpgrades) > 0 && (p.IsTCP() || p.IsUDP()) {
		return fmt.Errorf("config: allow_upgrades cannot be used with tcp or udp routes")
	}
```

### Task 3: Update Envoy Configuration

**Files:**
- Modify: `config/envoyconfig/routes.go`
- Modify: `config/envoyconfig/protocols.go`

**Step 1: Update UpgradeConfigs in routes.go**

Modify `buildPolicyRouteRouteAction` to include custom upgrades.

```go
	for _, upgrade := range policy.AllowUpgrades {
		upgradeConfigs = append(upgradeConfigs, &envoy_config_route_v3.RouteAction_UpgradeConfig{
			UpgradeType: upgrade,
			Enabled:     &wrapperspb.BoolValue{Value: true},
		})
	}
```

**Step 2: Update shouldDisableStreamIdleTimeout in routes.go**

```go
func shouldDisableStreamIdleTimeout(policy *config.Policy) bool {
	return policy.AllowWebsockets ||
		len(policy.AllowUpgrades) > 0 ||
		policy.IsTCP() ||
		policy.IsUDP() ||
		policy.IsForKubernetes()
}
```

**Step 3: Update getUpstreamProtocolForPolicy in protocols.go**

```go
func getUpstreamProtocolForPolicy(_ context.Context, policy *config.Policy) upstreamProtocolConfig {
	upstreamProtocol := upstreamProtocolAuto
	if policy.AllowWebsockets || len(policy.AllowUpgrades) > 0 {
		// #2388, force http/1 when using web sockets or custom upgrades
		log.WarnWebSocketHTTP1_1(GetClusterID(policy))
		upstreamProtocol = upstreamProtocolHTTP1
	}
	return upstreamProtocol
}
```

### Task 4: Verification

**Files:**
- Test: `config/policy_test.go`
- Test: `config/envoyconfig/routes_test.go`
- Test: `config/envoyconfig/protocols_test.go`

**Step 1: Test Policy validation**

Add a test case to `Test_PolicyValidate` in `config/policy_test.go`.

**Step 2: Test Envoy route generation**

Add a test case to `Test_buildPolicyRouteRouteAction` in `config/envoyconfig/routes_test.go` verifying `UpgradeConfigs`.

**Step 3: Test upstream protocol**

Add a test case to `TestBuildUpstreamProtocolOptions` in `config/envoyconfig/protocols_test.go`.
