package registry

//go:generate go tool -modfile ../../../internal/tools/go.mod go.uber.org/mock/mockgen -source=registry_grpc.pb.go -destination ./mock_registry/registry.pb.go RegistryClient
