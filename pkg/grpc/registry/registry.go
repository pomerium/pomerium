package registry

//go:generate go tool go.uber.org/mock/mockgen -source=registry_grpc.pb.go -destination ./mock_registry/registry.pb.go RegistryClient
