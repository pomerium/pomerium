package cluster

//go:generate go tool -modfile ../../../internal/tools/go.mod github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen --config=models.yaml openapi.yaml
//go:generate go tool -modfile ../../../internal/tools/go.mod github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen --config=server.yaml openapi.yaml
//go:generate go tool -modfile ../../../internal/tools/go.mod github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen --config=client.yaml openapi.yaml
