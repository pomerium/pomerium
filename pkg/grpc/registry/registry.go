package registry

import (
	_ "embed"

	gendoc "github.com/pseudomuto/protoc-gen-doc"

	"github.com/pomerium/pomerium/internal/jsonutil"
)

//go:embed registry.pb.json
var RawDocs []byte

var Docs = jsonutil.MustParse[gendoc.Template](RawDocs)

//go:generate go tool -modfile ../../../internal/tools/go.mod go.uber.org/mock/mockgen -source=registry_grpc.pb.go -destination ./mock_registry/registry.pb.go RegistryClient
