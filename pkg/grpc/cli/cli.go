package cli

import (
	_ "embed"

	gendoc "github.com/pseudomuto/protoc-gen-doc"

	"github.com/pomerium/pomerium/internal/jsonutil"
)

//go:embed cli.pb.json
var RawDocs []byte

var Docs = jsonutil.MustParse[gendoc.Template](RawDocs)
