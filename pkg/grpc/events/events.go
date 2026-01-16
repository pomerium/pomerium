package events

import (
	_ "embed"

	gendoc "github.com/pseudomuto/protoc-gen-doc"

	"github.com/pomerium/pomerium/internal/jsonutil"
)

//go:embed events.pb.json
var RawDocs []byte

var Docs = jsonutil.MustParse[gendoc.Template](RawDocs)
