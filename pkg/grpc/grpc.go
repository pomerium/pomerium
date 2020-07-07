package grpc

//go:generate ../../scripts/protoc -I ./session/ --go_out=plugins=grpc:$GOPATH/src ./session/session.proto
//go:generate ../../scripts/protoc -I ./user/ --go_out=plugins=grpc:$GOPATH/src ./user/user.proto
//go:generate ../../scripts/protoc -I ./databroker/ --go_out=plugins=grpc:$GOPATH/src ./databroker/databroker.proto
//go:generate ../../scripts/protoc -I ./directory/ --go_out=plugins=grpc:$GOPATH/src ./directory/directory.proto
//go:generate ../../scripts/protoc -I ./audit/ --go_out=plugins=grpc:$GOPATH/src ./audit/audit.proto
