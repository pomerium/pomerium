package grpc

//go:generate ../../scripts/protoc -I ./session/ --go_out=plugins=grpc,paths=source_relative:./session/. ./session/session.proto
//go:generate ../../scripts/protoc -I ./user/ --go_out=plugins=grpc,paths=source_relative:./user/. ./user/user.proto
//go:generate ../../scripts/protoc -I ./databroker/ --go_out=plugins=grpc,paths=source_relative:./databroker/. ./databroker/databroker.proto
//go:generate ../../scripts/protoc -I ./directory/ --go_out=plugins=grpc,paths=source_relative:./directory/. ./directory/directory.proto
//go:generate ../../scripts/protoc -I ./audit/ --go_out=plugins=grpc,paths=source_relative:./audit/. ./audit/audit.proto
//go:generate ../../scripts/protoc -I ./config/ --go_out=plugins=grpc,paths=source_relative:./config/. ./config/config.proto

const roundRobinServiceConfig = `{
  "loadBalancingConfig": [
    {
      "round_robin": {}
    }
  ]
}`
