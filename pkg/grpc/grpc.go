package grpc

//go:generate ./protoc.bash

const roundRobinServiceConfig = `{
  "loadBalancingConfig": [
    {
      "round_robin": {}
    }
  ]
}`
