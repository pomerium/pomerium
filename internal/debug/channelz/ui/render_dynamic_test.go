package ui

import (
	"testing"

	"google.golang.org/grpc/channelz/grpc_channelz_v1"
)

func TestRenderAddress(t *testing.T) {
	tests := []struct {
		name     string
		addr     *grpc_channelz_v1.Address
		expected string
	}{
		{
			name:     "nil address",
			addr:     nil,
			expected: "-",
		},
		{
			name: "IPv4 address",
			addr: &grpc_channelz_v1.Address{
				Address: &grpc_channelz_v1.Address_TcpipAddress{
					TcpipAddress: &grpc_channelz_v1.Address_TcpIpAddress{
						IpAddress: []byte{127, 0, 0, 1},
						Port:      8080,
					},
				},
			},
			expected: "127.0.0.1:8080",
		},
		{
			name: "IPv6 address",
			addr: &grpc_channelz_v1.Address{
				Address: &grpc_channelz_v1.Address_TcpipAddress{
					TcpipAddress: &grpc_channelz_v1.Address_TcpIpAddress{
						IpAddress: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
						Port:      443,
					},
				},
			},
			expected: "[::1]:443",
		},
		{
			name: "nil TcpipAddress inner",
			addr: &grpc_channelz_v1.Address{
				Address: &grpc_channelz_v1.Address_TcpipAddress{
					TcpipAddress: nil,
				},
			},
			expected: "-",
		},
		{
			name: "Unix domain socket",
			addr: &grpc_channelz_v1.Address{
				Address: &grpc_channelz_v1.Address_UdsAddress_{
					UdsAddress: &grpc_channelz_v1.Address_UdsAddress{
						Filename: "/var/run/grpc.sock",
					},
				},
			},
			expected: "unix:///var/run/grpc.sock",
		},
		{
			name: "nil UdsAddress inner",
			addr: &grpc_channelz_v1.Address{
				Address: &grpc_channelz_v1.Address_UdsAddress_{
					UdsAddress: nil,
				},
			},
			expected: "-",
		},
		{
			name: "Other address with name",
			addr: &grpc_channelz_v1.Address{
				Address: &grpc_channelz_v1.Address_OtherAddress_{
					OtherAddress: &grpc_channelz_v1.Address_OtherAddress{
						Name: "custom-transport",
					},
				},
			},
			expected: "custom-transport",
		},
		{
			name: "Other address without name",
			addr: &grpc_channelz_v1.Address{
				Address: &grpc_channelz_v1.Address_OtherAddress_{
					OtherAddress: &grpc_channelz_v1.Address_OtherAddress{
						Name: "",
					},
				},
			},
			expected: "other",
		},
		{
			name: "nil OtherAddress inner",
			addr: &grpc_channelz_v1.Address{
				Address: &grpc_channelz_v1.Address_OtherAddress_{
					OtherAddress: nil,
				},
			},
			expected: "-",
		},
		{
			name: "empty Address oneof",
			addr: &grpc_channelz_v1.Address{
				Address: nil,
			},
			expected: "-",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatAddress(tt.addr)
			if result != tt.expected {
				t.Errorf("renderAddress() = %q, want %q", result, tt.expected)
			}
		})
	}
}
