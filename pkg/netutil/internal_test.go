package netutil_test

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"testing"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/pomerium/pomerium/pkg/netutil"
)

func TestInternalAddress(t *testing.T) {
	t.Parallel()

	endToEnd := func(t *testing.T, addr *netutil.InternalAddress) {
		li, err := addr.Listen(t.Context())
		require.NoError(t, err)
		defer li.Close()

		eg, ctx := errgroup.WithContext(t.Context())
		eg.Go(func() error {
			conn, err := li.Accept()
			if err != nil {
				return fmt.Errorf("error accepting connection: %w", err)
			}
			defer conn.Close()

			var buf [4]byte
			_, err = conn.Read(buf[:])
			if err != nil {
				return fmt.Errorf("error reading data: %w", err)
			}

			_, err = conn.Write(buf[:])
			if err != nil {
				return fmt.Errorf("error writing data back: %w", err)
			}

			return nil
		})
		eg.Go(func() error {
			conn, err := addr.Dial(ctx)
			if err != nil {
				return fmt.Errorf("error dialing: %w", err)
			}
			defer conn.Close()

			buf := []byte{0x01, 0x02, 0x03, 0x04}
			_, err = conn.Write(buf)
			if err != nil {
				return fmt.Errorf("error writing data: %w", err)
			}

			_, err = conn.Read(buf)
			if err != nil {
				return fmt.Errorf("error reading data back: %w", err)
			}

			return nil
		})
		require.NoError(t, eg.Wait())
	}

	t.Run("tcp", func(t *testing.T) {
		t.Parallel()
		ports, err := netutil.AllocatePorts(1)
		require.NoError(t, err)
		name := fmt.Sprintf("127.0.0.1:%s", ports[0])
		addrPort := netip.MustParseAddrPort(name)
		addr := netutil.NewInternalAddressForTCP(addrPort)
		assert.Equal(t, "tcp://"+name, addr.String())
		assert.Empty(t, cmp.Diff(
			&envoy_config_core_v3.Address{
				Address: &envoy_config_core_v3.Address_SocketAddress{
					SocketAddress: &envoy_config_core_v3.SocketAddress{
						Protocol: *envoy_config_core_v3.SocketAddress_TCP.Enum(),
						Address:  addrPort.Addr().String(),
						PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
							PortValue: uint32(addrPort.Port()),
						},
					},
				},
			},
			addr.EnvoyAddress(),
			protocmp.Transform(),
		))
		endToEnd(t, addr)
	})
	t.Run("unix", func(t *testing.T) {
		t.Parallel()
		name := filepath.Join("/", "tmp", uuid.NewString())
		addr := netutil.NewInternalAddressForUnixSocket(name)
		assert.Equal(t, "unix:"+name, addr.String())
		assert.Empty(t, cmp.Diff(
			&envoy_config_core_v3.Address{
				Address: &envoy_config_core_v3.Address_Pipe{
					Pipe: &envoy_config_core_v3.Pipe{
						Path: name,
						Mode: 0o0600,
					},
				},
			},
			addr.EnvoyAddress(),
			protocmp.Transform(),
		))
		endToEnd(t, addr)
	})
	t.Run("unix-abstract", func(t *testing.T) {
		t.Parallel()
		name := uuid.NewString()
		addr := netutil.NewInternalAddressForUnixSocket("@" + name)
		assert.Equal(t, "unix-abstract:"+name, addr.String())
		assert.Empty(t, cmp.Diff(
			&envoy_config_core_v3.Address{
				Address: &envoy_config_core_v3.Address_Pipe{
					Pipe: &envoy_config_core_v3.Pipe{
						Path: "@" + name,
					},
				},
			},
			addr.EnvoyAddress(),
			protocmp.Transform(),
		))
		endToEnd(t, addr)
	})
}
