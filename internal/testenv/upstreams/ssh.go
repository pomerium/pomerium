package upstreams

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/values"
	"golang.org/x/crypto/ssh"
)

type SSHUpstreamOptions struct {
	displayName  string
	serverConfig ssh.ServerConfig
}

type SSHUpstreamOption interface {
	applySSH(*SSHUpstreamOptions)
}

type sshUpstreamOption func(o *SSHUpstreamOptions)

func (s sshUpstreamOption) applySSH(o *SSHUpstreamOptions) { s(o) }

func WithPublicKeyAuthAlgorithms(algs []string) SSHUpstreamOption {
	return sshUpstreamOption(func(o *SSHUpstreamOptions) {
		o.serverConfig.PublicKeyAuthAlgorithms = algs
	})
}

func WithHostKeys(keys ...ssh.Signer) SSHUpstreamOption {
	return sshUpstreamOption(func(o *SSHUpstreamOptions) {
		for _, key := range keys {
			o.serverConfig.AddHostKey(key)
		}
	})
}

func WithBannerCallback(c func(ssh.ConnMetadata) string) SSHUpstreamOption {
	return sshUpstreamOption(func(o *SSHUpstreamOptions) {
		o.serverConfig.BannerCallback = c
	})
}

func WithPublicKeyCallback(c func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error)) SSHUpstreamOption {
	return sshUpstreamOption(func(o *SSHUpstreamOptions) {
		o.serverConfig.PublicKeyCallback = c
	})
}

type ServerConnCallback func(*ssh.ServerConn, <-chan ssh.NewChannel, <-chan *ssh.Request)

var closeConnCallback ServerConnCallback = func(conn *ssh.ServerConn, ncc <-chan ssh.NewChannel, rq <-chan *ssh.Request) {
	conn.Close()
}

// SSHUpstream represents an ssh server which can be used as the target for
// one or more Pomerium routes in a test environment.
//
// Use SetServerConnCallback() to define the behavior of this server once
// a connection is established.
//
// Dial() can be used to make a client-side connection through the Pomerium
// route, while DirectDial() can be used to connect bypassing Pomerium.
type SSHUpstream interface {
	testenv.Upstream

	SetServerConnCallback(callback ServerConnCallback)

	Dial(r testenv.Route, config *ssh.ClientConfig) (*ssh.Client, error)
	DirectDial(r testenv.Route, config *ssh.ClientConfig) (*ssh.Client, error)
}

type sshUpstream struct {
	SSHUpstreamOptions
	testenv.Aggregate
	serverPort values.MutableValue[int]

	// XXX: does it make sense to cache clients?
	//clientCache sync.Map // map[testenv.Route]*ssh.Client

	serverConnCallback ServerConnCallback
}

var (
	_ testenv.Upstream = (*sshUpstream)(nil)
	_ SSHUpstream      = (*sshUpstream)(nil)
)

// SSH creates a new ssh upstream server.
func SSH(opts ...SSHUpstreamOption) SSHUpstream {
	options := SSHUpstreamOptions{
		displayName: "SSH Upstream",
	}
	for _, op := range opts {
		op.applySSH(&options)
	}
	up := &sshUpstream{
		SSHUpstreamOptions: options,
		serverPort:         values.Deferred[int](),
		serverConnCallback: closeConnCallback, // default handler, to avoid hanging connections
	}
	up.RecordCaller()
	return up
}

// Port implements SSHUpstream.
func (h *sshUpstream) Port() values.Value[int] {
	return h.serverPort
}

// Router implements SSHUpstream.
func (h *sshUpstream) SetServerConnCallback(callback ServerConnCallback) {
	h.serverConnCallback = callback
}

// Route implements SSHUpstream.
func (h *sshUpstream) Route() testenv.RouteStub {
	r := &testenv.PolicyRoute{}
	protocol := "ssh"
	r.To(values.Bind(h.serverPort, func(port int) string {
		return fmt.Sprintf("%s://127.0.0.1:%d", protocol, port)
	}))
	h.Add(r)
	return r
}

// Run implements SSHUpstream.
func (h *sshUpstream) Run(ctx context.Context) error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	h.serverPort.Resolve(listener.Addr().(*net.TCPAddr).Port)

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go h.handleConnection(ctx, conn)
	}
}

func (h *sshUpstream) handleConnection(ctx context.Context, conn net.Conn) {
	serverConn, ncc, rc, err := ssh.NewServerConn(conn, &h.serverConfig)
	if err != nil {
		// XXX: figure out the right way to log this
		log.Println("ssh connection handshake unsuccessful:", err)
		return
	}
	go func() {
		<-ctx.Done()
		conn.Close()
	}()
	h.serverConnCallback(serverConn, ncc, rc)
}

// Dial implements SSHUpstream.
func (h *sshUpstream) Dial(r testenv.Route, config *ssh.ClientConfig) (*ssh.Client, error) {
	// XXX: need to add ssh listener configuration to Env
	//ssh.Dial("tcp", h.Env().)
	return nil, fmt.Errorf("not implemented")
}

// DirectDial implements SSHUpstream.
func (h *sshUpstream) DirectDial(r testenv.Route, config *ssh.ClientConfig) (*ssh.Client, error) {
	addr := fmt.Sprintf("127.0.0.1:%d", h.serverPort.Value())
	return ssh.Dial("tcp", addr, config)
}
