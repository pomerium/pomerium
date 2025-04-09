package upstreams

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/values"
	"golang.org/x/crypto/ssh"
)

type SSHUpstreamOptions struct {
	displayName    string
	serverConfig   ssh.ServerConfig
	authorizedKeys authorizedKeysChecker
}

type SSHUpstreamOption interface {
	applySSH(*SSHUpstreamOptions)
}

type sshUpstreamOption func(o *SSHUpstreamOptions)

func (s sshUpstreamOption) applySSH(o *SSHUpstreamOptions) { s(o) }

func WithPublicKeyAuthAlgorithms(algs ...string) SSHUpstreamOption {
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

// WithPublicKeyCallback sets a custom callback for the publickey authentication method.
// This will override any previous [WithAuthorizedKey] option.
func WithPublicKeyCallback(c func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error)) SSHUpstreamOption {
	return sshUpstreamOption(func(o *SSHUpstreamOptions) {
		o.serverConfig.PublicKeyCallback = c
	})
}

// WithAuthorizedKey allows the given key to be used to authenticate the given username,
// enabling the publickey authentication method. This will override any previous
// [WithPublicKeyCallback] option.
func WithAuthorizedKey(key ssh.PublicKey, username string) SSHUpstreamOption {
	return sshUpstreamOption(func(o *SSHUpstreamOptions) {
		o.authorizedKeys.add(key, username)
		o.serverConfig.PublicKeyCallback = o.authorizedKeys.check
	})
}

type authorizedKeysChecker map[string]string // map from marshaled public key to corresponding username

func (c *authorizedKeysChecker) add(key ssh.PublicKey, username string) {
	if *c == nil {
		*c = make(map[string]string)
	}
	(*c)[string(key.Marshal())] = username
}

func (c authorizedKeysChecker) check(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	if c[string(key.Marshal())] == conn.User() {
		return &ssh.Permissions{}, nil
	}
	return nil, fmt.Errorf("not authorized")
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

// Addr implements SSHUpstream.
func (h *sshUpstream) Addr() values.Value[string] {
	return values.Bind(h.serverPort, func(port int) string {
		return fmt.Sprintf("%s:%d", h.Env().Host(), port)
	})
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
		return fmt.Sprintf("%s://%s:%d", protocol, h.Env().Host(), port)
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
			// The testenv cleanup expects this function to return a "test cleanup" error,
			// which propagates via the context.
			if ctx.Err() != nil {
				return context.Cause(ctx)
			}
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
	return ssh.Dial("tcp", strings.TrimPrefix(r.URL().Value(), "ssh://"), config)
}

// DirectDial implements SSHUpstream.
func (h *sshUpstream) DirectDial(r testenv.Route, config *ssh.ClientConfig) (*ssh.Client, error) {
	addr := fmt.Sprintf("127.0.0.1:%d", h.serverPort.Value())
	return ssh.Dial("tcp", addr, config)
}
