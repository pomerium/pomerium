package portforward

import (
	"context"
	"errors"
	"maps"
	"slices"
	"sync"

	"github.com/pomerium/pomerium/config"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

//go:generate go run go.uber.org/mock/mockgen -typed -destination ./mock/mock_port_forward.go . RouteEvaluator,UpdateListener

// MaxPermissionEntries is the max number of separate permissions (reverse port
// forward requests) that can be active at a time.
const MaxPermissionEntries = 128

type RouteInfo struct {
	RouteID   string
	From      string
	To        config.WeightedURLs
	Hostname  string // not including port
	Port      uint32
	ClusterID string
}

type RoutePortForwardInfo struct {
	RouteInfo
	Permission Permission
}

type StaticPort struct {
	Port   uint32
	Scheme string
}

type RouteEvaluator interface {
	EvaluateRoute(ctx context.Context, info RouteInfo) error
}

type UpdateListener interface {
	OnRoutesUpdated(routes []RouteInfo)
	OnPermissionsUpdated(permissions []Permission)
	OnClusterEndpointsUpdated(added map[string]RoutePortForwardInfo, removed map[string]struct{})
}

// Manager tracks the state of reverse port-forward requests.
//
// When the SSH client requests reverse port-forwarding, it sends a message
// containing a string bind address and an integer port. The meaning of these
// values is partially implementation-defined, with several special cases
// outlined in https://datatracker.ietf.org/doc/html/rfc4254#section-7, however
// these cases don't quite mean the same thing to Pomerium as they would to a
// standard ssh server. Regardless, we are free to interpret the host and port
// however we wish, as long as the behavior observed from the client's end
// matches what they expect.
//
// Importantly, the bind address is an arbitrary string with very few
// restrictions. It can contain an IP address, a hostname, a regular expression,
// a glob pattern, etc. Openssh uses a limited glob syntax for dynamic port
// forwards to match hostnames, so that is the pattern matching logic that
// Pomerium uses. Route hostnames are matched against the pattern(s) provided by
// the client to determine which routes are candidates for port-forwarding.
//
// Only routes with a valid upstream_tunnel configuration are considered for
// reverse port-forwarding. The ssh_policy in the upstream_tunnel config for
// each matched route is evaluated against the logged-in user/session, and if
// the user is authorized, the SSH connection is added as an endpoint for that
// route's cluster for the duration of the connection, or until the request is
// canceled or authorization is revoked.
//
// In addition to matching the hostname, ports must also be considered. Pomerium
// can serve multiple protocols at the same time on different ports, so the port
// requested by the client is used to select routes by protocol. For non-zero
// ports (0 is a special case - more on this below), a route is considered to
// match if the requested port is 443 and the route has the scheme 'https', or
// the requested port is 22 and the route has the scheme 'ssh', regardless of
// what ports Pomerium is actually listening on. The SSH listener is optional;
// if it is disabled then port 22 is ignored.
//
// If the requested port is 0, however, the logic changes entirely. Pomerium
// uses port 0 to signal that the openssh client (we assume the client is
// openssh-compatible for this mode) is expecting to use the "dynamic" reverse
// port-forwarding protocol on channels that match this permission. Port 0 is
// also a special case at the protocol level:
//
// From https://datatracker.ietf.org/doc/html/rfc4254#section-7.1:
//
//	If a client passes 0 as port number to bind and has 'want reply' as
//	TRUE, then the server allocates the next available unprivileged port
//	number and replies with the following message; otherwise, there is no
//	response-specific data.
//	   byte     SSH_MSG_REQUEST_SUCCESS
//	   uint32   port that was bound on the server
//
// Of course, "allocating the next available unprivileged port" means something
// very different to Pomerium than it might mean to a regular ssh server. A
// regular server might bind to port 0 and send back the dynamically allocated
// port given to it by the kernel, but we obviously aren't allocating real ports
// for this. However, the ssh client needs *some* non-zero port to match the
// permissions to. If a specific host was requested, then different hosts may
// have different permission sets even if both are using dynamic ports. When
// the server opens a forwarded-tcpip channel, the host and port in the
// ChannelOpen request are checked by the client to make sure there is a valid
// matching set of forwarding permissions before allowing the channel to be
// opened.
//
// Note that the pattern matching only happens in dynamic mode; if the client
// sends a glob pattern for the address to us and isn't using dynamic mode, the
// client doesn't treat that host string as a pattern when forwarding channels
// are opened, and will match it exactly instead. In that case, we open the
// channel and send the literal pattern as the address, and only do the route
// hostname matching on our end (i.e. any route that matches the pattern is
// opened using the literal pattern as the address).
//
// Each connection therefore maintains a [VirtualPortSet], which randomly
// allocates "virtual" ports from a preset range - by default, [32768,65536)
// (we could choose any range, but if a low port is randomly chosen, it might
// look strange). These "virtual" ports are effectively just unique (wrt each
// connection) identifiers for dynamic port-forwards. When we send the global
// request success, we send the virtual port, and the client updates its local
// copy of the port-forward permissions it has sent, changing the port from 0
// to the virtual port we sent. When channels are subsequently created, the
// port we send in the channel open request is the virtual port. The client
// uses that port, along with the hostname sent in the same request (which may
// use glob matching), to match a local permission. If successful, the channel
// is opened.
//
// When the client matches a forwarded-tcpip channel open request to a dynamic
// permission, it expects to receive a SOCKS handshake from the client (us)
// according to https://datatracker.ietf.org/doc/html/rfc1928#section-3. The
// client is expected to request no authentication, then send a Connect request.
// The address and port contained in the Connect request are then used as the
// destination address (or dns name) and port that the server will connect to.
// If the connection is successful, the socket data is read/written to the
// channel encapsulated in channel data messages. If the connection is not
// successful, the channel will be closed.
//
// When a dynamic forwarded-tcpip channel is closed, the virtual port is
// released so that it can be reused in the future. Channels using static ports
// use the same port for all requests, but if configuration is changed such that
// a static port is no longer used by the server, any open channels which
// previously requested to port-forward with that static port are closed. The
// client may remain connected though, and if the configuration is changed to
// re-enable the port, port-forwards will be once again be allowed using the
// original permission; clients do not need to reconnect.
type Manager struct {
	permissions      *PermissionSet
	mu               sync.Mutex
	virtualPorts     *VirtualPortSet
	staticPorts      map[uint]context.Context
	ownedStaticPorts map[uint]context.CancelCauseFunc

	// Cached list of all routes the current session would be authorized to
	// port-forward.
	cachedAuthorizedRoutes []RouteInfo
	// Contains the most recently built set of endpoints, keyed by cluster ID.
	// Updated automatically by rebuildEndpoints().
	cachedEndpoints map[string]RoutePortForwardInfo

	updateListeners []UpdateListener
	// auth            RouteEvaluator
}

func NewManager() *Manager {
	mgr := &Manager{
		permissions:      &PermissionSet{},
		virtualPorts:     NewVirtualPortSet(32768, 32768),
		staticPorts:      map[uint]context.Context{},
		ownedStaticPorts: map[uint]context.CancelCauseFunc{},
		cachedEndpoints:  map[string]RoutePortForwardInfo{},
	}
	return mgr
}

func (pfm *Manager) AddUpdateListener(l UpdateListener) {
	pfm.mu.Lock()
	defer pfm.mu.Unlock()
	pfm.updateListeners = append(pfm.updateListeners, l)
	l.OnRoutesUpdated(pfm.cachedAuthorizedRoutes)
	l.OnPermissionsUpdated(slices.Collect(pfm.permissions.AllEntries()))
	l.OnClusterEndpointsUpdated(maps.Clone(pfm.cachedEndpoints), nil)
}

func (pfm *Manager) RemoveUpdateListener(l UpdateListener) {
	pfm.mu.Lock()
	defer pfm.mu.Unlock()
	pfm.updateListeners = slices.DeleteFunc(pfm.updateListeners, func(v UpdateListener) bool { return v == l })
}

func (pfm *Manager) AddPermission(pattern string, requestedPort uint32) (ServerPort, error) {
	pfm.mu.Lock()
	defer pfm.mu.Unlock()
	if pfm.permissions.EntryCount() >= MaxPermissionEntries {
		return ServerPort{}, status.Errorf(codes.ResourceExhausted,
			"exceeded maximum allowed port-forward requests")
	}
	// Check to see if this is a duplicate request
	if _, ok := pfm.permissions.Find(pattern, requestedPort, IncludeExpired(), MatchEquivalent()); ok {
		return ServerPort{}, status.Errorf(codes.InvalidArgument,
			"received duplicate port forward request (host: %s, port: %d)", pattern, requestedPort)
	}

	p := &Permission{}
	if requestedPort == 0 {
		p.HostMatcher = GlobHostMatcher(pattern)
	} else {
		p.HostMatcher = StringHostMatcher(pattern)
	}
	if c, ok := pfm.staticPorts[uint(requestedPort)]; ok {
		p.RequestedPort = requestedPort
		p.Context = c
	} else if requestedPort == 0 {
		// If the client requests port 0, dynamic mode is enabled.
		p.VirtualPort, p.Context = pfm.virtualPorts.MustGet()
	} else {
		return ServerPort{}, status.Errorf(codes.PermissionDenied, "invalid port: %d", requestedPort)
	}

	pfm.permissions.Add(p)
	entries := slices.Collect(pfm.permissions.AllEntries())
	for _, l := range pfm.updateListeners {
		l.OnPermissionsUpdated(entries)
	}
	pfm.rebuildEndpoints()
	return p.ServerPort(), nil
}

func (pfm *Manager) RemovePermission(remoteAddress string, remotePort uint32) error {
	pfm.mu.Lock()
	defer pfm.mu.Unlock()
	perm, ok := pfm.permissions.Find(remoteAddress, remotePort, IncludeExpired())
	if !ok {
		return status.Errorf(codes.NotFound, "port-forward not found")
	}
	pfm.permissions.Remove(perm, errors.New("port-forward canceled"))
	if perm.VirtualPort != 0 {
		pfm.virtualPorts.Put(perm.VirtualPort)
	}
	entries := slices.Collect(pfm.permissions.AllEntries())
	for _, l := range pfm.updateListeners {
		l.OnPermissionsUpdated(entries)
	}
	pfm.rebuildEndpoints()
	return nil
}

// func (pfm *Manager) OnConfigUpdate(cfg *config.Config) {
// 	pfm.mu.Lock()
// 	defer pfm.mu.Unlock()
// 	options := cfg.Options
// 	// Update static ports
// 	const httpsPort = 443
// 	const sshPort = 22
// 	allowedStaticPorts := []uint{httpsPort}
// 	if options.SSHAddr != "" {
// 		allowedStaticPorts = append(allowedStaticPorts, sshPort)
// 	}

// 	pfm.updateAllowedStaticPorts(allowedStaticPorts)

// 	// make a new slice, this is copied around and shouldn't be modified in-place
// 	pfm.cachedAuthorizedRoutes = make([]RouteInfo, 0, len(pfm.cachedAuthorizedRoutes))
// 	for route := range options.GetAllPolicies() {
// 		if route.UpstreamTunnel == nil {
// 			continue
// 		}
// 		info := RouteInfo{
// 			Route:     route,
// 			ClusterID: envoyconfig.GetClusterID(route),
// 		}
// 		u, err := urlutil.ParseAndValidateURL(route.From)
// 		if err != nil {
// 			continue
// 		}
// 		switch u.Scheme {
// 		case "https":
// 			info.Port = httpsPort
// 		case "ssh":
// 			info.Port = sshPort
// 		default:
// 			continue
// 		}
// 		info.Hostname = u.Hostname()
// 		if err := pfm.auth.EvaluateRoute(pfm.streamCtx, info); err == nil {
// 			pfm.cachedAuthorizedRoutes = append(pfm.cachedAuthorizedRoutes, info)
// 		}
// 	}

// 	for _, l := range pfm.updateListeners {
// 		l.OnRoutesUpdated(pfm.cachedAuthorizedRoutes)
// 	}
// 	pfm.rebuildEndpoints()
// }

func (pfm *Manager) rebuildEndpoints() {
	toAdd := make(map[string]RoutePortForwardInfo)
	toRemove := make(map[string]struct{})
	for k := range pfm.cachedEndpoints {
		toRemove[k] = struct{}{}
	}
	for _, route := range pfm.cachedAuthorizedRoutes {
		if permission, ok := pfm.permissions.Match(route.Hostname, route.Port); ok {
			delete(toRemove, route.ClusterID)
			if _, exists := pfm.cachedEndpoints[route.ClusterID]; !exists {
				toAdd[route.ClusterID] = RoutePortForwardInfo{
					RouteInfo:  route,
					Permission: *permission,
				}
			}
		}
	}

	maps.Copy(pfm.cachedEndpoints, toAdd)
	for id := range toRemove {
		delete(pfm.cachedEndpoints, id)
	}
	for _, l := range pfm.updateListeners {
		l.OnClusterEndpointsUpdated(toAdd, toRemove)
	}
}

var errListenerShuttingDown = errors.New("listener shutting down")

func (pfm *Manager) UpdateEnabledStaticPorts(enabledStaticPorts []uint) {
	pfm.mu.Lock()
	defer pfm.mu.Unlock()
	for existing := range pfm.staticPorts {
		if !slices.Contains(enabledStaticPorts, existing) {
			pfm.ownedStaticPorts[existing](errListenerShuttingDown)
			delete(pfm.ownedStaticPorts, existing)
			delete(pfm.staticPorts, existing)
		}
	}
	for _, updated := range enabledStaticPorts {
		if _, ok := pfm.staticPorts[updated]; !ok {
			ctx, ca := context.WithCancelCause(context.Background())
			pfm.staticPorts[updated] = ctx
			pfm.ownedStaticPorts[updated] = ca
		}
		// If there are any (static) permissions that were previously canceled in
		// the permission set with this port, re-enable them with the new context
		pfm.permissions.ResetCanceled(pfm.staticPorts[updated], updated)
	}
}

func (pfm *Manager) UpdateAuthorizedRoutes(routes []RouteInfo) {
	pfm.mu.Lock()
	defer pfm.mu.Unlock()
	pfm.cachedAuthorizedRoutes = routes
	for _, l := range pfm.updateListeners {
		l.OnRoutesUpdated(pfm.cachedAuthorizedRoutes)
	}
	pfm.rebuildEndpoints()
}
