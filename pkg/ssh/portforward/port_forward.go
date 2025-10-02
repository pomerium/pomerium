package portforward

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/bits-and-blooms/bitset"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/urlutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// PermissionSet models a set of active reverse port-forward requests from the
// client. Analog to `struct permission_set` in openssh.
type PermissionSet struct {
	Permissions map[*Permission]context.CancelCauseFunc
}

func (ps PermissionSet) ResetCanceled(port uint, context context.Context) {
	for perm := range ps.Permissions {
		if perm.RequestedPort == uint32(port) && perm.Context.Err() != nil {
			perm.Context = context
		}
	}
}

func (ps *PermissionSet) Add(perm *Permission) {
	var cancel context.CancelCauseFunc
	perm.Context, cancel = context.WithCancelCause(perm.Context)
	ps.Permissions[perm] = cancel
}

func (ps *PermissionSet) Remove(perm *Permission, cause error) {
	ps.Permissions[perm](cause)
	delete(ps.Permissions, perm)
}

func (ps *PermissionSet) Find(pattern string, serverPort uint32) (*Permission, bool) {
	for perm := range ps.Permissions {
		if perm.Context.Err() != nil {
			continue
		}
		if perm.HostPattern.inputPattern == pattern && perm.ServerPort().Value == serverPort {
			return perm, true
		}
	}
	return nil, false
}

func (ps *PermissionSet) Match(requestedHostname string, requestedPort uint32) (*Permission, bool) {
	for perm := range ps.Permissions {
		if perm.Context.Err() != nil {
			continue
		}
		if perm.HostPattern.Match(requestedHostname) {
			if perm.RequestedPort == 0 || perm.RequestedPort == requestedPort {
				return perm, true
			}
		}
	}
	return nil, false
}

type ServerPort struct {
	Value     uint32
	IsDynamic bool
}

// Permission models a single reverse port-forward request from the client.
// It should be uniquely identifiable within a permission set.
type Permission struct {
	Context       context.Context
	HostPattern   Matcher
	RequestedPort uint32
	VirtualPort   uint
}

func (p *Permission) ServerPort() ServerPort {
	if p.RequestedPort != 0 {
		return ServerPort{
			Value:     p.RequestedPort,
			IsDynamic: false,
		}
	}
	return ServerPort{
		Value:     uint32(p.VirtualPort),
		IsDynamic: true,
	}
}

type VirtualPortSet struct {
	mu       sync.Mutex
	ports    *bitset.BitSet
	maxPorts uint
	offset   uint
	reserved map[uint]context.CancelCauseFunc
	active   map[uint]context.CancelCauseFunc
}

func NewVirtualPortSet(maxPorts, offset uint) *VirtualPortSet {
	return &VirtualPortSet{
		maxPorts: maxPorts,
		offset:   offset,
		ports:    bitset.MustNew(maxPorts),
		reserved: map[uint]context.CancelCauseFunc{},
		active:   map[uint]context.CancelCauseFunc{},
	}
}

var ErrNoFreePorts = errors.New("no free ports available")

func (vps *VirtualPortSet) Count() uint {
	return vps.ports.Count()
}

func (vps *VirtualPortSet) Get() (uint, context.Context, error) {
	initial := rand.N(vps.maxPorts)
	var port uint
	var ok bool
	if initial%2 == 0 {
		if port, ok = vps.ports.NextClear(initial); !ok {
			port, ok = vps.ports.PreviousClear(initial)
		}
	} else {
		if port, ok = vps.ports.PreviousClear(initial); !ok {
			port, ok = vps.ports.NextClear(initial)
		}
	}
	if ok {
		vps.ports.Set(port)
		ctx, ca := context.WithCancelCause(context.Background())
		vps.active[port] = ca
		return port + vps.offset, ctx, nil
	}
	return 0, nil, ErrNoFreePorts
}

func (vps *VirtualPortSet) WithinRange(port uint) bool {
	return port >= vps.offset && port < vps.offset+vps.maxPorts
}

func (vps *VirtualPortSet) Put(port uint) {
	if !vps.WithinRange(port) {
		panic(fmt.Sprintf("bug: Put called with out-of-range port %d", port))
	}
	translatedPort := port - vps.offset
	if !vps.ports.Test(translatedPort) {
		panic("bug: port was never allocated")
	}
	vps.putTranslated(translatedPort)
}

func (vps *VirtualPortSet) putTranslated(port uint) {
	vps.ports.Clear(port)
	vps.active[port](errors.New("port closed")) // TODO better error message
	delete(vps.active, port)
}

func (vps *VirtualPortSet) Reserve(port uint) context.Context {
	if !vps.WithinRange(port) {
		panic(fmt.Sprintf("bug: Reserve called with out-of-range port %d", port))
	}
	translatedPort := port - vps.offset
	if _, ok := vps.reserved[translatedPort]; ok {
		panic(fmt.Sprintf("bug: Reserve called with port %d which is already reserved", port))
	}
	// first, check if there is an active port with this number
	if _, ok := vps.active[translatedPort]; ok {
		// if so, clear it
		vps.putTranslated(translatedPort)
	}
	ctx, ca := context.WithCancelCause(context.Background())
	vps.reserved[translatedPort] = ca
	vps.ports.Set(translatedPort)
	return ctx
}

func (vps *VirtualPortSet) ClearReservation(port uint) {
	if !vps.WithinRange(port) {
		panic(fmt.Sprintf("bug: Reserve called with out-of-range port %d", port))
	}
	translatedPort := port - vps.offset
	if _, ok := vps.reserved[translatedPort]; !ok {
		panic(fmt.Sprintf("bug: ClearReservation called with port %d which is not reserved", port))
	}
	vps.reserved[translatedPort](errors.New("connection closed by server"))
	delete(vps.reserved, translatedPort)
	vps.ports.Clear(translatedPort)
}

type RouteInfo struct {
	Route     *config.Policy
	Hostname  string // not including port
	Port      uint32
	ClusterID string
}

type RoutePortForwardInfo struct {
	RouteInfo
	Permission *Permission
}

type RouteEvaluator interface {
	EvaluateRoute(info RouteInfo) error
}

type UpdateListener interface {
	OnRoutesUpdated(routes []RouteInfo)
	OnPermissionsUpdated(permissions *PermissionSet)
	OnClusterEndpointsUpdated(endpoints []RoutePortForwardInfo)
}

// PortForwardManager tracks the state of reverse port-forward requests.
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
// forwards to match hostnames (there is no built-in client for this however),
// so that is the pattern matching logic that Pomerium uses. We match route
// hostnames against the patterns provided by the client to determine which
// routes are candidates for port-forwarding. Only routes with a valid
// upstream_tunnel configuration are considered for this. The ssh_policy in
// each upstream_tunnel config is evaluated against the logged-in user, and
// if successful, the connection is added as an endpoint for that route's
// cluster.
//
// It is not only the hostname that needs to match, though: the requested port
// also must either "match" (somehow), or be 0. If the port is 0, the meaning
// changes entirely (more on this below). For non-zero requested ports, we
// consider a route to match if the port is equal to the listen port of the
// listener serving that route's scheme. For example, if Pomerium is
// configured with `address: ":443"`, then a requested port of 443 will match
// routes with the `https://` scheme. If the address is something else, e.g.
// `address: ":8443"`, then clients must request port 8443 instead. If the
// server's listen addresses are changed at runtime, existing permissions will
// be re-evaluated against the new ports.
//
// If the requested port is 0, however, the logic changes entirely. Pomerium
// uses port 0 to signal that the openssh client (we assume the client is
// openssh-compatible for this mode) is expecting to use the "dynamic" reverse
// port-forwarding protocol on channels that match this permission. Port 0 is
// also a special case at the protocol level:
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
// opened. Note that the pattern patching only happens in dynamic mode though;
// if the client sends a glob pattern for the address to us and isn't using
// dynamic mode, the client doesn't treat that host string as a pattern when
// forwarding channels are opened, and will match it exactly instead. In that
// case, we open the channel and send the literal pattern as the address, and
// only do the route hostname matching on our end (i.e. any route that matches
// the pattern is opened using the literal pattern as the address).
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
// When a dynamic forwarded-tcpip channel is closed, we release the virtual
// port so that it can be reused in the future. Channels using static ports
// use the same port for all requests, but if configuration is changed such
// that a static port is no longer used by the server, any open channels that
// previously requested to port-forward with that static port are closed. The
// client may remain connected though, and if the configuration is changed to
// re-enable the port, port-forwards will be once again be allowed using the
// original permission; clients do not need to reconnect.
type PortForwardManager struct {
	permissions      PermissionSet
	mu               sync.Mutex
	virtualPorts     *VirtualPortSet
	staticPorts      map[uint]context.Context
	ownedStaticPorts map[uint]context.CancelCauseFunc

	cachedTunnelRoutes []RouteInfo
	cachedEndpoints    []RoutePortForwardInfo

	updateListeners []UpdateListener
	auth            RouteEvaluator
}

func NewPortForwardManager(cfg *config.Config, auth RouteEvaluator) *PortForwardManager {
	mgr := &PortForwardManager{
		auth:             auth,
		permissions:      PermissionSet{Permissions: map[*Permission]context.CancelCauseFunc{}},
		virtualPorts:     NewVirtualPortSet(32768, 32768),
		staticPorts:      map[uint]context.Context{},
		ownedStaticPorts: map[uint]context.CancelCauseFunc{},
	}
	mgr.OnConfigUpdate(cfg)
	return mgr
}

func (pfm *PortForwardManager) AddUpdateListener(l UpdateListener) {
	pfm.mu.Lock()
	defer pfm.mu.Unlock()
	pfm.updateListeners = append(pfm.updateListeners, l)
	l.OnRoutesUpdated(pfm.cachedTunnelRoutes)
	l.OnPermissionsUpdated(&pfm.permissions)
	l.OnClusterEndpointsUpdated(pfm.cachedEndpoints)
}

func (pfm *PortForwardManager) RemoveUpdateListener(l UpdateListener) {
	pfm.mu.Lock()
	defer pfm.mu.Unlock()
	pfm.updateListeners = slices.DeleteFunc(pfm.updateListeners, func(v UpdateListener) bool { return v == l })
}

func (pfm *PortForwardManager) AddPermission(pattern string, requestedPort uint32) (ServerPort, error) {
	pfm.mu.Lock()
	defer pfm.mu.Unlock()
	// Check to see if this is a duplicate request
	if _, ok := pfm.permissions.Find(pattern, requestedPort); ok {
		return ServerPort{}, status.Errorf(codes.InvalidArgument,
			"received duplicate port forward request (host: %s, port: %d)", pattern, requestedPort)
	}

	p := &Permission{
		HostPattern: CompileMatcher(pattern),
	}
	if c, ok := pfm.staticPorts[uint(requestedPort)]; ok {
		p.RequestedPort = requestedPort
		p.Context = c
	} else if requestedPort == 0 {
		// If the client requests port 0, dynamic mode is enabled.
		var err error
		p.VirtualPort, p.Context, err = pfm.virtualPorts.Get()
		if err != nil {
			return ServerPort{}, status.Error(codes.ResourceExhausted, err.Error())
		}
	} else {
		return ServerPort{}, status.Errorf(codes.PermissionDenied, "invalid port: %d", requestedPort)
	}

	pfm.permissions.Add(p)
	for _, l := range pfm.updateListeners {
		l.OnPermissionsUpdated(&pfm.permissions)
	}
	pfm.rebuildEndpoints()
	return p.ServerPort(), nil
}

func (pfm *PortForwardManager) RemovePermission(remoteAddress string, remotePort uint32) error {
	pfm.mu.Lock()
	defer pfm.mu.Unlock()
	perm, ok := pfm.permissions.Find(remoteAddress, remotePort)
	if !ok {
		return status.Errorf(codes.NotFound, "port-forward not found")
	}
	pfm.permissions.Remove(perm, errors.New("port-forward canceled"))
	if perm.VirtualPort != 0 {
		pfm.virtualPorts.Put(perm.VirtualPort)
	}
	for _, l := range pfm.updateListeners {
		l.OnPermissionsUpdated(&pfm.permissions)
	}
	pfm.rebuildEndpoints()
	return nil
}

// FIXME
var getClusterID = func(policy *config.Policy) string {
	prefix := getClusterStatsName(policy)
	if prefix == "" {
		prefix = "route"
	}

	id, _ := policy.RouteID()
	return fmt.Sprintf("%s-%s", prefix, id)
}

// FIXME
func getClusterStatsName(policy *config.Policy) string {
	if policy.EnvoyOpts != nil && policy.EnvoyOpts.Name != "" {
		return policy.EnvoyOpts.Name
	}
	return ""
}

func (pfm *PortForwardManager) OnConfigUpdate(cfg *config.Config) error {
	pfm.mu.Lock()
	defer pfm.mu.Unlock()
	options := cfg.Options
	// Update static ports
	var httpsPort uint32 = 443
	var sshPort uint32 = 22
	allowedStaticPorts := []uint{}
	if _, port, err := net.SplitHostPort(options.Addr); err != nil {
		return err
	} else {
		p, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			panic(err)
		}
		httpsPort = uint32(p)
		allowedStaticPorts = append(allowedStaticPorts, uint(p))
	}
	if options.SSHAddr != "" {
		if _, port, err := net.SplitHostPort(options.SSHAddr); err == nil {
			p, err := strconv.ParseUint(port, 10, 16)
			if err != nil {
				panic(err)
			}
			sshPort = uint32(p)
			allowedStaticPorts = append(allowedStaticPorts, uint(p))
		}
	}
	pfm.updateAllowedStaticPorts(allowedStaticPorts)

	// make a new slice, this is copied around and shouldn't be modified in-place
	pfm.cachedTunnelRoutes = make([]RouteInfo, 0, len(pfm.cachedTunnelRoutes))
	for route := range options.GetAllPolicies() {
		if route.UpstreamTunnel == nil {
			continue
		}
		info := RouteInfo{
			Route:     route,
			ClusterID: getClusterID(route),
		}
		u, err := urlutil.ParseAndValidateURL(route.From)
		if err != nil {
			continue
		}
		switch u.Scheme {
		case "https":
			info.Port = httpsPort
		case "ssh":
			info.Port = sshPort
		default:
			continue
		}
		info.Hostname = u.Hostname()
		if err := pfm.auth.EvaluateRoute(info); err == nil {
			pfm.cachedTunnelRoutes = append(pfm.cachedTunnelRoutes, info)
		}
	}

	for _, l := range pfm.updateListeners {
		l.OnRoutesUpdated(pfm.cachedTunnelRoutes)
	}
	pfm.rebuildEndpoints()
	return nil
}

func (pfm *PortForwardManager) rebuildEndpoints() {
	endpoints := make([]RoutePortForwardInfo, 0, len(pfm.cachedTunnelRoutes))
	for _, route := range pfm.cachedTunnelRoutes {
		if permission, ok := pfm.permissions.Match(route.Hostname, route.Port); ok {
			endpoints = append(endpoints, RoutePortForwardInfo{
				RouteInfo:  route,
				Permission: permission,
			})
		}
	}
	pfm.cachedEndpoints = endpoints
	for _, l := range pfm.updateListeners {
		l.OnClusterEndpointsUpdated(endpoints)
		l.OnPermissionsUpdated(&pfm.permissions)
		l.OnRoutesUpdated(pfm.cachedTunnelRoutes)
	}
}

func (pfm *PortForwardManager) updateAllowedStaticPorts(allowedStaticPorts []uint) {
	for existing := range pfm.staticPorts {
		if !slices.Contains(allowedStaticPorts, existing) {
			// clear any reserved ports that were within the virtual port range
			if pfm.virtualPorts.WithinRange(existing) {
				pfm.virtualPorts.ClearReservation(existing)
				delete(pfm.staticPorts, existing)
			} else {
				pfm.ownedStaticPorts[existing](errors.New("listener shutting down"))
				delete(pfm.ownedStaticPorts, existing)
				delete(pfm.staticPorts, existing)
			}
		}
	}
	for _, updated := range allowedStaticPorts {
		if _, ok := pfm.staticPorts[updated]; !ok {
			// reserve any new ports in the virtual port range
			if pfm.virtualPorts.WithinRange(updated) {
				pfm.staticPorts[updated] = pfm.virtualPorts.Reserve(updated)
			} else {
				ctx, ca := context.WithCancelCause(context.Background())
				pfm.staticPorts[updated] = ctx
				pfm.ownedStaticPorts[updated] = ca
			}

			// If there are any permissions that were previously canceled in the
			// permission set with this port, re-enable them with the new context
			pfm.permissions.ResetCanceled(updated, pfm.staticPorts[updated])
		}
	}
}

// Matcher is a limited glob matcher supporting only ? and * wildcards,
// compatible with openssh match_pattern().
type Matcher struct {
	inputPattern string // the exact pattern that was compiled
	re           *regexp.Regexp
}

var regexMatchAll = regexp.MustCompile("^.*$")

func CompileMatcher(pattern string) Matcher {
	// Openssh will send the empty string if the client requests either the
	// empty string or a single '*'.
	//
	// 'localhost' is special: it's the default when using the syntax
	// '-R port:host:hostport'. Compared to '-R :port:host:hostport' (with the
	// extra colon) which sends empty string. We treat it the same for pattern
	// matching purposes, and we could look for it in the future to trigger
	// specific behavior when using that syntax.
	if pattern == "" || strings.Trim(pattern, "*") == "" || pattern == "localhost" {
		return Matcher{
			inputPattern: pattern,
			re:           regexMatchAll,
		}
	}

	regexPattern := make([]byte, 0, 2*len(pattern)+2)
	// note: openssh patterns are case-insensitive
	regexPattern = append(regexPattern, "(?i:^"...)
	for i := 0; i < len(pattern); i++ {
		switch b := pattern[i]; b {
		case '*':
			for i+1 < len(pattern) && pattern[i+1] == '*' {
				i++
			}
			regexPattern = append(regexPattern, ".*"...)
		case '?':
			regexPattern = append(regexPattern, '.')
		case '\\', '.', '+', '(', ')', '|', '[', ']', '{', '}', '^', '$':
			regexPattern = append(regexPattern, '\\', b)
		default:
			// non-escape character
			regexPattern = append(regexPattern, b)
		}
	}
	regexPattern = append(regexPattern, "$)"...)
	return Matcher{
		inputPattern: pattern,
		re:           regexp.MustCompile(string(regexPattern)),
	}
}

func (g *Matcher) InputPattern() string {
	return g.inputPattern
}

func (g *Matcher) IsMatchAll() bool {
	return (g.re == regexMatchAll)
}

func (g *Matcher) Match(str string) bool {
	return g.re.MatchString(str)
}
