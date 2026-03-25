package httputil

// upgrade types
const (
	UpgradeTypeConnectTCP = "CONNECT"
	UpgradeTypeConnectUDP = "CONNECT-UDP"
	UpgradeTypeWebsocket  = "websocket"
	UpgradeTypeSPDY       = "spdy/3.1"
)
