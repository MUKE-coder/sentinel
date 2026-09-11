package api

import (
	"net"
	"net/http"
	"net/netip"
)

// forwardingHeaders mark a request relayed by a proxy. A reverse proxy or
// tunnel on the same host connects over loopback on behalf of remote
// clients, so a loopback peer alone doesn't make a request local.
var forwardingHeaders = []string{
	"X-Forwarded-For", "X-Real-IP", "Forwarded", "X-Forwarded-Host",
	"True-Client-IP", "CF-Connecting-IP",
}

// isLocalRequest reports whether r came straight from this machine: a
// loopback peer and no forwarding headers.
func isLocalRequest(r *http.Request) bool {
	for _, h := range forwardingHeaders {
		if r.Header.Get(h) != "" {
			return false
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.Unmap().IsLoopback()
}
