package httpproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"mac-proxy/internal/outbound"
	"mac-proxy/internal/wire"
)

type Dial func(context.Context, string, string) (net.Conn, error)

func Handler(dial Dial) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodConnect {
			connect(writer, request, dial)
			return
		}
		forward(writer, request, dial)
	})
}

func fail(writer http.ResponseWriter, err error) {
	if errors.Is(err, outbound.ErrRejected) {
		http.Error(writer, "Blocked by routing policy", http.StatusForbidden)
	} else {
		http.Error(writer, "Proxy connection failed", http.StatusBadGateway)
	}
}

func connect(writer http.ResponseWriter, request *http.Request, dial Dial) {
	target := request.RequestURI
	if _, _, err := wire.Split(target); err != nil {
		http.Error(writer, "CONNECT requires host:port", http.StatusBadRequest)
		return
	}
	upstream, err := dial(request.Context(), "HTTP CONNECT", target)
	if err != nil {
		fail(writer, err)
		return
	}
	defer upstream.Close()
	client, buffer, err := http.NewResponseController(writer).Hijack()
	if err != nil {
		http.Error(writer, "Cannot establish tunnel", http.StatusInternalServerError)
		return
	}
	defer client.Close()
	if _, err := buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := buffer.Flush(); err != nil {
		return
	}
	wire.Relay(&wire.BufferedConn{Conn: client, Reader: buffer.Reader}, upstream)
}

func forward(writer http.ResponseWriter, request *http.Request, dial Dial) {
	if request.URL.Scheme != "http" || request.URL.Hostname() == "" || request.URL.User != nil {
		http.Error(writer, "Expected an absolute HTTP URL", http.StatusBadRequest)
		return
	}
	outgoing := request.Clone(request.Context())
	outgoing.RequestURI = ""
	outgoing.Host = outgoing.URL.Host
	outgoing.Close = false
	removeHopHeaders(outgoing.Header)
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, target string) (net.Conn, error) {
			return dial(ctx, "HTTP", target)
		},
		DisableKeepAlives:     true,
		DisableCompression:    true,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	response, err := transport.RoundTrip(outgoing)
	if err != nil {
		fail(writer, err)
		return
	}
	defer response.Body.Close()
	removeHopHeaders(response.Header)
	for name, values := range response.Header {
		writer.Header()[name] = values
	}
	writer.WriteHeader(response.StatusCode)
	io.Copy(writer, response.Body)
}

func removeHopHeaders(header http.Header) {
	for _, value := range header.Values("Connection") {
		for name := range strings.SplitSeq(value, ",") {
			header.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range []string{"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Proxy-Connection", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		header.Del(name)
	}
}
