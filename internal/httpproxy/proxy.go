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
	"mac-proxy/internal/peer"
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
	code, message := failure(err)
	http.Error(writer, message, code)
}

func failure(err error) (int, string) {
	if errors.Is(err, wire.ErrConnectionLimit) {
		return http.StatusServiceUnavailable, "Proxy connection limit reached"
	}
	if wire.DescriptorExhausted(err) {
		return http.StatusServiceUnavailable, "Proxy file descriptor limit reached"
	}
	if errors.Is(err, outbound.ErrRejected) {
		return http.StatusForbidden, "Blocked by routing policy"
	}
	return http.StatusBadGateway, "Proxy connection failed"
}

func connect(writer http.ResponseWriter, request *http.Request, dial Dial) {
	target := request.RequestURI
	if _, _, err := wire.Split(target); err != nil {
		http.Error(writer, "CONNECT requires host:port", http.StatusBadRequest)
		return
	}
	client, buffer, err := http.NewResponseController(writer).Hijack()
	if err != nil {
		http.Error(writer, "Cannot establish tunnel", http.StatusInternalServerError)
		return
	}
	defer client.Close()
	// The hijacked socket now owns the tunnel lifetime. The HTTP reader
	// can cancel its old request context even on a legitimate half-close.
	upstream, err := wire.DialWithClient(context.WithoutCancel(withPeer(request)), client, buffer.Reader, func(ctx context.Context) (net.Conn, error) {
		return dial(ctx, "HTTP CONNECT", target)
	})
	if err != nil {
		code, message := failure(err)
		body := message + "\n"
		response := http.Response{
			ProtoMajor: 1, ProtoMinor: 1, StatusCode: code, Close: true, ContentLength: int64(len(body)),
			Header: http.Header{"Content-Type": {"text/plain; charset=utf-8"}, "X-Content-Type-Options": {"nosniff"}},
			Body:   io.NopCloser(strings.NewReader(body)),
		}
		_ = response.Write(buffer)
		_ = buffer.Flush()
		return
	}
	defer upstream.Close()
	if _, err := buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := buffer.Flush(); err != nil {
		return
	}
	if buffer.Reader.Buffered() != 0 {
		client = &wire.BufferedConn{Conn: client, Reader: buffer.Reader}
	}
	wire.Relay(client, upstream)
}

func forward(writer http.ResponseWriter, request *http.Request, dial Dial) {
	if request.URL.Scheme != "http" || request.URL.Hostname() == "" || request.URL.User != nil {
		http.Error(writer, "Expected an absolute HTTP URL", http.StatusBadRequest)
		return
	}
	outgoing := request.Clone(withPeer(request))
	outgoing.RequestURI = ""
	outgoing.Host = outgoing.URL.Host
	outgoing.Close = false
	removeHopHeaders(outgoing.Header)
	transport := &http.Transport{
		// The transport is per request. Do not keep its dial running
		// after this client's request has been canceled.
		DialContext: func(_ context.Context, _, target string) (net.Conn, error) {
			return dial(outgoing.Context(), "HTTP", target)
		},
		DisableKeepAlives:     true,
		DisableCompression:    true,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	defer transport.CloseIdleConnections()
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

// withPeer records the client's socket so the engine can find its process.
func withPeer(request *http.Request) context.Context {
	local, _ := request.Context().Value(http.LocalAddrContextKey).(net.Addr)
	remote, err := net.ResolveTCPAddr("tcp", request.RemoteAddr)
	if err != nil || local == nil {
		return request.Context()
	}
	return peer.With(request.Context(), remote, local)
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
