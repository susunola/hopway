package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"mac-proxy/internal/engine"
	"mac-proxy/internal/httpproxy"
	"mac-proxy/internal/importer"
	"mac-proxy/internal/socks5"
)

type ready struct {
	Control string `json:"control"`
	Token   string `json:"token"`
	SOCKS   string `json:"socks"`
	HTTP    string `json:"http"`
}

func main() {
	path := flag.String("config", "", "JSON configuration file")
	port := flag.Int("port", -1, "override the SOCKS5 listen port")
	check := flag.Bool("check", false, "validate configuration and exit")
	managed := flag.Bool("managed", false, "start the local control API and exit when stdin closes")
	importInput := flag.Bool("import", false, "read a subscription URL or profile from stdin and print converted JSON")
	flag.Parse()
	if *importInput {
		base, err := loadConfig(*path)
		if err == nil {
			var result importer.Result
			result, err = importer.Import(context.Background(), os.Stdin, base)
			if err == nil {
				err = json.NewEncoder(os.Stdout).Encode(result)
			}
		}
		if err != nil {
			log.SetFlags(0)
			log.Fatal(err)
		}
		return
	}

	if err := run(*path, *port, *check, *managed); err != nil {
		if *managed {
			json.NewEncoder(os.Stdout).Encode(map[string]string{"error": err.Error()})
		}
		log.Fatal(err)
	}
}

func listen(port int) (*net.TCPListener, error) {
	return net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
}

func loadConfig(path string) (engine.Config, error) {
	if path == "" {
		return engine.Default(), nil
	}
	file, err := os.Open(path)
	if err != nil {
		return engine.Config{}, err
	}
	defer file.Close()
	return engine.Decode(file)
}

func run(path string, port int, check, managed bool) error {
	config, err := loadConfig(path)
	if err != nil {
		return err
	}
	if port != -1 {
		config.SOCKSPort = port
	}
	if _, err := engine.New(config); err != nil {
		return err
	}
	if check {
		return nil
	}

	socks, err := listen(config.SOCKSPort)
	if err != nil {
		return fmt.Errorf("SOCKS5: %w", err)
	}
	defer socks.Close()
	httpProxy, err := listen(config.HTTPPort)
	if err != nil {
		return fmt.Errorf("HTTP proxy: %w", err)
	}
	defer httpProxy.Close()

	info := ready{SOCKS: socks.Addr().String(), HTTP: httpProxy.Addr().String()}
	ports := []int{socks.Addr().(*net.TCPAddr).Port, httpProxy.Addr().(*net.TCPAddr).Port}
	var control *net.TCPListener
	if managed {
		control, err = listen(0)
		if err != nil {
			return err
		}
		defer control.Close()
		ports = append(ports, control.Addr().(*net.TCPAddr).Port)
		var token [32]byte
		if _, err := rand.Read(token[:]); err != nil {
			return err
		}
		info.Control = "http://" + control.Addr().String()
		info.Token = hex.EncodeToString(token[:])
	}
	core, err := engine.New(config, ports...)
	if err != nil {
		return err
	}
	serverErrors := make(chan error, 3)
	go func() { serverErrors <- serveSOCKS(socks, core) }()
	httpServer := &http.Server{
		Handler: httpproxy.Handler(core.Dial), ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 64 << 10,
	}
	go func() { serverErrors <- httpServer.Serve(httpProxy) }()
	log.Printf("SOCKS5 listening on %s", info.SOCKS)
	log.Printf("HTTP proxy listening on %s", info.HTTP)
	if managed {
		server := &http.Server{
			Handler: controlHandler(core, info.Token), ReadTimeout: 5 * time.Second,
			WriteTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8 << 10,
		}
		go func() { serverErrors <- server.Serve(control) }()
		if err := json.NewEncoder(os.Stdout).Encode(info); err != nil {
			return err
		}
		go func() {
			io.Copy(io.Discard, os.Stdin)
			serverErrors <- nil
		}()
	}
	return <-serverErrors
}

func serveSOCKS(listener *net.TCPListener, core *engine.Engine) error {
	for {
		client, err := listener.AcceptTCP()
		if err != nil {
			return err
		}
		go func() {
			defer client.Close()
			socks5.Handle(client, core.Dial)
		}()
	}
}

func controlHandler(core *engine.Engine, token string) http.Handler {
	router := http.NewServeMux()
	router.HandleFunc("GET /status", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		json.NewEncoder(writer).Encode(core.Status())
	})
	router.HandleFunc("PUT /policy", func(writer http.ResponseWriter, request *http.Request) {
		var policy engine.Policy
		decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, 4096))
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&policy)
		if err == nil && decoder.Decode(new(any)) != io.EOF {
			err = errors.New("expected one policy object")
		}
		if err == nil {
			err = core.SetPolicy(policy)
		}
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	})
	authorization := []byte("Bearer " + token)
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		if subtle.ConstantTimeCompare([]byte(request.Header.Get("Authorization")), authorization) != 1 {
			http.Error(writer, "Unauthorized", http.StatusUnauthorized)
			return
		}
		router.ServeHTTP(writer, request)
	})
}
