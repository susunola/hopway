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
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"mac-proxy/internal/app"
	"mac-proxy/internal/backend"
	"mac-proxy/internal/engine"
	"mac-proxy/internal/httpproxy"
	"mac-proxy/internal/importer"
	"mac-proxy/internal/profile"
	"mac-proxy/internal/socks5"
	"mac-proxy/internal/sysproxy"
	"mac-proxy/internal/tun"
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
	tunHelper := flag.String("tun-helper", "", "internal: create the TUN device as root and hand it to the core over this socket")
	flag.Parse()
	if *tunHelper != "" {
		if err := tun.RunHelper(*tunHelper, tun.Options{}); err != nil {
			log.SetFlags(0)
			log.Fatal(err)
		}
		return
	}
	if *importInput {
		result, err := runImport(*path)
		if err == nil {
			err = json.NewEncoder(os.Stdout).Encode(result)
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

// runImport converts pasted input. A subscription URL becomes a subscription
// entry (its nodes are cached and refreshed automatically); anything else is
// merged into the configuration as before.
func runImport(path string) (importer.Result, error) {
	base, err := loadConfig(path)
	if errors.Is(err, os.ErrNotExist) {
		base, err = engine.Default(), nil
	}
	if err != nil {
		return importer.Result{}, err
	}
	data, err := io.ReadAll(io.LimitReader(os.Stdin, importer.MaxSize+1))
	if err != nil {
		return importer.Result{}, err
	}
	raw := strings.TrimSpace(strings.TrimPrefix(string(data), "\ufeff"))
	impl := backend.Default()
	if !strings.ContainsAny(raw, " \r\n\t") && (strings.HasPrefix(raw, "https://") || strings.HasPrefix(raw, "http://")) {
		return profile.Subscribe(context.Background(), base, raw, dataDir(path), impl)
	}
	result, err := importer.Import(context.Background(), strings.NewReader(raw), base, impl)
	result.Config.DataDir = ""
	return result, err
}

func listen(port int) (*net.TCPListener, error) {
	return net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
}

func loadConfig(path string) (engine.Config, error) {
	config := engine.Default()
	if path != "" {
		file, err := os.Open(path)
		if err != nil {
			return engine.Config{}, err
		}
		defer file.Close()
		if config, err = engine.Decode(file); err != nil {
			return engine.Config{}, err
		}
	}
	config.DataDir = dataDir(path)
	return config, nil
}

// dataDir keeps caches next to the configuration file.
func dataDir(configPath string) string {
	if configPath != "" {
		return filepath.Join(filepath.Dir(configPath), "cache")
	}
	if dir, err := os.UserCacheDir(); err == nil {
		return filepath.Join(dir, "HopWay")
	}
	return ""
}

func run(path string, port int, check, managed bool) error {
	impl := backend.Default()
	validate := func(config engine.Config) error { return engine.Validate(config, impl) }
	if check {
		loaded, err := profile.Check(path, dataDir(path), validate)
		for _, warning := range loaded.Warnings {
			log.Printf("warning: %s", warning)
		}
		return err
	}
	supervisor, err := app.Open(path, dataDir(path), impl)
	if err != nil {
		return err
	}
	config := supervisor.Config()
	if port != -1 {
		config.SOCKSPort = port
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
	if err := supervisor.Start(sysproxy.Target{HTTP: info.HTTP, SOCKS: info.SOCKS}, ports...); err != nil {
		return err
	}
	defer supervisor.Close()
	serverErrors := make(chan error, 3)
	go func() { serverErrors <- serveSOCKS(socks, supervisor.Dial) }()
	httpServer := &http.Server{
		Handler: httpproxy.Handler(supervisor.Dial), ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 64 << 10,
	}
	go func() { serverErrors <- httpServer.Serve(httpProxy) }()
	log.Printf("SOCKS5 listening on %s", info.SOCKS)
	log.Printf("HTTP proxy listening on %s", info.HTTP)
	if managed {
		server := &http.Server{
			Handler: controlHandler(supervisor, info.Token), ReadTimeout: 5 * time.Second,
			WriteTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8 << 10,
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
	// SIGINT/SIGTERM return normally so deferred cleanup restores the system
	// proxy. A SIGKILL cannot be caught; the next start restores it instead.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		<-signals
		serverErrors <- nil
	}()
	return <-serverErrors
}

func serveSOCKS(listener *net.TCPListener, dial func(context.Context, string, string) (net.Conn, error)) error {
	for {
		client, err := listener.AcceptTCP()
		if err != nil {
			return err
		}
		go func() {
			defer client.Close()
			socks5.Handle(client, dial)
		}()
	}
}

func controlHandler(supervisor *app.Supervisor, token string) http.Handler {
	core := supervisor.Engine // the engine changes on reload; always use the current one
	router := http.NewServeMux()
	router.HandleFunc("GET /status", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		json.NewEncoder(writer).Encode(supervisor.Status())
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
			err = core().SetPolicy(policy)
		}
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	})
	router.HandleFunc("PUT /groups/{name}", func(writer http.ResponseWriter, request *http.Request) {
		var body struct {
			Selected string `json:"selected"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, 4096))
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&body)
		if err == nil {
			err = core().SelectInGroup(request.PathValue("name"), body.Selected)
		}
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	})
	// Probing takes seconds, longer than the control API's write timeout, so
	// it runs in the background and results appear in /status.
	router.HandleFunc("POST /probe", func(writer http.ResponseWriter, request *http.Request) {
		go core().Probe(context.Background(), nil)
		writer.WriteHeader(http.StatusAccepted)
	})
	router.HandleFunc("POST /rulesets/refresh", func(writer http.ResponseWriter, request *http.Request) {
		go core().RefreshRuleSets(context.Background(), true)
		writer.WriteHeader(http.StatusAccepted)
	})
	router.HandleFunc("POST /subscriptions/refresh", func(writer http.ResponseWriter, request *http.Request) {
		go supervisor.RefreshSubscriptions(context.Background(), true)
		writer.WriteHeader(http.StatusAccepted)
	})
	// Reload applies a saved configuration without restarting: open
	// connections stay on the previous engine until they finish.
	router.HandleFunc("POST /reload", func(writer http.ResponseWriter, request *http.Request) {
		if err := supervisor.Reload(); err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, app.ErrPortsChanged) {
				status = http.StatusConflict
			}
			http.Error(writer, err.Error(), status)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	})
	// TUN can wait on the administrator password dialog, longer than the
	// control API's write timeout, so it is applied in the background.
	router.HandleFunc("PUT /tun", func(writer http.ResponseWriter, request *http.Request) {
		var body struct {
			Enabled bool `json:"enabled"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, 1024))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		go supervisor.SetTUN(body.Enabled)
		writer.WriteHeader(http.StatusAccepted)
	})
	router.HandleFunc("PUT /system-proxy", func(writer http.ResponseWriter, request *http.Request) {
		var body struct {
			Enabled bool `json:"enabled"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, 1024))
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&body)
		if err == nil {
			err = supervisor.SetSystemProxy(body.Enabled)
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
