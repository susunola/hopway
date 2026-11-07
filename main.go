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
	"runtime/debug"
	"strconv"
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
	inspect := flag.Bool("inspect", false, "print the effective configuration's node and subscription summaries")
	probe := flag.Bool("probe", false, "measure latency through configured nodes")
	var probeNames []string
	flag.Func("probe-node", "probe only this node (repeatable)", func(name string) error { probeNames = append(probeNames, name); return nil })
	refreshID := flag.String("subscription-id", "", "refresh only this subscription")
	refresh := flag.Bool("refresh-subscriptions", false, "refresh saved subscriptions without starting the proxy")
	previewImport := flag.Bool("preview-import", false, "preview a subscription or profile from stdin without writing it")
	importInput := flag.Bool("import", false, "read a subscription URL or profile from stdin and print converted JSON")
	commitImport := flag.Bool("commit-import", false, "import from stdin and atomically update the configuration")
	saveConfig := flag.Bool("save-config", false, "validate and atomically replace the configuration with JSON from stdin")
	expectedRevision := flag.String("expected-revision", "", "original configuration SHA-256, or missing for a new file")
	tunHelper := flag.String("tun-helper", "", "internal: create the TUN device as root and hand it to the core over this socket")
	tunIPv6 := flag.Bool("tun-ipv6", false, "internal: give the helper's TUN device an IPv6 address and route")
	tunMTU := flag.Uint("tun-mtu", 0, "internal: MTU for the helper's TUN device")
	tunService := flag.Int("tun-service", -1, "internal: run the installed TUN service for this uid")
	tunInstall := flag.Int("tun-install", -1, "internal: install the TUN service for this uid (root)")
	tunUninstall := flag.Bool("tun-uninstall", false, "internal: remove the TUN service (root)")
	flag.Parse()
	if *tunService >= 0 || *tunInstall >= 0 || *tunUninstall {
		var err error
		switch {
		case *tunService >= 0:
			err = tun.RunService(tun.ServiceSocket, uint32(*tunService), tun.CreateDevice)
		case *tunInstall >= 0:
			executable, _ := os.Executable()
			err = tun.InstallService(executable, uint32(*tunInstall))
		default:
			err = tun.UninstallService()
		}
		if err != nil {
			log.SetFlags(0)
			log.Fatal(err)
		}
		return
	}
	if *tunHelper != "" {
		if *tunMTU > 65535 {
			log.Fatal("invalid TUN MTU")
		}
		if err := tun.RunHelper(*tunHelper, tun.Options{IPv6: *tunIPv6, MTU: uint32(*tunMTU)}); err != nil {
			log.SetFlags(0)
			log.Fatal(err)
		}
		return
	}
	if *inspect || *probe || *refresh {
		if err := inspectProfile(*path, *inspect, *probe, *refresh, probeNames, *refreshID); err != nil {
			log.SetFlags(0)
			log.Fatal(err)
		}
		return
	}
	if *saveConfig || *commitImport {
		err := writeProfile(*path, *expectedRevision, *commitImport)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			if errors.Is(err, profile.ErrConfigurationChanged) {
				os.Exit(3)
			}
			os.Exit(1)
		}
		return
	}
	if *importInput || *previewImport {
		result, err := runImport(*path, *previewImport)
		if err == nil {
			if *previewImport {
				if result.Notes == nil {
					result.Notes = []string{}
				}
				err = json.NewEncoder(os.Stdout).Encode(struct {
					Added   int      `json:"added"`
					Skipped int      `json:"skipped"`
					Notes   []string `json:"notes"`
				}{Added: result.Added, Skipped: result.Skipped, Notes: result.Notes})
			} else {
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

func writeProfile(path, expected string, importing bool) error {
	data, err := readProfileInput(os.Stdin)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	output := json.NewEncoder(os.Stdout)
	if importing {
		raw := strings.TrimSpace(strings.TrimPrefix(string(data), "\ufeff"))
		result, err := profile.CommitImport(ctx, path, dataDir(path), expected, raw, backend.Default())
		if err != nil {
			return err
		}
		return output.Encode(result)
	}
	revision, err := profile.CommitConfig(ctx, path, dataDir(path), expected, data, backend.Default())
	if err != nil {
		return err
	}
	return output.Encode(map[string]string{"revision": revision})
}

func readProfileInput(input io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(input, importer.MaxSize+1))
	if err == nil && len(data) > importer.MaxSize {
		err = errors.New("输入超过 1 MB")
	}
	return data, err
}

// runImport converts pasted input. A subscription URL becomes a subscription
// entry (its nodes are cached and refreshed automatically); anything else is
// merged into the configuration as before.
func runImport(path string, preview bool) (importer.Result, error) {
	base, err := loadConfig(path)
	if errors.Is(err, os.ErrNotExist) {
		base, err = engine.Default(), nil
	}
	if err != nil {
		return importer.Result{}, err
	}
	data, err := readProfileInput(os.Stdin)
	if err != nil {
		return importer.Result{}, err
	}
	raw := strings.TrimSpace(strings.TrimPrefix(string(data), "\ufeff"))
	impl := backend.Default()
	source, _, _, err := importer.SubscriptionLink(raw)
	if err != nil {
		return importer.Result{}, err
	}
	if source != nil {
		if preview {
			return profile.PreviewSubscription(context.Background(), base, raw, dataDir(path), impl)
		}
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
	// Return normally on signals so deferred cleanup can restore the network.
	signals, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stopSignals()
	supervisor, err := app.Open(path, dataDir(path), impl)
	if err != nil {
		return err
	}
	defer supervisor.Close()
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
	if signals.Err() != nil {
		return nil
	}
	serverErrors := make(chan error, 4)
	go func() { serverErrors <- serveSOCKS(socks, supervisor.Dial, supervisor.DialPacket) }()
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
	select {
	case <-signals.Done():
		return nil
	case err := <-serverErrors:
		return err
	}
}

func serveSOCKS(listener *net.TCPListener, dial socks5.DialFunc, dialPacket socks5.DialPacketFunc) error {
	for {
		client, err := listener.AcceptTCP()
		if err != nil {
			return err
		}
		go func() {
			defer client.Close()
			socks5.HandleWithUDP(client, dial, dialPacket)
		}()
	}
}

func controlHandler(supervisor *app.Supervisor, token string) http.Handler {
	core := supervisor.Engine // the engine changes on reload; always use the current one
	router := http.NewServeMux()
	router.HandleFunc("GET /status", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if request.URL.Query().Get("view") == "compact" {
			json.NewEncoder(writer).Encode(supervisor.CompactStatus())
			return
		}
		json.NewEncoder(writer).Encode(supervisor.Status())
	})
	router.HandleFunc("GET /connections", func(writer http.ResponseWriter, request *http.Request) {
		query := request.URL.Query()
		var generation uint64
		var cursor *uint64
		if query.Has("generation") || query.Has("cursor") {
			g, generationErr := strconv.ParseUint(query.Get("generation"), 10, 64)
			c, cursorErr := strconv.ParseUint(query.Get("cursor"), 10, 64)
			if generationErr != nil || cursorErr != nil {
				http.Error(writer, "invalid connection cursor", http.StatusBadRequest)
				return
			}
			generation, cursor = g, &c
		}
		writer.Header().Set("Content-Type", "application/json")
		json.NewEncoder(writer).Encode(supervisor.Connections(generation, cursor))
	})
	router.HandleFunc("GET /route", func(writer http.ResponseWriter, request *http.Request) {
		decision, err := core().ExplainContext(request.Context(), request.URL.Query().Get("target"))
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		json.NewEncoder(writer).Encode(decision)
	})
	router.HandleFunc("POST /verify", func(writer http.ResponseWriter, request *http.Request) {
		transport := &http.Transport{
			DialContext: func(_ context.Context, _, address string) (net.Conn, error) {
				return supervisor.Dial(request.Context(), "verification", address)
			},
			DisableKeepAlives: true,
		}
		defer transport.CloseIdleConnections()
		client := http.Client{Transport: transport, Timeout: 6 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
		probe, err := http.NewRequestWithContext(request.Context(), http.MethodGet, "https://www.gstatic.com/generate_204", nil)
		if err != nil {
			http.Error(writer, "无法创建联网验证请求", http.StatusInternalServerError)
			return
		}
		response, err := client.Do(probe)
		if err != nil {
			http.Error(writer, "当前路由无法访问测试地址", http.StatusBadGateway)
			return
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			http.Error(writer, fmt.Sprintf("测试地址返回 HTTP %d", response.StatusCode), http.StatusBadGateway)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	})
	router.HandleFunc("PUT /policy", func(writer http.ResponseWriter, request *http.Request) {
		var policy engine.Policy
		decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, 64<<10))
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&policy)
		if err == nil && decoder.Decode(new(any)) != io.EOF {
			err = errors.New("expected one policy object")
		}
		if err == nil {
			err = supervisor.SetPolicy(policy)
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
	router.HandleFunc("POST /probe/stream", func(writer http.ResponseWriter, request *http.Request) {
		var body struct {
			Names []string `json:"names"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, 1<<20))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil || len(body.Names) > 4096 {
			http.Error(writer, "invalid probe batch", http.StatusBadRequest)
			return
		}
		controller := http.NewResponseController(writer)
		writer.Header().Set("Content-Type", "application/x-ndjson")
		encoder := json.NewEncoder(writer)
		flush := func(write func() error) error {
			if err := controller.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
				return err
			}
			if write != nil {
				if err := write(); err != nil {
					return err
				}
			}
			if err := controller.Flush(); err != nil {
				return err
			}
			// Measurement may take longer than the control server's normal
			// write deadline. Limit each actual write independently.
			return controller.SetWriteDeadline(time.Time{})
		}
		if err := flush(nil); err != nil {
			return
		}
		ctx, cancel := context.WithCancel(request.Context())
		defer cancel()
		results := make(chan engine.ProbeResult)
		current := core()
		go func() {
			defer close(results)
			_ = current.ProbeResults(ctx, body.Names, func(result engine.ProbeResult) error {
				select {
				case results <- result:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			})
		}()
		heartbeat := time.NewTicker(4 * time.Second)
		defer heartbeat.Stop()
		for {
			select {
			case result, ok := <-results:
				if !ok || flush(func() error { return encoder.Encode(result) }) != nil {
					return
				}
			case <-heartbeat.C:
				// A whole batch may be waiting on shared-outage detection.
				if flush(func() error { _, err := io.WriteString(writer, "\n"); return err }) != nil {
					return
				}
			case <-ctx.Done():
				return
			}
		}
	})
	router.HandleFunc("POST /rulesets/refresh", func(writer http.ResponseWriter, request *http.Request) {
		go core().RefreshRuleSets(context.Background(), true)
		writer.WriteHeader(http.StatusAccepted)
	})
	router.HandleFunc("POST /subscriptions/refresh", func(writer http.ResponseWriter, request *http.Request) {
		go supervisor.RefreshSubscriptions(context.Background(), true)
		writer.WriteHeader(http.StatusAccepted)
	})
	router.HandleFunc("POST /subscriptions/{id}/refresh", func(writer http.ResponseWriter, request *http.Request) {
		id := request.PathValue("id")
		go supervisor.RefreshSubscription(context.Background(), id)
		writer.WriteHeader(http.StatusAccepted)
	})
	// Reload applies a saved configuration without restarting: open
	// connections stay on the previous engine until they finish.
	router.HandleFunc("POST /reload", func(writer http.ResponseWriter, request *http.Request) {
		if err := supervisor.ReloadRevision(request.Header.Get("X-HopWay-Revision")); err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, app.ErrPortsChanged) || errors.Is(err, profile.ErrConfigurationChanged) {
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
		if err := supervisor.StartTUNChange(body.Enabled); err != nil {
			http.Error(writer, err.Error(), http.StatusConflict)
			return
		}
		writer.WriteHeader(http.StatusAccepted)
	})
	router.HandleFunc("PUT /tun-service", func(writer http.ResponseWriter, request *http.Request) {
		var body struct {
			Installed bool `json:"installed"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, 1024))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		if err := supervisor.StartTUNServiceChange(body.Installed); err != nil {
			http.Error(writer, err.Error(), http.StatusConflict)
			return
		}
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

func inspectProfile(path string, inspect, probe, refresh bool, names []string, refreshID string) error {
	impl := backend.Default()
	validate := func(config engine.Config) error { return engine.Validate(config, impl) }
	dir := dataDir(path)
	loaded, err := profile.Check(path, dir, validate)
	if err != nil {
		return err
	}
	output := json.NewEncoder(os.Stdout)
	if refresh {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		updated, failed := 0, 0
		for _, sub := range loaded.User.Subscriptions {
			if sub.Paused || (refreshID != "" && sub.Key() != refreshID) {
				continue
			}
			_, err := profile.RefreshSnapshot(ctx, loaded.User, sub, path, dir, impl, nil)
			if err != nil {
				failed++
			} else {
				updated++
			}
		}
		return output.Encode(map[string]int{"updated": updated, "failed": failed})
	}
	if inspect {
		type summary struct {
			Nodes          []engine.NodeSummary  `json:"nodes"`
			Subs           []engine.Subscription `json:"subscriptions"`
			Groups         []engine.Group        `json:"groups,omitempty"`
			RuleSets       []string              `json:"ruleSets,omitempty"`
			RuleCount      int                   `json:"ruleCount"`
			Mode           string                `json:"mode"`
			Selected       string                `json:"selected"`
			Backend        string                `json:"backend"`
			BackendVersion string                `json:"backendVersion,omitempty"`
			SOCKSPort      int                   `json:"socksPort"`
			HTTPPort       int                   `json:"httpPort"`
			SystemProxy    bool                  `json:"systemProxy"`
			TUNEnabled     bool                  `json:"tunEnabled"`
			SnapshotAt     map[string]int64      `json:"snapshotAt,omitempty"`
			Revision       string                `json:"revision"`
		}
		config := loaded.Merged
		result := summary{
			Subs: config.Subscriptions, Groups: config.Groups, RuleCount: len(config.Rules),
			Mode: config.Mode, Selected: config.Selected, Backend: impl.Name(), SnapshotAt: loaded.SnapshotUpdated, Revision: loaded.Revision,
			SOCKSPort: config.SOCKSPort, HTTPPort: config.HTTPPort,
			SystemProxy: config.SystemProxy, TUNEnabled: config.TUN != nil && config.TUN.Enabled,
		}
		if build, ok := debug.ReadBuildInfo(); ok && impl.Name() == "sing-box" {
			for _, dep := range build.Deps {
				if dep.Path == "github.com/sagernet/sing-box" {
					result.BackendVersion = dep.Version
					break
				}
			}
		}
		for _, set := range config.RuleSets {
			result.RuleSets = append(result.RuleSets, set.Name)
		}
		for i := range result.Subs {
			result.Subs[i].ID = result.Subs[i].Key()
			result.Subs[i].URL = ""
		}
		for _, node := range loaded.Merged.Nodes {
			result.Nodes = append(result.Nodes, engine.NodeSummary{Name: node.Name, Type: node.Type})
		}
		return output.Encode(result)
	}
	if probe {
		core, err := engine.New(loaded.Merged, impl)
		if err != nil {
			return err
		}
		defer core.Close()
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return core.ProbeResults(ctx, names, func(result engine.ProbeResult) error { return output.Encode(result) })
	}
	return nil
}
