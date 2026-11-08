package importer

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/engine"
)

const providerFixture = `
proxies:
  - {name: Air 01, type: socks5, server: air-01.example.test, port: 1080}
  - {name: Air 02, type: socks5, server: air-02.example.test, port: 1080, username: u, password: p}
`

func providerProfile(url string) string {
	return fmt.Sprintf(`
proxy-providers:
  air:
    type: http
    url: %s
    interval: 3600
proxy-groups:
  - {name: Auto, type: url-test, use: [air]}
rules:
  - MATCH,Auto
`, url)
}

func TestImportRemoteProxyProviders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Write([]byte(providerFixture))
	}))
	defer server.Close()

	config := engine.Default()
	config.DataDir = t.TempDir()
	result, err := Import(context.Background(), strings.NewReader(providerProfile(server.URL+"/air.yaml")), config, backend.Native{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Added != 2 {
		t.Fatalf("imported %d nodes, want 2: %+v", result.Added, result.Notes)
	}
	names := []string{result.Config.Nodes[0].Name, result.Config.Nodes[1].Name}
	if names[0] != "Air 01" || names[1] != "Air 02" {
		t.Fatalf("unexpected node names %v", names)
	}
	if len(result.Config.Groups) != 1 || result.Config.Groups[0].Name != "Auto" {
		t.Fatalf("unexpected groups %+v", result.Config.Groups)
	}
	members := result.Config.Groups[0].Members
	if len(members) != 2 || members[0] != "Air 01" || members[1] != "Air 02" {
		t.Fatalf("group members %v do not come from the provider", members)
	}
	// The provider document must be cached next to the profile.
	if _, err := os.Stat(providerCachePath(result.Config.DataDir, server.URL+"/air.yaml")); err != nil {
		t.Fatalf("provider was not cached: %v", err)
	}
}

func TestImportRemoteProxyProvidersUsesCacheOffline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Write([]byte(providerFixture))
	}))
	url := server.URL + "/air.yaml"
	config := engine.Default()
	config.DataDir = t.TempDir()
	if _, err := Import(context.Background(), strings.NewReader(providerProfile(url)), config, backend.Native{}); err != nil {
		t.Fatal(err)
	}
	server.Close() // the next import must fall back to the cached document

	result, err := Import(context.Background(), strings.NewReader(providerProfile(url)), config, backend.Native{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Added != 2 {
		t.Fatalf("offline import added %d nodes, want the 2 cached ones: %+v", result.Added, result.Notes)
	}
	found := false
	for _, note := range result.Notes {
		if strings.Contains(note, "缓存") {
			found = true
		}
	}
	if !found {
		t.Fatalf("offline import did not say it used the cache: %v", result.Notes)
	}
}

func TestImportProxyProviderWithoutURLIsSkipped(t *testing.T) {
	config := engine.Default()
	config.DataDir = t.TempDir()
	profile := `
proxy-providers:
  broken:
    type: http
proxy-groups:
  - {name: Auto, type: select, use: [broken]}
rules:
  - MATCH,Auto
`
	result, err := Import(context.Background(), strings.NewReader(profile), config, backend.Native{})
	if err == nil {
		t.Fatalf("a profile with no usable nodes must fail, got %+v", result.Config)
	}
}
