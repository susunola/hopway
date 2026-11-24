package importer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"sort"

	"go.yaml.in/yaml/v3"

	"mac-proxy/internal/engine"
	"mac-proxy/internal/outbound"
)

// Remote proxy-providers: a Clash profile may keep every node in a separate
// file and only reference it from proxy-groups with "use". Without this the
// import ends up with a group that has no members, so the provider is fetched
// (and cached, so a restart offline still works) before the groups are built.

const (
	providerMaxSize = 8 << 20
	providerDir     = "providers"
)

type providerDocument struct {
	Proxies []yaml.Node `yaml:"proxies"`
}

// providerCachePath is shared by every import that uses the same URL.
func providerCachePath(dataDir, source string) string {
	if dataDir == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(source))
	return filepath.Join(dataDir, providerDir, hex.EncodeToString(sum[:8])+".yaml")
}

// importProviders downloads every http proxy-provider, adds its nodes to the
// result and returns provider name -> final node names for group expansion.
func (result *Result) importProviders(ctx context.Context, providers map[string]clashProvider, options Options) map[string][]string {
	if len(providers) == 0 {
		return nil
	}
	names := make([]string, 0, len(providers))
	for name := range providers {
		names = append(names, name)
	}
	sort.Strings(names) // deterministic node order and notes
	nodes := make(map[string][]string, len(providers))
	for _, name := range names {
		provider := providers[name]
		if provider.Type != "" && provider.Type != "http" {
			result.Notes = append(result.Notes, "远程节点集「"+name+"」的类型 "+provider.Type+" 不受支持，已跳过")
			continue
		}
		source, err := url.Parse(provider.URL)
		if err != nil || source.Hostname() == "" || (source.Scheme != "https" && source.Scheme != "http") {
			result.Notes = append(result.Notes, "远程节点集「"+name+"」的地址无效，已跳过")
			continue
		}
		body, cached, err := result.fetchProvider(ctx, name, source, provider, options)
		if err != nil {
			result.Notes = append(result.Notes, "远程节点集「"+name+"」下载失败："+err.Error())
			continue
		}
		added := result.importProviderNodes(name, body)
		if len(added) == 0 {
			result.Notes = append(result.Notes, "远程节点集「"+name+"」没有可导入的节点")
			continue
		}
		nodes[name] = added
		if cached {
			result.Notes = append(result.Notes, "远程节点集「"+name+"」下载失败，使用上次缓存")
		}
	}
	return nodes
}

func (result *Result) fetchProvider(ctx context.Context, name string, source *url.URL, provider clashProvider, options Options) ([]byte, bool, error) {
	fetched, err := fetch(ctx, source, options)
	if err == nil {
		body := fetched.body
		if len(body) > providerMaxSize {
			return nil, false, errors.New("节点集超过 8 MB")
		}
		if path := providerCachePath(result.Config.DataDir, source.String()); path != "" {
			_ = engine.WriteAtomic(path, body) // best effort: a cache miss only costs a download
		}
		return body, false, nil
	}
	path := providerCachePath(result.Config.DataDir, source.String())
	if path == "" {
		return nil, false, err
	}
	body, cacheErr := os.ReadFile(path)
	if cacheErr != nil {
		return nil, false, err
	}
	return body, true, nil
}

// importProviderNodes converts the provider document and remembers which final
// name each node ended up with, so a group's "use" can point at them.
func (result *Result) importProviderNodes(provider string, body []byte) []string {
	raw, err := importText(body)
	if err != nil {
		return nil
	}
	var document providerDocument
	if err := yaml.Unmarshal([]byte(raw), &document); err != nil || len(document.Proxies) == 0 {
		return nil
	}
	var added []string
	for _, entry := range document.Proxies {
		var proxy clashNode
		if err := entry.Decode(&proxy); err != nil {
			result.add(outbound.Node{Name: "远程节点集 " + provider}, errors.New("Clash 节点字段格式无效"))
			continue
		}
		node, err := proxy.convert()
		node.Name = proxy.Name
		result.addNamed(proxy.Name, node, err)
		if final, ok := result.renamed[proxy.Name]; ok && !containsString(added, final) {
			added = append(added, final)
		}
	}
	return added
}

func containsString(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}
