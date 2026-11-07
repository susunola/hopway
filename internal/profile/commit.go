package profile

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/engine"
	"mac-proxy/internal/importer"
)

const MissingRevision = "missing"

var ErrConfigurationChanged = errors.New("磁盘配置已更新，当前操作未保存")

type Document struct {
	Bytes    []byte
	Revision string
}

func ReadDocument(path string) (Document, error) {
	if path == "" {
		return Document{Revision: MissingRevision}, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Document{Revision: MissingRevision}, nil
	}
	if err != nil {
		return Document{}, err
	}
	return Document{Bytes: data, Revision: revision(data)}, nil
}

func (doc Document) Config() (engine.Config, error) {
	if doc.Bytes == nil {
		return engine.Default(), nil
	}
	return engine.Decode(bytes.NewReader(doc.Bytes))
}

func revision(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func readExpected(path, expected string) (Document, error) {
	if path == "" || expected == "" {
		return Document{}, errors.New("保存配置需要配置路径和原始版本")
	}
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return Document{}, errors.New("配置路径不是普通文件，无法安全替换")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Document{}, err
	}
	doc, err := ReadDocument(path)
	if err == nil && doc.Revision != expected {
		return Document{}, ErrConfigurationChanged
	}
	return doc, err
}

// CommitConfig validates and replaces a profile only if its original bytes
// are still on disk. The same lock protects imported and refreshed snapshots.
func CommitConfig(ctx context.Context, path, dataDir, expected string, data []byte, impl backend.Backend) (string, error) {
	if len(data) > importer.MaxSize {
		return "", errors.New("配置文件上限为 1 MB")
	}
	release, err := LockWrites(dataDir)
	if err != nil {
		return "", err
	}
	defer release()
	if _, err := readExpected(path, expected); err != nil {
		return "", err
	}
	config, err := engine.Decode(bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	validate := func(config engine.Config) error { return engine.Validate(config, impl) }
	if _, err := validateConfig(config, dataDir, validate, "", nil); err != nil {
		return "", err
	}
	return writeDocument(ctx, path, expected, data)
}

type ImportReceipt struct {
	Text     string   `json:"text"`
	Revision string   `json:"revision"`
	Added    int      `json:"added"`
	Skipped  int      `json:"skipped"`
	Notes    []string `json:"notes"`
}

// CommitImport downloads before taking the write lock. It publishes a remote
// snapshot at a new key so the previous config remains readable until rename.
func CommitImport(ctx context.Context, path, dataDir, expected, raw string, impl backend.Backend) (ImportReceipt, error) {
	doc, err := readExpected(path, expected)
	if err != nil {
		return ImportReceipt{}, err
	}
	base, err := doc.Config()
	if err != nil {
		return ImportReceipt{}, err
	}
	base.DataDir = dataDir
	source, _, _, err := importer.SubscriptionLink(raw)
	if err != nil {
		return ImportReceipt{}, err
	}
	var plan *subscriptionImport
	var result importer.Result
	if source != nil {
		plan, err = fetchSubscription(ctx, base, raw, dataDir, impl, false)
		if err == nil {
			result = plan.result
		}
	} else {
		result, err = importer.Import(ctx, strings.NewReader(raw), base, impl)
	}
	if err != nil {
		return ImportReceipt{}, err
	}
	release, err := LockWrites(dataDir)
	if err != nil {
		return ImportReceipt{}, err
	}
	defer release()
	if _, err := readExpected(path, expected); err != nil {
		return ImportReceipt{}, err
	}
	if err := ctx.Err(); err != nil {
		return ImportReceipt{}, err
	}
	var stagedPath string
	if plan != nil {
		if err := plan.prepare(dataDir, impl); err != nil {
			return ImportReceipt{}, err
		}
		stagedPath, err = plan.stage(dataDir)
		if err != nil {
			return ImportReceipt{}, err
		}
		result = plan.result
	} else {
		validate := func(config engine.Config) error { return engine.Validate(config, impl) }
		if _, err := validateConfig(result.Config, dataDir, validate, "", nil); err != nil {
			return ImportReceipt{}, err
		}
	}
	data, err := json.MarshalIndent(result.Config, "", "  ")
	if err == nil && len(data) > importer.MaxSize {
		err = errors.New("导入后的配置文件超过 1 MB")
	}
	var saved string
	if err == nil {
		saved, err = writeDocument(ctx, path, expected, data)
	}
	if err != nil {
		if stagedPath != "" {
			_ = os.Remove(stagedPath)
		}
		return ImportReceipt{}, err
	}
	return ImportReceipt{Text: string(data), Revision: saved, Added: result.Added, Skipped: result.Skipped, Notes: result.Notes}, nil
}

func writeDocument(ctx context.Context, path, expected string, data []byte) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	// An external editor may not take our lock. Recheck after the staged
	// data has been synced, just before replacing the live document.
	if err := engine.WriteAtomicChecked(path, data, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, err := readExpected(path, expected)
		return err
	}); err != nil {
		return "", err
	}
	return revision(data), nil
}

func newSnapshotKey() string {
	var key [16]byte
	rand.Read(key[:])
	return hex.EncodeToString(key[:])
}
