package profile

import (
	"errors"
	"os"
	"time"

	"mac-proxy/internal/engine"
)

// RestoreLastGood puts the last configuration that validated back in place of
// path. The broken file is kept as a timestamped copy, so a recovery step is
// never destructive: the user can look at what the app refused to run.
func RestoreLastGood(path, dataDir string, validate func(engine.Config) error) (string, error) {
	if path == "" || dataDir == "" {
		return "", errors.New("需要配置文件路径和缓存目录")
	}
	document, err := ReadDocument(lastGoodPath(dataDir))
	if err != nil || document.Bytes == nil {
		return "", errors.New("还没有上一次可用的配置")
	}
	if _, err := load(lastGoodPath(dataDir), dataDir, validate, nil); err != nil {
		return "", errors.New("上一次可用的配置也无法通过校验：" + err.Error())
	}

	backup := ""
	if current, err := os.ReadFile(path); err == nil {
		backup = path + ".broken-" + time.Now().Format("20060102-150405")
		if err := os.WriteFile(backup, current, 0o600); err != nil {
			return "", err
		}
	}
	if err := engine.WriteAtomic(path, document.Bytes); err != nil {
		return "", err
	}
	return backup, nil
}
