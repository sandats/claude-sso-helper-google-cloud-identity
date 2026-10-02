package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// Lock waits; replaceable in tests.
var (
	LockTimeout          = 35 * time.Second
	AutoLoginLockTimeout = 300 * time.Second
	lockPollInterval     = 100 * time.Millisecond
)

// Record is the on-disk token cache. Opaque Google API access tokens are
// deliberately neither stored nor emitted.
type Record struct {
	IDToken      string  `json:"id_token"`
	RefreshToken string  `json:"refresh_token"`
	Sub          string  `json:"sub"`
	ExpiresAt    float64 `json:"expires_at"`
}

func cacheFile(cfg *Config) string { return filepath.Join(cfg.CacheDir, "tokens.json") }

func privateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	return checkPrivateDirectory(path)
}

// WithCacheLock runs fn while holding the per-configuration cache lock.
func WithCacheLock(ctx context.Context, cfg *Config, timeout time.Duration, fn func() error) error {
	if err := privateDirectory(filepath.Dir(cfg.CacheDir)); err != nil {
		return err
	}
	if err := privateDirectory(cfg.CacheDir); err != nil {
		return err
	}
	lock, err := openNoFollow(filepath.Join(cfg.CacheDir, "auth.lock"), true)
	if err != nil {
		return err
	}
	defer lock.Close()
	deadline := time.Now().Add(timeout)
	for {
		acquired, err := tryLock(lock)
		if err != nil {
			return err
		}
		if acquired {
			break
		}
		if !time.Now().Before(deadline) {
			return authErr("Another helper/login is running; retry after it completes.")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(lockPollInterval):
		}
	}
	defer unlock(lock)
	return fn()
}

// readCache returns the cached JSON object, or an empty map when no cache exists.
func readCache(cfg *Config) (map[string]any, error) {
	file, err := openNoFollow(cacheFile(cfg), false)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]any{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if err := checkCacheFile(file); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	var value map[string]any
	if json.Unmarshal(raw, &value) != nil || value == nil {
		return nil, authErr("Invalid token cache; run login to replace it.")
	}
	return value, nil
}

func writeCache(cfg *Config, record Record) (err error) {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(cfg.CacheDir, ".tokens-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() {
		if _, statErr := os.Lstat(name); statErr == nil {
			os.Remove(name)
		}
	}()
	if err := restrictFile(tmp); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, cacheFile(cfg))
}

func removeCache(cfg *Config) error {
	err := os.Remove(cacheFile(cfg))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}
