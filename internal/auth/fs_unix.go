//go:build darwin || linux || freebsd || netbsd || openbsd || dragonfly

package auth

import (
	"errors"
	"os"
	"syscall"
)

func checkPrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || !ok || int(st.Uid) != os.Getuid() {
		return authErr("Cache directory must be an owned directory, not a symlink.")
	}
	return os.Chmod(path, 0o700)
}

func openNoFollow(path string, create bool) (*os.File, error) {
	flag := os.O_RDONLY
	if create {
		flag = os.O_CREATE | os.O_RDWR
	}
	return os.OpenFile(path, flag|syscall.O_NOFOLLOW, 0o600)
}

func checkCacheFile(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || !ok || int(st.Uid) != os.Getuid() || info.Mode().Perm()&0o077 != 0 {
		return authErr("Token cache must be an owned regular file with mode 0600.")
	}
	return nil
}

func restrictFile(file *os.File) error { return file.Chmod(0o600) }

func tryLock(file *os.File) (bool, error) {
	err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return false, nil
	}
	return err == nil, err
}

func unlock(file *os.File) { syscall.Flock(int(file.Fd()), syscall.LOCK_UN) }
