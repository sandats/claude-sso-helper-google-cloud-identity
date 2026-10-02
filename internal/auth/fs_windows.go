//go:build windows

package auth

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

// POSIX owner/mode checks do not apply on Windows; the cache relies on the
// user-profile ACLs, while symlinks and other reparse points are still rejected.

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx   = kernel32.NewProc("LockFileEx")
	procUnlockFileEx = kernel32.NewProc("UnlockFileEx")
)

const (
	lockfileFailImmediately = 0x1
	lockfileExclusiveLock   = 0x2
	errorLockViolation      = syscall.Errno(33)
)

func checkPrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return authErr("Cache directory must be a directory, not a symlink.")
	}
	return nil
}

// openNoFollow opens the reparse point itself (like O_NOFOLLOW); checkCacheFile
// and the lock path then reject anything that is not a regular file.
func openNoFollow(path string, create bool) (*os.File, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	access, disposition := uint32(syscall.GENERIC_READ), uint32(syscall.OPEN_EXISTING)
	if create {
		access, disposition = syscall.GENERIC_READ|syscall.GENERIC_WRITE, syscall.OPEN_ALWAYS
	}
	handle, err := syscall.CreateFile(name, access, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil, disposition, syscall.FILE_ATTRIBUTE_NORMAL|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	file := os.NewFile(uintptr(handle), path)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		return nil, &os.PathError{Op: "open", Path: path, Err: errors.New("not a regular file")}
	}
	return file, nil
}

func checkCacheFile(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return authErr("Token cache must be a regular file.")
	}
	return nil
}

func restrictFile(*os.File) error { return nil }

func tryLock(file *os.File) (bool, error) {
	var overlapped syscall.Overlapped
	r1, _, err := procLockFileEx.Call(file.Fd(), lockfileExclusiveLock|lockfileFailImmediately,
		0, 1, 0, uintptr(unsafe.Pointer(&overlapped)))
	if r1 != 0 {
		return true, nil
	}
	if errors.Is(err, errorLockViolation) {
		return false, nil
	}
	return false, err
}

func unlock(file *os.File) {
	var overlapped syscall.Overlapped
	procUnlockFileEx.Call(file.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&overlapped)))
}
