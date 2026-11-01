//go:build unix

package helpers

import (
	"errors"
	"io"
	"os"
	"syscall"
)

// readNoFollow reads the regular file at path, refusing it if it is a symbolic
// link when opened, so swapping the file for a link after the caller's Lstat
// gains nothing.
func readNoFollow(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	return io.ReadAll(f)
}
