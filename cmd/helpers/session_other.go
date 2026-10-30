//go:build !unix

package helpers

import (
	"errors"
	"io"
	"os"
)

// readNoFollow reads the regular file at path. Without O_NOFOLLOW, the
// caller's Lstat is the symbolic-link check.
func readNoFollow(path string) ([]byte, error) {
	f, err := os.Open(path)
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
