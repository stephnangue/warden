//go:build unix

package helpers

import (
	"io"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A signal from outside restores the terminal and exits with 128 plus its
// number.
func TestPick_SignalRestoresAndExits(t *testing.T) {
	restored, exitCode := fakeTerminal(t)
	r, w, err := os.Pipe()
	require.NoError(t, err)
	defer r.Close()
	done := make(chan struct{})
	go func() {
		_, _ = pick("t", pickItems, r, io.Discard)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond) // let pick register for signals
	require.NoError(t, syscall.Kill(os.Getpid(), syscall.SIGHUP))
	require.Eventually(t, func() bool { return exitCode.Load() == int32(128+int(syscall.SIGHUP)) }, 2*time.Second, 10*time.Millisecond)
	assert.GreaterOrEqual(t, restored.Load(), int32(1))
	w.Close()
	<-done
}
