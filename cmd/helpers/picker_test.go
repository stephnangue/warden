package helpers

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// keyReader delivers one read per key, as a raw terminal does.
type keyReader struct{ keys []string }

func (r *keyReader) Read(p []byte) (int, error) {
	if len(r.keys) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.keys[0])
	r.keys = r.keys[1:]
	return n, nil
}

var pickItems = []PickItem{
	{Name: "operator", Description: "Day-to-day Warden operations"},
	{Name: "auditor", Description: "Read-only audit and identity views"},
	{Name: "aws-deployer", Description: "Deploy to the prod AWS account", Detail: "aws/"},
}

const (
	keyUp    = "\x1b[A"
	keyDown  = "\x1b[B"
	keyEnter = "\r"
	keyEsc   = "\x1b"
)

func pickKeys(t *testing.T, keys ...string) (int, error, string) {
	t.Helper()
	out := &bytes.Buffer{}
	idx, err := runPicker("Choose a role:", pickItems, &keyReader{keys: keys}, out, 0, 0)
	return idx, err, out.String()
}

func TestPicker(t *testing.T) {
	for name, tc := range map[string]struct {
		keys []string
		want int
		err  error
	}{
		"enter picks the first":                   {[]string{keyEnter}, 0, nil},
		"down then enter":                         {[]string{keyDown, keyEnter}, 1, nil},
		"down wraps":                              {[]string{keyDown, keyDown, keyDown, keyEnter}, 0, nil},
		"up wraps to the last":                    {[]string{keyUp, keyEnter}, 2, nil},
		"application-mode arrows":                 {[]string{"\x1bOB", keyEnter}, 1, nil},
		"typing filters":                          {[]string{"a", "w", "s", keyEnter}, 2, nil},
		"filter on the description":               {[]string{"r", "e", "a", "d", keyEnter}, 1, nil},
		"filter is case-insensitive":              {[]string{"A", "U", "D", keyEnter}, 1, nil},
		"backspace widens the filter":             {[]string{"a", "w", "s", "\x7f", "\x7f", "\x7f", keyDown, keyEnter}, 1, nil},
		"no match: enter does nothing, esc skips": {[]string{"z", "z", keyEnter, keyEsc}, -1, ErrPickSkipped},
		"esc skips":                               {[]string{keyDown, keyEsc}, -1, ErrPickSkipped},
		"ctrl-c interrupts":                       {[]string{"\x03"}, -1, ErrPickInterrupted},
		"input closed":                            {nil, -1, ErrPickSkipped},
		"other keys' sequences ignored":           {[]string{"\x1b[C", "\x1b[3~", keyDown, keyEnter}, 1, nil},
		"several keys in one read":                {[]string{keyDown + keyDown + keyEnter}, 2, nil},
	} {
		idx, err, _ := pickKeys(t, tc.keys...)
		assert.Equal(t, tc.want, idx, name)
		if tc.err != nil {
			assert.ErrorIs(t, err, tc.err, name)
		} else {
			assert.NoError(t, err, name)
		}
	}
}

func TestPicker_Frames(t *testing.T) {
	_, err, out := pickKeys(t, keyDown, keyEnter)
	require.NoError(t, err)
	assert.Contains(t, out, "Choose a role:\r\n")
	assert.Contains(t, out, "> operator", "the first frame highlights the first item")
	assert.Contains(t, out, "> auditor", "the second highlights the next")
	assert.Contains(t, out, "(aws/)", "the detail is shown")
	assert.True(t, strings.HasSuffix(out, "\x1b[J"), "the last frame is cleared on the way out")
	assert.NotContains(t, strings.ReplaceAll(out, "\r\n", ""), "\n", "a raw terminal gets \\r\\n only")

	_, _, out = pickKeys(t, "z", keyEsc)
	assert.Contains(t, out, "(no match)")
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("tty gone") }

func TestPicker_ReadError(t *testing.T) {
	idx, err := runPicker("t", pickItems, failingReader{}, io.Discard, 0, 0)
	assert.Equal(t, -1, idx)
	assert.ErrorContains(t, err, "tty gone")
}

// Alt+key sends ESC and the key in one read: it is not Esc.
func TestPicker_AltKeyIsNotEsc(t *testing.T) {
	idx, err, _ := pickKeys(t, "\x1bx", keyDown, keyEnter)
	require.NoError(t, err)
	assert.Equal(t, 1, idx)
}

// On a short terminal the matches scroll, and every frame is erased by
// exactly the lines it drew.
func TestPicker_Scrolls(t *testing.T) {
	items := make([]PickItem, 10)
	for i := range items {
		items[i] = PickItem{Name: fmt.Sprintf("role-%d", i)}
	}
	out := &bytes.Buffer{}
	keys := []string{}
	for range 7 {
		keys = append(keys, keyDown)
	}
	keys = append(keys, keyEnter)
	idx, err := runPicker("t", items, &keyReader{keys: keys}, out, 80, 6)
	require.NoError(t, err)
	assert.Equal(t, 7, idx)
	frames := strings.Split(out.String(), "\x1b[J")
	last := frames[len(frames)-2] // the frame shown before Enter
	assert.Contains(t, last, "> role-7")
	assert.NotContains(t, last, "role-0", "scrolled past the first")
	assert.Equal(t, 2+3, strings.Count(last, "\r\n"), "header and three match lines fit six rows")
	for _, f := range frames[1:] {
		if f == "" {
			continue
		}
		assert.True(t, strings.HasSuffix(f, "\r\n") || strings.Contains(f, "\x1b["))
	}
}

func TestPicker_TruncatesToWidth(t *testing.T) {
	items := []PickItem{{Name: "operator", Description: strings.Repeat("long description ", 10)}}
	out := &bytes.Buffer{}
	_, err := runPicker("t", items, &keyReader{keys: []string{keyEnter}}, out, 30, 0)
	require.NoError(t, err)
	for _, line := range strings.Split(out.String(), "\r\n") {
		line = line[strings.LastIndex(line, "\x1b[J")+1:]
		assert.Less(t, utf8.RuneCountInString(line), 30, "a line never reaches the last column")
	}
	assert.Contains(t, out.String(), "…")
}

func TestChoiceLine_AlignsByCharacter(t *testing.T) {
	items := []PickItem{{Name: "café", Description: "a"}, {Name: "ops", Description: "b"}}
	w := nameWidth(items, []int{0, 1})
	assert.Equal(t, 4, w)
	assert.Equal(t, "café  a", choiceLine(items[0], w))
	assert.Equal(t, "ops   b", choiceLine(items[1], w))
}

// fakeTerminal replaces the terminal operations for pick, recording whether
// raw mode was restored.
func fakeTerminal(t *testing.T) (restored, exitCode *atomic.Int32) {
	t.Helper()
	restored, exitCode = new(atomic.Int32), new(atomic.Int32)
	exitCode.Store(-1)
	oldRaw, oldSize, oldExit := makeRaw, termSize, exitFunc
	makeRaw = func(int) (func() error, error) { return func() error { restored.Add(1); return nil }, nil }
	termSize = func(int) (int, int, error) { return 80, 24, nil }
	exitFunc = func(code int) { exitCode.Store(int32(code)) }
	t.Cleanup(func() { makeRaw, termSize, exitFunc = oldRaw, oldSize, oldExit })
	return restored, exitCode
}

// pickWith runs pick over a pipe fed keys, the way the terminal feeds it.
func pickWith(t *testing.T, keys string) (int, error) {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	defer r.Close()
	go func() {
		_, _ = w.WriteString(keys)
		w.Close()
	}()
	return pick("t", pickItems, r, io.Discard)
}

// Raw mode is restored on every way out of the picker.
func TestPick_RestoresTerminal(t *testing.T) {
	for name, keys := range map[string]string{
		"enter":        keyEnter,
		"esc":          keyEsc,
		"ctrl-c":       "\x03",
		"input closed": "",
	} {
		restored, _ := fakeTerminal(t)
		_, _ = pickWith(t, keys)
		assert.GreaterOrEqual(t, restored.Load(), int32(1), name)
	}

	restored, _ := fakeTerminal(t)
	makeRaw = func(int) (func() error, error) { return nil, errors.New("not a terminal") }
	_, err := pickWith(t, keyEnter)
	assert.ErrorContains(t, err, "cannot use the terminal")
	assert.Zero(t, restored.Load())
}
