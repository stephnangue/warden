package helpers

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"

	"github.com/mattn/go-isatty"
	"golang.org/x/term"
)

// PickItem is one choice of the picker.
type PickItem struct {
	Name        string
	Description string
	Detail      string // shown in parentheses, e.g. the provider a role is used with
}

var (
	// ErrPickSkipped: the user pressed Esc.
	ErrPickSkipped = errors.New("nothing selected")
	// ErrPickInterrupted: the user pressed Ctrl-C.
	ErrPickInterrupted = errors.New("interrupted")
)

// Interactive reports whether the picker can run: stdin and stderr (where it
// draws) are both terminals. Scripts and CI get a list instead, never a
// prompt. Tests replace it.
var Interactive = func() bool {
	return isTerminal(os.Stdin.Fd()) && isTerminal(os.Stderr.Fd())
}

func isTerminal(fd uintptr) bool {
	return isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)
}

// The terminal operations Pick uses; tests replace them.
var (
	makeRaw = func(fd int) (func() error, error) {
		old, err := term.MakeRaw(fd)
		if err != nil {
			return nil, err
		}
		return func() error { return term.Restore(fd, old) }, nil
	}
	termSize = term.GetSize
	exitFunc = os.Exit
)

// Pick lets the user choose one of items on the terminal (arrows to move,
// typing to filter, Enter to select, Esc to skip) and returns its index. The
// terminal is put in raw mode and restored on every way out: a choice, Esc,
// Ctrl-C, an error, a panic, and a SIGINT, SIGTERM or SIGHUP from outside,
// which raw mode does not turn into input (the process then exits with 128
// plus the signal's number, as a shell reports it).
func Pick(title string, items []PickItem) (int, error) {
	return pick(title, items, os.Stdin, os.Stderr)
}

func pick(title string, items []PickItem, in *os.File, out io.Writer) (int, error) {
	fd := int(in.Fd())
	restore, err := makeRaw(fd)
	if err != nil {
		return -1, fmt.Errorf("cannot use the terminal: %w", err)
	}
	defer func() { _ = restore() }()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	done := make(chan struct{})
	defer func() {
		signal.Stop(sig)
		close(done)
	}()
	go func() {
		select {
		case s := <-sig:
			_ = restore()
			code := 1
			if n, ok := s.(syscall.Signal); ok {
				code = 128 + int(n)
			}
			exitFunc(code)
		case <-done:
		}
	}()

	width, height, err := termSize(fd)
	if err != nil {
		width, height = 0, 0
	}
	return runPicker(title, items, in, out, width, height)
}

// picker is the picker's state: the filter typed so far, the highlighted line
// among the items it matches, and the window of them shown.
type picker struct {
	title   string
	items   []PickItem
	filter  []rune
	matches []int // indexes into items
	cursor  int   // index into matches
	top     int   // first match shown
	width   int   // terminal columns; 0 is unknown
	rows    int   // match lines that fit; 0 is unlimited
	drawn   int   // lines the last frame took
}

// pickerHeaderLines are the lines above the matches: the title and the
// filter.
const pickerHeaderLines = 2

// runPicker runs the picker reading keys from in and drawing frames on out,
// as a raw terminal delivers and shows them, on a terminal of width columns
// and height rows (0 when unknown). Lines are cut to the width and the matches
// scroll within the height, so every frame is erased exactly.
func runPicker(title string, items []PickItem, in io.Reader, out io.Writer, width, height int) (int, error) {
	p := &picker{title: title, items: items, width: width}
	if height > 0 {
		p.rows = max(1, height-pickerHeaderLines-1)
	}
	p.refilter()
	p.draw(out)
	buf := make([]byte, 64)
	for {
		n, err := in.Read(buf)
		if n > 0 {
			if idx, end, perr := p.keys(buf[:n]); end {
				p.clear(out)
				return idx, perr
			}
			p.draw(out)
		}
		if err != nil {
			p.clear(out)
			if errors.Is(err, io.EOF) {
				return -1, ErrPickSkipped
			}
			return -1, err
		}
	}
}

// keys applies the keys in b, one read's worth. It reports end when one of
// them ends the picker, with the chosen index or why none was. A lone ESC is
// Esc; ESC followed by more bytes of the same read is a key's sequence (an
// arrow, Alt+key) and never Esc.
func (p *picker) keys(b []byte) (int, bool, error) {
	for len(b) > 0 {
		switch {
		case hasPrefix(b, "\x1b[A"), hasPrefix(b, "\x1bOA"):
			p.move(-1)
			b = b[3:]
		case hasPrefix(b, "\x1b[B"), hasPrefix(b, "\x1bOB"):
			p.move(1)
			b = b[3:]
		case hasPrefix(b, "\x1b["), hasPrefix(b, "\x1bO"):
			b = skipEscape(b) // another key's sequence: ignored
		case b[0] == 0x1b && len(b) > 1:
			_, size := utf8.DecodeRune(b[1:]) // Alt+key: ignored
			b = b[1+size:]
		case b[0] == 0x1b:
			return -1, true, ErrPickSkipped
		case b[0] == 0x03:
			return -1, true, ErrPickInterrupted
		case b[0] == '\r', b[0] == '\n':
			if len(p.matches) > 0 {
				return p.matches[p.cursor], true, nil
			}
			b = b[1:]
		case b[0] == 0x7f, b[0] == 0x08:
			if len(p.filter) > 0 {
				p.filter = p.filter[:len(p.filter)-1]
				p.refilter()
			}
			b = b[1:]
		default:
			r, size := utf8.DecodeRune(b)
			if unicode.IsPrint(r) {
				p.filter = append(p.filter, r)
				p.refilter()
			}
			b = b[size:]
		}
	}
	return -1, false, nil
}

func hasPrefix(b []byte, s string) bool { return strings.HasPrefix(string(b), s) }

// skipEscape drops a CSI or SS3 sequence: ESC, '[' or 'O', parameters, and a
// final byte in 0x40-0x7e.
func skipEscape(b []byte) []byte {
	for i := 2; i < len(b); i++ {
		if b[i] >= 0x40 && b[i] <= 0x7e {
			return b[i+1:]
		}
	}
	return nil
}

func (p *picker) move(d int) {
	if len(p.matches) == 0 {
		return
	}
	p.cursor = (p.cursor + d + len(p.matches)) % len(p.matches)
	p.scroll()
}

// scroll keeps the highlighted match inside the window shown.
func (p *picker) scroll() {
	if p.rows == 0 {
		p.top = 0
		return
	}
	if p.cursor < p.top {
		p.top = p.cursor
	}
	if p.cursor >= p.top+p.rows {
		p.top = p.cursor - p.rows + 1
	}
}

// refilter keeps the items whose name or description contains the filter,
// case-insensitively, and puts the highlight on the first.
func (p *picker) refilter() {
	f := strings.ToLower(string(p.filter))
	p.matches = p.matches[:0]
	for i, it := range p.items {
		if f == "" || strings.Contains(strings.ToLower(it.Name+" "+it.Description), f) {
			p.matches = append(p.matches, i)
		}
	}
	p.cursor, p.top = 0, 0
}

// draw replaces the last frame with the current one. A raw terminal needs
// "\r\n" to start a line.
func (p *picker) draw(out io.Writer) {
	p.clear(out)
	var lines []string
	lines = append(lines, p.title, "  filter: "+string(p.filter))
	shown := p.matches
	if p.rows > 0 && len(shown) > p.rows {
		shown = shown[p.top : p.top+p.rows]
	}
	if len(p.matches) == 0 {
		lines = append(lines, "    (no match)")
	}
	width := nameWidth(p.items, p.matches)
	for j, i := range shown {
		marker := "  "
		if p.top+j == p.cursor {
			marker = "> "
		}
		lines = append(lines, "  "+marker+choiceLine(p.items[i], width))
	}
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(truncate(l, p.width) + "\r\n")
	}
	_, _ = io.WriteString(out, b.String())
	p.drawn = len(lines)
}

// clear erases the last frame.
func (p *picker) clear(out io.Writer) {
	if p.drawn > 0 {
		fmt.Fprintf(out, "\x1b[%dA\r\x1b[J", p.drawn)
		p.drawn = 0
	}
}

// nameWidth is the widest name, in characters, among items at idx.
func nameWidth(items []PickItem, idx []int) int {
	w := 0
	for _, i := range idx {
		w = max(w, utf8.RuneCountInString(items[i].Name))
	}
	return w
}

// choiceLine renders an item with its name padded to width characters.
func choiceLine(it PickItem, width int) string {
	line := it.Name + strings.Repeat(" ", width-utf8.RuneCountInString(it.Name)) + "  " + it.Description
	if it.Detail != "" {
		line += "  (" + it.Detail + ")"
	}
	return strings.TrimRight(line, " ")
}

// truncate cuts s to fit in width columns (one per character), leaving the
// last column free so the terminal never wraps; 0 is unlimited.
func truncate(s string, width int) string {
	if width <= 1 || utf8.RuneCountInString(s) < width {
		return s
	}
	r := []rune(s)
	return string(r[:width-2]) + "…"
}

// PrintChoices lists items on stderr, one per line, as the picker shows them,
// for a caller without a terminal. stdout stays clean for the command's own
// output.
func PrintChoices(items []PickItem) {
	idx := make([]int, len(items))
	for i := range items {
		idx[i] = i
	}
	width := nameWidth(items, idx)
	for _, it := range items {
		fmt.Fprintln(errWriter, "  "+choiceLine(it, width))
	}
}
