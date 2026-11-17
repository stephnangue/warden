package audit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FileSink writes audit logs to a file
type FileSink struct {
	mu     sync.Mutex
	path   string
	file   *os.File
	mode   os.FileMode
	writer io.Writer

	// Rotation settings
	rotateSize  int64
	rotateDaily bool
	maxBackups  int

	currentSize int64
	lastRotate  time.Time

	// midLine: the file ends with the start of an entry, cut by a write that
	// failed part-way, or by a crash before this sink opened it. The next
	// write ends that line first, so the entry after it is not joined to it.
	midLine bool

	// closed is set by Close: the sink takes no write from then on. While it
	// is not, a nil file is one a rotation could not open, and the next
	// write opens it.
	closed bool

	// openFile is os.OpenFile, but for tests.
	openFile func(name string, flag int, perm os.FileMode) (*os.File, error)
}

// FileSinkConfig contains configuration for file sink
type FileSinkConfig struct {
	Path        string
	Mode        os.FileMode
	RotateSize  int64 // Rotate when file reaches this size in bytes (0 = no rotation)
	RotateDaily bool  // Rotate daily
	MaxBackups  int   // Number of backup files to keep
}

// NewFileSink creates a new file sink
func NewFileSink(config FileSinkConfig) (*FileSink, error) {
	if config.Path == "" {
		return nil, fmt.Errorf("file path is required")
	}

	if config.Mode == 0 {
		config.Mode = 0600
	}

	// Ensure directory exists
	dir := filepath.Dir(config.Path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}

	sink := &FileSink{
		path:        config.Path,
		mode:        config.Mode,
		rotateSize:  config.RotateSize,
		rotateDaily: config.RotateDaily,
		maxBackups:  config.MaxBackups,
		lastRotate:  time.Now(),
		openFile:    os.OpenFile,
	}
	if err := sink.open(); err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	return sink, nil
}

// open opens the file at the sink's path, creating it if need be, as the file
// the sink appends to, and reads what the sink needs to know of it: its size,
// and whether it ends mid-line. The caller holds s.mu, or is NewFileSink.
func (s *FileSink) open() error {
	file, err := s.openFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, s.mode)
	if err != nil {
		return err
	}
	stat, err := file.Stat()
	if err != nil {
		file.Close()
		return err
	}
	s.file, s.writer = file, file
	s.currentSize = stat.Size()
	s.midLine = endsMidLine(s.path, stat.Size())
	return nil
}

// endsMidLine reports whether the file at path, size bytes long, ends with
// something other than a newline. A file that cannot be read is taken to end
// cleanly: the sink only needs to write to it.
func endsMidLine(path string, size int64) bool {
	if size == 0 {
		return false
	}
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()

	var last [1]byte
	if _, err := file.ReadAt(last[:], size-1); err != nil {
		return false
	}
	return last[0] != '\n'
}

// Write writes an entry to the file
func (s *FileSink) Write(ctx context.Context, entry []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Write entry with newline
	_, err := s.writeLocked(append(entry, '\n'))
	return err
}

// WriteBatch writes batch, a run of entries each ended by a newline, in one
// write, and returns how many of its bytes reached the file. The file is
// checked for rotation once, before the write: a batch is never split between
// two files, and the file may pass its rotation size by one batch.
func (s *FileSink) WriteBatch(ctx context.Context, batch []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.writeLocked(batch)
}

// writeLocked writes lines, one entry or more each ended by a newline, and
// returns how many of its bytes reached the file. The caller holds s.mu.
func (s *FileSink) writeLocked(lines []byte) (int, error) {
	if s.closed {
		return 0, errFileSinkClosed
	}
	// A rotation that could not open the file leaves none: it is opened
	// here, for as many writes as it takes.
	if s.file == nil {
		if err := s.open(); err != nil {
			return 0, fmt.Errorf("failed to open file: %w", err)
		}
	}

	// A line cut short is ended before anything follows it. Where that fails
	// the file is rotated all the same if it is due: with a full disk,
	// rotation is what can free room, once it has a backup to prune.
	endErr := s.endCutLine()

	// Check if rotation is needed
	if err := s.checkRotation(); err != nil {
		return 0, fmt.Errorf("rotation check failed: %w", err)
	}
	if s.midLine {
		return 0, fmt.Errorf("failed to write to file: %w", endErr)
	}

	n, err := s.writer.Write(lines)
	s.currentSize += int64(n)
	if n > 0 {
		s.midLine = lines[n-1] != '\n'
	}
	if err != nil {
		return n, fmt.Errorf("failed to write to file: %w", err)
	}

	return n, nil
}

// endCutLine ends the line a failed write left unfinished at the end of the
// file, if there is one. A fragment stays, as a line of its own that no
// parser reads; the entry it was the start of is written again whole. A line
// that lacked only its newline is an entry, and now a whole one: its writer
// counts it as written.
func (s *FileSink) endCutLine() error {
	if !s.midLine {
		return nil
	}
	n, err := s.writer.Write([]byte{'\n'})
	s.currentSize += int64(n)
	if err != nil {
		return err
	}
	s.midLine = false
	return nil
}

// checkRotation checks if file should be rotated and performs rotation
func (s *FileSink) checkRotation() error {
	needsRotation := false

	// Check size-based rotation
	if s.rotateSize > 0 && s.currentSize >= s.rotateSize {
		needsRotation = true
	}

	// Check daily rotation
	if s.rotateDaily {
		now := time.Now()
		if now.Year() != s.lastRotate.Year() ||
			now.YearDay() != s.lastRotate.YearDay() {
			needsRotation = true
		}
	}

	if !needsRotation {
		return nil
	}

	return s.rotate()
}

// rotate moves the file aside as a backup and opens a new one at its path.
//
// Whatever fails, the sink is left able to write once the failure clears. The
// file is let go even when closing it fails: a descriptor whose close failed
// is not one to write to, and keeping it meant trying to close it again at
// every write, which could never succeed. When the file cannot be moved, the
// sink opens it again and the rotation is tried at the next write; when the
// new one cannot be opened, the next write opens it. Before, either failure
// left the sink holding a closed file, refusing every write until a restart.
//
// A rotation that failed in any way fails the write that set it off.
func (s *FileSink) rotate() error {
	closeErr := s.file.Close()
	s.file, s.writer = nil, nil

	timestamp := time.Now().Format("20060102-150405")
	backupPath := fmt.Sprintf("%s.%s", s.path, timestamp)

	renameErr := os.Rename(s.path, backupPath)
	if renameErr == nil {
		s.lastRotate = time.Now()
		// Clean up old backups asynchronously but with proper
		// synchronization. We capture the path and maxBackups values to
		// avoid racing with future rotations. Pruning may be what frees the
		// room the new file needs: it runs whether or not that opens.
		if s.maxBackups > 0 {
			path := s.path
			maxBackups := s.maxBackups
			go cleanupBackupsAsync(path, maxBackups)
		}
	}

	// The sink writes on at its path: to a new file if the old one was moved
	// away, a line cut short going with it; to the old one if it was not.
	openErr := s.open()

	var failures []error
	if closeErr != nil {
		failures = append(failures, fmt.Errorf("failed to close file: %w", closeErr))
	}
	if renameErr != nil {
		failures = append(failures, fmt.Errorf("failed to rename file: %w", renameErr))
	}
	if openErr != nil {
		failures = append(failures, fmt.Errorf("failed to open file: %w", openErr))
	}
	return errors.Join(failures...)
}

// errFileSinkClosed refuses a write to a file sink that has been closed.
var errFileSinkClosed = errors.New("file sink is closed")

// cleanupBackupsAsync removes old backup files.
// This is a standalone function that takes the path and maxBackups as parameters
// to avoid any race conditions with the FileSink state.
func cleanupBackupsAsync(path string, maxBackups int) {
	pattern := path + ".*"
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return
	}

	if len(matches) <= maxBackups {
		return
	}

	// Sort by modification time and remove oldest
	type fileInfo struct {
		path    string
		modTime time.Time
	}

	var files []fileInfo
	for _, match := range matches {
		stat, err := os.Stat(match)
		if err != nil {
			continue
		}
		files = append(files, fileInfo{
			path:    match,
			modTime: stat.ModTime(),
		})
	}

	// Sort oldest first (files[i] should be before files[j] if files[i] is older)
	for i := 0; i < len(files)-1; i++ {
		for j := i + 1; j < len(files); j++ {
			if files[i].modTime.After(files[j].modTime) {
				// files[i] is newer than files[j], swap to put older first
				files[i], files[j] = files[j], files[i]
			}
		}
	}

	// Remove oldest files
	toRemove := len(files) - maxBackups
	for i := 0; i < toRemove; i++ {
		os.Remove(files[i].path)
	}
}

// Close closes the file sink
func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.closed = true
	if s.file != nil {
		file := s.file
		s.file, s.writer = nil, nil
		return file.Close()
	}

	return nil
}

// Name returns the sink name
func (s *FileSink) Name() string {
	return s.path
}

// Type returns the sink type
func (s *FileSink) Type() string {
	return "file"
}
