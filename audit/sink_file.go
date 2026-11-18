package audit

import (
	"context"
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

	// Open file
	file, err := os.OpenFile(config.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, config.Mode)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	// Get current file size
	stat, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	sink := &FileSink{
		path:        config.Path,
		file:        file,
		mode:        config.Mode,
		writer:      file,
		rotateSize:  config.RotateSize,
		rotateDaily: config.RotateDaily,
		maxBackups:  config.MaxBackups,
		currentSize: stat.Size(),
		lastRotate:  time.Now(),
		midLine:     endsMidLine(config.Path, stat.Size()),
	}

	return sink, nil
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

// rotate performs file rotation
func (s *FileSink) rotate() error {
	// Close current file
	if err := s.file.Close(); err != nil {
		return fmt.Errorf("failed to close file: %w", err)
	}

	// Rename current file with timestamp
	timestamp := time.Now().Format("20060102-150405")
	backupPath := fmt.Sprintf("%s.%s", s.path, timestamp)

	if err := os.Rename(s.path, backupPath); err != nil {
		// Try to reopen original file if rename fails
		file, openErr := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, s.mode)
		if openErr != nil {
			return fmt.Errorf("failed to rename file and reopen: %v, %v", err, openErr)
		}
		s.file = file
		s.writer = file
		return fmt.Errorf("failed to rename file: %w", err)
	}

	// Create new file
	file, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, s.mode)
	if err != nil {
		return fmt.Errorf("failed to create new file: %w", err)
	}

	s.file = file
	s.writer = file
	s.currentSize = 0
	s.lastRotate = time.Now()
	// A line cut short stays in the file that was rotated away.
	s.midLine = false

	// Clean up old backups asynchronously but with proper synchronization.
	// We capture the path and maxBackups values to avoid racing with future rotations.
	if s.maxBackups > 0 {
		path := s.path
		maxBackups := s.maxBackups
		go cleanupBackupsAsync(path, maxBackups)
	}

	return nil
}

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

	if s.file != nil {
		return s.file.Close()
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
