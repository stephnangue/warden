package logger

// FileConfig holds file rotation configuration
type FileConfig struct {
	Filename   string // File path
	MaxSize    int    // Maximum size in megabytes
	MaxAge     int    // Maximum age in days
	MaxBackups int    // Maximum number of backup files
	Compress   bool   // Whether to compress rotated files
}

// DefaultFileConfig returns a default file configuration
func DefaultFileConfig(filename string) *FileConfig {
	return &FileConfig{
		Filename:   filename,
		MaxSize:    100, // 100MB
		MaxAge:     30,  // 30 days
		MaxBackups: 10,  // 10 backup files
		Compress:   true,
	}
}
