package utils

import (
	"fmt"
	"io"
	"log"
	"os"
	"time"
)

// LogLevel represents logging severity
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
)

// Logger handles application logging
type Logger struct {
	debugLogger *log.Logger
	infoLogger  *log.Logger
	warnLogger  *log.Logger
	errorLogger *log.Logger
	level       LogLevel
	file        *os.File
}

var defaultLogger *Logger

// InitLogger initializes the default logger
func InitLogger(verbose bool, logFile string) error {
	level := INFO
	if verbose {
		level = DEBUG
	}

	writers := []io.Writer{os.Stdout}

	// Add file writer if log file specified
	if logFile != "" {
		file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return fmt.Errorf("failed to open log file: %w", err)
		}
		writers = append(writers, file)
	}

	multiWriter := io.MultiWriter(writers...)

	defaultLogger = &Logger{
		debugLogger: log.New(multiWriter, "🔍 DEBUG: ", log.Ltime),
		infoLogger:  log.New(multiWriter, "ℹ️  INFO:  ", log.Ltime),
		warnLogger:  log.New(multiWriter, "⚠️  WARN:  ", log.Ltime),
		errorLogger: log.New(multiWriter, "❌ ERROR: ", log.Ltime),
		level:       level,
	}

	return nil
}

// Debug logs debug messages
func Debug(format string, v ...interface{}) {
	if defaultLogger == nil || defaultLogger.level > DEBUG {
		return
	}
	defaultLogger.debugLogger.Printf(format, v...)
}

// Info logs info messages
func Info(format string, v ...interface{}) {
	if defaultLogger == nil || defaultLogger.level > INFO {
		return
	}
	defaultLogger.infoLogger.Printf(format, v...)
}

// Warn logs warning messages
func Warn(format string, v ...interface{}) {
	if defaultLogger == nil || defaultLogger.level > WARN {
		return
	}
	defaultLogger.warnLogger.Printf(format, v...)
}

// Error logs error messages
func Error(format string, v ...interface{}) {
	if defaultLogger == nil {
		return
	}
	defaultLogger.errorLogger.Printf(format, v...)
}

// Close closes the log file if open
func CloseLogger() {
	if defaultLogger != nil && defaultLogger.file != nil {
		defaultLogger.file.Close()
	}
}

// PrintBanner prints the application banner
func PrintBanner() {
	banner := `
╔═══════════════════════════════════════════════════════╗
║                                                       ║
║     █████╗ ██╗   ██╗████████╗ ██████╗ ███████╗       ║
║    ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗██╔════╝       ║
║    ███████║██║   ██║   ██║   ██║   ██║███████╗       ║
║    ██╔══██║██║   ██║   ██║   ██║   ██║╚════██║       ║
║    ██║  ██║╚██████╔╝   ██║   ╚██████╔╝███████║       ║
║    ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚══════╝       ║
║                                                       ║
║          SecScan - Web Security Audit Tool           ║
║                   Version 1.0.0                       ║
║                                                       ║
╚═══════════════════════════════════════════════════════╝
`
	fmt.Println(banner)
}

// PrintProgress prints a progress message
func PrintProgress(message string) {
	timestamp := time.Now().Format("15:04:05")
	fmt.Printf("[%s] → %s\n", timestamp, message)
}

// PrintSuccess prints a success message
func PrintSuccess(message string) {
	fmt.Printf("✓ %s\n", message)
}

// PrintError prints an error message
func PrintError(message string) {
	fmt.Printf("✗ %s\n", message)
}
