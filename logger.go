package wgrpcd

import "log"

// Logger wraps Go's stdlib logger to allow for more control over logging.
// An empty logger will log to Go's default logger.
type Logger struct {
	*log.Logger
}

// Printf forwards the logging call to a custom logger, or the default logger if there is no custom logger.
func (l *Logger) Printf(format string, args ...interface{}) {
	if l.Logger != nil {
		l.Logger.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}
