package logger

import (
    "log"
    "strings"
    "os"
)

type LogLevel int

const (
    FATAL LogLevel = iota
    ERROR
    WARN
    INFO
    DEBUG
    TRACE
)

var levelName = map[LogLevel]string {
    FATAL: "FATAL",
    ERROR: "ERROR",
    WARN: "WARN",
    INFO: "INFO",
    DEBUG: "DEBUG",
    TRACE: "TRACE",
}

func ConvertStringToLogLevel(levelName string) LogLevel {
    switch (strings.ToUpper(levelName)) {
    case "FATAL":
        return FATAL
    case "ERROR":
        return ERROR
    case "WARN":
        return WARN
    case "INFO":
        return INFO
    case "DEBUG":
        return DEBUG
    case "TRACE":
        return TRACE
    default:
        log.Printf("[ERROR]: Invalid log level: %v. Defaulting to `INFO`", levelName)
        return INFO
    }
}

type logger struct {
    level LogLevel
    logPath string
}

var loggerInstance *logger = &logger{INFO, "log"}

func GetLoggerInstance() *logger {
    return loggerInstance
}

func UpdateLoggerInstance(level LogLevel, logPath string) {
    loggerInstance.level = level
    loggerInstance.logPath = logPath
}

func UpdateLogLevel(level LogLevel) {
    loggerInstance.level = level
}

func UpdateLogLevelName(levelName string) {
    level := ConvertStringToLogLevel(levelName)
    loggerInstance.level = level
}

func UpdateLogPath(logPath string) {
    loggerInstance.logPath = logPath
}

func GetLogLevel() LogLevel {
    return loggerInstance.level
}

func GetLogPath() string {
    return loggerInstance.logPath
}

func (level LogLevel) string() string {
    return levelName[level]
}

func Fatal(msg string) {
    if loggerInstance.level >= FATAL {
        log.Printf("[%v]: %v", FATAL.string(), msg)
        os.Exit(1)
    }
}

func Error(msg string) {
    if loggerInstance.level >= ERROR {
        log.Printf("[%v]: %v", ERROR.string(), msg)
    }
}

func Warn(msg string) {
    if loggerInstance.level >= WARN {
        log.Printf("[%v]: %v", WARN.string(), msg)
    }
}

func Info(msg string) {
    if loggerInstance.level >= INFO {
        log.Printf("[%v]: %v", INFO.string(), msg)
    }
}

func Debug(msg string) {
    if loggerInstance.level >= DEBUG {
        log.Printf("[%v]: %v", DEBUG.string(), msg)
    }
}

func Trace(msg string) {
    if loggerInstance.level >= TRACE {
        log.Printf("[%v]: %v", TRACE.string(), msg)
    }
}
