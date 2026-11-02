//! Log records surfaced to both `tracing` and the GUI log panel.

/// Severity of a log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    /// Short uppercase tag used in the log panel.
    pub fn tag(self) -> &'static str {
        match self {
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
        }
    }
}

/// A single user-visible log record.
///
/// Credentials and key material must never be placed in a `LogLine`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    pub level: LogLevel,
    pub message: String,
}

impl LogLine {
    pub fn new(level: LogLevel, message: impl Into<String>) -> Self {
        Self {
            level,
            message: message.into(),
        }
    }

    pub fn debug(message: impl Into<String>) -> Self {
        Self::new(LogLevel::Debug, message)
    }

    pub fn info(message: impl Into<String>) -> Self {
        Self::new(LogLevel::Info, message)
    }

    pub fn warn(message: impl Into<String>) -> Self {
        Self::new(LogLevel::Warn, message)
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self::new(LogLevel::Error, message)
    }

    /// Single line rendering used by the GUI and by log export.
    pub fn render(&self) -> String {
        format!("[{}] {}", self.level.tag(), self.message)
    }
}

/// Forward a [`LogLine`] to the `tracing` subscriber.
pub fn trace_line(line: &LogLine) {
    match line.level {
        LogLevel::Debug => tracing::debug!("{}", line.message),
        LogLevel::Info => tracing::info!("{}", line.message),
        LogLevel::Warn => tracing::warn!("{}", line.message),
        LogLevel::Error => tracing::error!("{}", line.message),
    }
}
