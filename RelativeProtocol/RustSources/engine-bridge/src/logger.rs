use crate::ffi::BridgeLogSink;
use bitflags::bitflags;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::ffi::{c_void, CString};
use std::os::raw::c_char;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

type LogCallback = unsafe extern "C" fn(
    level: *const c_char,
    message: *const c_char,
    breadcrumbs: u32,
    context: *mut c_void,
);

static LOGGER: Lazy<LogManager> = Lazy::new(LogManager::new);

pub fn warn(message: impl Into<String>) {
    LOGGER.log(LogLevel::Warn, message.into());
}

pub fn error(message: impl Into<String>) {
    LOGGER.log(LogLevel::Error, message.into());
}

pub fn info(message: impl Into<String>) {
    LOGGER.log(LogLevel::Info, message.into());
}

pub fn debug(message: impl Into<String>) {
    LOGGER.log(LogLevel::Debug, message.into());
}

pub fn breadcrumb(flag: BreadcrumbFlags, message: impl Into<String>) {
    LOGGER.breadcrumb(flag, message.into());
}

pub fn install_sink(sink: Option<&BridgeLogSink>, level: Option<&str>) -> Result<(), &'static str> {
    LOGGER.install_sink(sink, level)
}

pub fn set_breadcrumb_mask(mask: u32) {
    LOGGER.set_breadcrumb_mask(mask);
}

bitflags! {
    #[derive(Clone, Copy, Debug)]
    pub struct BreadcrumbFlags: u32 {
        const DEVICE = 0b0000_0001;
        const FLOW   = 0b0000_0010;
        const DNS    = 0b0000_0100;
        const METRICS= 0b0000_1000;
        const FFI    = 0b0001_0000;
        const POLL   = 0b0010_0000;
        const PACKET = 0b0100_0000;
        const ALL    = u32::MAX;
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
}

impl LogLevel {
    fn from_str(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "error" | "err" => LogLevel::Error,
            "warn" | "warning" => LogLevel::Warn,
            "debug" | "dbg" => LogLevel::Debug,
            _ => LogLevel::Info,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
        }
    }
}

#[derive(Clone, Copy)]
struct LogSinkInner {
    callback: LogCallback,
    context: *mut std::ffi::c_void,
    breadcrumbs: BreadcrumbFlags,
    min_level: LogLevel,
}

unsafe impl Send for LogSinkInner {}
unsafe impl Sync for LogSinkInner {}

struct LogManager {
    sink: Mutex<Option<LogSinkInner>>,
    prefix: String,
}

impl LogManager {
    fn new() -> Self {
        let pid = std::process::id();
        Self {
            sink: Mutex::new(None),
            prefix: format!("[rp-p{pid}]"),
        }
    }

    fn install_sink(
        &self,
        sink: Option<&BridgeLogSink>,
        level: Option<&str>,
    ) -> Result<(), &'static str> {
        let mut guard = self.sink.lock();
        if let Some(sink) = sink {
            let callback = match sink.log {
                Some(cb) => cb,
                None => return Err("log callback missing"),
            };
            let min_level = level.map(LogLevel::from_str).unwrap_or(LogLevel::Info);
            *guard = Some(LogSinkInner {
                callback,
                context: sink.context,
                breadcrumbs: BreadcrumbFlags::from_bits_truncate(sink.enabled_breadcrumbs),
                min_level,
            });
        } else {
            *guard = None;
        }
        Ok(())
    }

    fn set_breadcrumb_mask(&self, mask: u32) {
        if let Some(inner) = self.sink.lock().as_mut() {
            inner.breadcrumbs = BreadcrumbFlags::from_bits_truncate(mask);
        }
    }

    fn log(&self, level: LogLevel, message: String) {
        if message.is_empty() {
            return;
        }
        self.dispatch(level, BreadcrumbFlags::empty(), message);
    }

    fn breadcrumb(&self, flag: BreadcrumbFlags, message: String) {
        if message.is_empty() || flag.is_empty() {
            return;
        }
        self.dispatch(LogLevel::Debug, flag, message);
    }

    fn dispatch(&self, level: LogLevel, breadcrumbs: BreadcrumbFlags, message: String) {
        let sink = {
            let guard = self.sink.lock();
            *guard
        };
        let Some(inner) = sink else { return };
        if level > inner.min_level && breadcrumbs.is_empty() {
            return;
        }
        if !breadcrumbs.is_empty() && !inner.breadcrumbs.intersects(breadcrumbs) {
            return;
        }

        let formatted = if !breadcrumbs.is_empty() {
            let label = label_for(breadcrumbs);
            format!("{} [{}] {}", self.prefix, label, message)
        } else {
            format!("{} {}", self.prefix, message)
        };

        let level_c = match CString::new(level.as_str()) {
            Ok(val) => val,
            Err(_) => return,
        };
        let msg_c = match CString::new(formatted) {
            Ok(val) => val,
            Err(_) => return,
        };
        unsafe {
            (inner.callback)(
                level_c.as_ptr(),
                msg_c.as_ptr(),
                breadcrumbs.bits(),
                inner.context,
            );
        }
    }
}

fn label_for(flags: BreadcrumbFlags) -> &'static str {
    if flags.contains(BreadcrumbFlags::FLOW) {
        "FLOW"
    } else if flags.contains(BreadcrumbFlags::DNS) {
        "DNS"
    } else if flags.contains(BreadcrumbFlags::DEVICE) {
        "DEVICE"
    } else if flags.contains(BreadcrumbFlags::METRICS) {
        "METRICS"
    } else if flags.contains(BreadcrumbFlags::FFI) {
        "FFI"
    } else if flags.contains(BreadcrumbFlags::POLL) {
        "POLL"
    } else {
        "LOG"
    }
}

// ============================================================================
// Rate-Limited Error Logging
// ============================================================================
// Production-grade error logging that prevents log flooding from repeated errors.
// Each error category has its own rate limiter to ensure important errors aren't
// suppressed by unrelated high-frequency errors.

/// Minimum interval between logs of the same error category (in milliseconds).
const RATE_LIMIT_INTERVAL_MS: u64 = 1000;

/// Error categories for rate-limited logging.
/// Each category has independent rate limiting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCategory {
    /// Invalid IP packet structure (version, header length, etc.)
    PacketInvalidIp,
    /// Invalid TCP packet structure
    PacketInvalidTcp,
    /// Invalid UDP packet structure
    PacketInvalidUdp,
    /// Memory budget exhausted
    MemoryExhausted,
    /// FFI/callback errors
    CallbackError,
    /// Socket operation failures
    SocketError,
}

impl ErrorCategory {
    fn index(self) -> usize {
        match self {
            Self::PacketInvalidIp => 0,
            Self::PacketInvalidTcp => 1,
            Self::PacketInvalidUdp => 2,
            Self::MemoryExhausted => 3,
            Self::CallbackError => 4,
            Self::SocketError => 5,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::PacketInvalidIp => "INVALID_IP",
            Self::PacketInvalidTcp => "INVALID_TCP",
            Self::PacketInvalidUdp => "INVALID_UDP",
            Self::MemoryExhausted => "MEMORY_EXHAUSTED",
            Self::CallbackError => "CALLBACK_ERROR",
            Self::SocketError => "SOCKET_ERROR",
        }
    }
}

/// Rate limiter state for error logging.
/// Uses atomic timestamps for lock-free rate limiting.
struct RateLimitedLogger {
    /// Last log time (unix millis) for each error category.
    last_log_times: [AtomicU64; 6],
}

impl RateLimitedLogger {
    const fn new() -> Self {
        Self {
            last_log_times: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
        }
    }

    /// Attempts to log an error if rate limit allows.
    /// Returns true if the log was emitted, false if rate-limited.
    fn try_log(&self, category: ErrorCategory, message: &str) -> bool {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let idx = category.index();
        let last = self.last_log_times[idx].load(Ordering::Relaxed);

        // Check if enough time has passed since last log
        if now_ms.saturating_sub(last) < RATE_LIMIT_INTERVAL_MS {
            return false;
        }

        // Try to update the timestamp (compare-and-swap for thread safety)
        if self.last_log_times[idx]
            .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            // We won the race, emit the log
            let formatted = format!("[{}] {}", category.label(), message);
            warn(formatted);
            true
        } else {
            // Another thread logged, skip
            false
        }
    }
}

static RATE_LIMITER: RateLimitedLogger = RateLimitedLogger::new();

/// Log an error with rate limiting to prevent log flooding.
/// Only one log per category per second will be emitted.
/// Returns true if the log was emitted, false if suppressed.
pub fn rate_limited_error(category: ErrorCategory, message: impl Into<String>) -> bool {
    RATE_LIMITER.try_log(category, &message.into())
}
