use crate::ffi::BridgeLogSink;
use bitflags::bitflags;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::ffi::{c_void, CString};
use std::fmt::Write as _;
use std::os::raw::c_char;

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
            guard.clone()
        };
        let Some(inner) = sink else { return };
        if level > inner.min_level && breadcrumbs.is_empty() {
            return;
        }
        if !breadcrumbs.is_empty() && !inner.breadcrumbs.intersects(breadcrumbs) {
            return;
        }

        let mut formatted = String::new();
        let _ = write!(formatted, "{} {}", self.prefix, message);
        if !breadcrumbs.is_empty() {
            let label = label_for(breadcrumbs);
            formatted = format!("{} [{}] {}", self.prefix, label, message);
        }

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
