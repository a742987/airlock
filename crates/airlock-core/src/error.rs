//! 错误类型与 CLI 退出码（PRD §6.1：退出码是 API 的一部分，v1.0 起冻结）。

pub const EXIT_OK: i32 = 0;
/// 冲突拒绝（409 型）
pub const EXIT_CONFLICT: i32 = 2;
/// 无租约 / 未找到
pub const EXIT_NOT_FOUND: i32 = 3;
/// daemon 不可达
pub const EXIT_DAEMON_UNREACHABLE: i32 = 4;
/// 配置错误
pub const EXIT_CONFIG: i32 = 5;
/// 用户中断
pub const EXIT_INTERRUPTED: i32 = 130;

use crate::proto::Rejection;

#[derive(Debug)]
pub enum Error {
    /// 409 型结构化拒绝（P1：拒绝必须可解释）
    Conflict(Box<Rejection>),
    NotFound(String),
    DaemonUnreachable(String),
    Config(String),
    Io(std::io::Error),
    Store(String),
    /// 审计日志断链等不可恢复状态
    Integrity(String),
    Other(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Conflict(r) => write!(f, "{}", r.human),
            Error::NotFound(m) => write!(f, "not found: {m}"),
            Error::DaemonUnreachable(m) => write!(f, "daemon unreachable: {m}"),
            Error::Config(m) => write!(f, "config error: {m}"),
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::Store(m) => write!(f, "store error: {m}"),
            Error::Integrity(m) => write!(f, "integrity error: {m}"),
            Error::Other(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Other(format!("json: {e}"))
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        match e {
            rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error {
                    code: rusqlite::ffi::ErrorCode::DatabaseCorrupt,
                    ..
                },
                _,
            ) => Error::Integrity(crate::messages::SQLITE_CORRUPT.to_string()),
            other => Error::Store(other.to_string()),
        }
    }
}

impl Error {
    /// CLI 退出码（§6.1 冻结表）
    pub fn exit_code(&self) -> i32 {
        match self {
            Error::Conflict(_) => EXIT_CONFLICT,
            Error::NotFound(_) => EXIT_NOT_FOUND,
            Error::DaemonUnreachable(_) => EXIT_DAEMON_UNREACHABLE,
            Error::Config(_) | Error::Integrity(_) => EXIT_CONFIG,
            Error::Io(_) | Error::Store(_) | Error::Other(_) => 1,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
