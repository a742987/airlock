//! Airlock 核心库：让多个 AI 编程代理在同一目录、同一分支并行工作——
//! 文件租约由内核强制执行、共享资源自动分配、协作状态随租约生命周期自动维护。
//!
//! 模块地图（对应 PRD 功能编号）：
//! - [`lease`]     F1 租约引擎（claim/release/heartbeat/expire）
//! - [`enforce`]   F2 三层强制（L1 advisory / L2 Landlock / L3 BPF-LSM）
//! - [`resources`] F3 资源分配（端口段 / 配置改写 / 数据库分支 / 杂项锁）
//! - [`predict`]   F5 冲突预测（file → directory 级）
//! - [`proto`]     F4 接入层共享协议（IPC / MCP 载荷，P4 双形态）
//! - [`store`]     §7 数据设计（SQLite WAL + hash-chained 审计）
//! - [`glob`]      路径模式匹配与重叠判定
//! - [`config`]    P3 零配置可用的可选配置层
//! - [`messages`]  §6.2/§6.4 用户可见文案集中地（i18n 架构准备）

pub mod config;
pub mod enforce;
pub mod error;
pub mod glob;
pub mod landlock;
pub mod lease;
pub mod messages;
pub mod paths;
pub mod predict;
pub mod proto;
pub mod resources;
pub mod store;

pub use error::{Error, Result};
pub use paths::Domain;
