//! 输出三档（§6.1）：`--json`（模型/脚本）、默认（人类，彩色）、`--quiet`（CI）。
//! 颜色语义全局统一：绿=正常、黄=降级/警告、红=拒绝/拦截、灰=过期/归档。

use std::io::IsTerminal;

#[derive(Clone)]
pub struct Output {
    pub json: bool,
    pub color: bool,
    pub quiet: bool,
}

impl Output {
    pub fn new(json: bool, no_color: bool, quiet: bool) -> Output {
        // NO_COLOR 环境变量（https://no-color.org/）与 --no-color 同效
        let no_color_env = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
        Output {
            json,
            color: !no_color && !no_color_env && std::io::stdout().is_terminal(),
            quiet,
        }
    }

    pub fn green(&self, s: &str) -> String {
        if self.color {
            format!("\x1b[32m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
    pub fn yellow(&self, s: &str) -> String {
        if self.color {
            format!("\x1b[33m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
    pub fn red(&self, s: &str) -> String {
        if self.color {
            format!("\x1b[31m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
    pub fn grey(&self, s: &str) -> String {
        if self.color {
            format!("\x1b[90m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }

    pub fn println_stdout(&self, s: &str) {
        if self.quiet && !self.json {
            return;
        }
        println!("{s}");
    }

    pub fn println_stderr(&self, s: &str) {
        eprintln!("{s}");
    }

    /// JSON 模式下打印结构化数据；否则打印人类文本。
    pub fn either(&self, value: &serde_json::Value, human: &str) {
        if self.json {
            println!(
                "{}",
                serde_json::to_string_pretty(value).unwrap_or_default()
            );
        } else if !self.quiet {
            println!("{human}");
        }
    }
}
