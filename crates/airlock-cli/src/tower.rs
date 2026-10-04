//! `airlock tower`（F6，v0.3）：一屏看懂——谁持有什么、是否在保护中（层 badge）、
//! 最近发生了什么（§6.3）。≤1s 刷新；键盘可达（q/ESC 退出，r 手动刷新）；
//! 非 TTY 环境退化为一次性纯文本渲染（CI/冒烟可用）。

use std::io::IsTerminal;

use airlock_core::error::Result;
use airlock_core::proto::{AuditEntry, BoardRead, StatusReport};
use airlock_core::store::now;

use crate::commands::{self, Ctx};

pub fn run(ctx: &Ctx) -> Result<i32> {
    if !std::io::stdout().is_terminal() {
        return render_once(ctx);
    }
    render_tui(ctx)
}

fn short(id: &str) -> String {
    id.chars().take(8).collect()
}

fn hhmmss(ts: i64) -> String {
    let secs = ts % 86400;
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

fn ttl_left(expires_at: i64) -> String {
    let s = (expires_at - now()).max(0);
    format!("{:02}:{:02} 剩余", s / 60, s % 60)
}

fn fetch_all(
    ctx: &Ctx,
) -> (
    Option<StatusReport>,
    Vec<AuditEntry>,
    Option<BoardRead>,
    bool,
) {
    let status = commands::fetch_status(ctx).ok();
    let events = commands::fetch_events(ctx, 50).unwrap_or_default();
    let board = commands::fetch_board(ctx).ok();
    let degraded = status.is_none();
    (status, events, board, degraded)
}

/// 一次性纯文本渲染（§6.3 首屏三问）。
fn render_once(ctx: &Ctx) -> Result<i32> {
    let (status, events, board, degraded) = fetch_all(ctx);
    if degraded {
        println!("AIRLOCK TOWER —— daemon 不可达（degraded）");
        return Ok(4);
    }
    let s = status.unwrap();
    println!(
        "AIRLOCK TOWER ─ repo: {} ─ {} ({})",
        s.repo_root, s.layer.id, s.layer.name
    );
    println!("LEASES");
    for l in &s.leases {
        let state = if l.state == "active" {
            ttl_left(l.expires_at)
        } else {
            l.state.clone()
        };
        println!(
            "  {:<10} {:<28} {:<10} intent: {}",
            l.agent_id,
            l.glob,
            state,
            l.intent.as_deref().unwrap_or("-")
        );
    }
    let resources: Vec<String> = s
        .ports
        .iter()
        .map(|p| format!("{} :{} {}", short(&p.session_id), p.port, p.purpose))
        .collect();
    println!("RESOURCES       {}", resources.join("  "));
    println!("EVENTS");
    for e in events.iter().rev().take(10) {
        println!(
            "  {} {} {} → {}",
            hhmmss(e.ts),
            e.event,
            e.actor.agent,
            e.path
        );
    }
    if let Some(b) = board {
        println!("BOARD");
        for e in &b.entries {
            println!("  [{}] {}", e.origin, e.body);
        }
    }
    Ok(0)
}

/// ratatui TUI。
fn render_tui(ctx: &Ctx) -> Result<i32> {
    use crossterm::event::{Event, KeyCode, KeyEventKind};
    use ratatui::prelude::*;
    use ratatui::widgets::*;

    let mut terminal = ratatui::init();
    let mut should_quit = false;
    let mut refresh = true;
    let mut cached = fetch_all(ctx);

    let res = loop {
        if refresh {
            cached = fetch_all(ctx);
            refresh = false;
        }
        let (status, events, board, _degraded) = &cached;
        terminal
            .draw(|f| {
                let area = f.area();
                let header = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(1),
                        Constraint::Min(6),
                        Constraint::Length(6),
                        Constraint::Min(4),
                        Constraint::Length(1),
                    ])
                    .split(area);

                // 头部：一屏三问之一——是否在保护中（层 badge）
                let (layer_txt, layer_color) = match status {
                    Some(s) => (
                        format!(
                            "AIRLOCK TOWER ─ repo: {} ─ {} ({})",
                            s.repo_root, s.layer.id, s.layer.name
                        ),
                        if s.layer.id == "L0" || s.layer.id == "L1" {
                            Color::Yellow
                        } else {
                            Color::Green
                        },
                    ),
                    None => (
                        "AIRLOCK TOWER ─ daemon 不可达（degraded）".to_string(),
                        Color::Red,
                    ),
                };
                f.render_widget(
                    Paragraph::new(Span::styled(layer_txt, Style::default().fg(layer_color)))
                        .bold(),
                    header[0],
                );

                // LEASES：谁持有什么、剩余 TTL、意图
                let rows: Vec<Row> = status
                    .as_ref()
                    .map(|s| {
                        s.leases
                            .iter()
                            .map(|l| {
                                let (state, color) = if l.state == "active" {
                                    (ttl_left(l.expires_at), Color::Green)
                                } else {
                                    (l.state.clone(), Color::DarkGray)
                                };
                                Row::new(vec![
                                    l.agent_id.clone(),
                                    l.glob.clone(),
                                    state,
                                    l.intent.clone().unwrap_or_else(|| "-".into()),
                                ])
                                .style(Style::default().fg(color))
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                f.render_widget(
                    Table::new(
                        rows,
                        [
                            Constraint::Length(12),
                            Constraint::Percentage(45),
                            Constraint::Length(12),
                            Constraint::Min(10),
                        ],
                    )
                    .header(Row::new(vec!["AGENT", "GLOB", "TTL", "INTENT"]).bold())
                    .block(Block::default().borders(Borders::ALL).title("LEASES")),
                    header[1],
                );

                // RESOURCES + EVENTS
                let mut ev_lines: Vec<Line> = Vec::new();
                if let Some(s) = status {
                    let resources: Vec<String> = s
                        .ports
                        .iter()
                        .map(|p| format!("{} :{} {}", short(&p.session_id), p.port, p.purpose))
                        .collect();
                    ev_lines.push(Line::from(format!(
                        "RESOURCES  {}",
                        if resources.is_empty() {
                            "（无）".into()
                        } else {
                            resources.join("  ")
                        }
                    )));
                    if let Some(gap) = s.protection_gap_s {
                        ev_lines.push(Line::from(Span::styled(
                            format!("⚠ 保护空窗 {gap} 秒"),
                            Style::default().fg(Color::Yellow),
                        )));
                    }
                }
                for e in events.iter().rev().take(3) {
                    let color = match e.event.as_str() {
                        "deny" | "enforce_deny" => Color::Red,
                        "degrade" => Color::Yellow,
                        "expire" => Color::DarkGray,
                        _ => Color::Green,
                    };
                    ev_lines.push(Line::from(Span::styled(
                        format!(
                            "EVENTS     {} {} {} → {}",
                            hhmmss(e.ts),
                            e.event,
                            e.actor.agent,
                            e.path
                        ),
                        Style::default().fg(color),
                    )));
                }
                f.render_widget(
                    Paragraph::new(ev_lines).block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title("RESOURCES / EVENTS"),
                    ),
                    header[2],
                );

                // BOARD
                let mut board_lines: Vec<Line> = Vec::new();
                if let Some(b) = board {
                    for e in b.entries.iter().take(4) {
                        board_lines.push(Line::from(format!("[{}] {}", e.origin, e.body)));
                    }
                    for a in b.archived_summary.iter().take(2) {
                        board_lines.push(Line::from(Span::styled(
                            a.clone(),
                            Style::default().fg(Color::DarkGray),
                        )));
                    }
                }
                if board_lines.is_empty() {
                    board_lines.push(Line::from("（黑板为空——claim --intent 让编队开始交接）"));
                }
                f.render_widget(
                    Paragraph::new(board_lines)
                        .block(Block::default().borders(Borders::ALL).title("BOARD")),
                    header[3],
                );

                f.render_widget(
                    Paragraph::new("q 退出 · r 刷新（≤1s 自动刷新）")
                        .style(Style::default().fg(Color::DarkGray)),
                    header[4],
                );
            })
            .ok();

        // 事件轮询：≤1s 刷新 + 键盘可达
        if crossterm::event::poll(std::time::Duration::from_millis(1000)).ok() == Some(true) {
            if let Ok(Event::Key(key)) = crossterm::event::read() {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
                            should_quit = true;
                        }
                        KeyCode::Char('r') => refresh = true,
                        _ => {}
                    }
                }
            }
        } else {
            refresh = true; // 周期刷新（≤1s）
        }
        if should_quit {
            break 0;
        }
    };
    ratatui::restore();
    Ok(res)
}
