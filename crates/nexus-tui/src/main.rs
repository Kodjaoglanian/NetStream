//! nexus-tui — interactive terminal dashboard for a running NexusMesh agent.
//!
//! Polls the agent's Unix IPC socket once per second and renders the peer
//! table, throughput sparklines, connection modes, and the audit event log.
//!
//! Keys: q / Esc / Ctrl-C quit · ↑↓/j/k select peer · p ping selected peer ·
//! r refresh now.

use anyhow::Result;
use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use nexus_core::ipc::{self, human_rate, IpcRequest, IpcResponse, StatusReport, IPC_SOCK_PATH};
use nexus_core::model::ConnMode;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Sparkline, Table, TableState, Wrap};
use ratatui::Terminal;
use std::collections::VecDeque;
use std::io::Stdout;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver};
use std::time::Duration;

const POLL_INTERVAL: Duration = Duration::from_secs(1);
const HISTORY: usize = 240;

#[derive(Parser)]
#[command(name = "nexus-tui", version, about = "NexusMesh terminal dashboard")]
struct Cli {
    /// Path to the agent's IPC socket.
    #[arg(long, env = "NEXUS_SOCK", default_value = IPC_SOCK_PATH)]
    sock: PathBuf,
}

struct App {
    report: Option<StatusReport>,
    last_err: Option<String>,
    /// Aggregate throughput history for the sparklines.
    rx_hist: VecDeque<u64>,
    tx_hist: VecDeque<u64>,
    selected: usize,
    state: TableState,
    /// Local notes (e.g. ping results) appended to the event view.
    notes: VecDeque<String>,
}

impl App {
    fn new() -> Self {
        Self {
            report: None,
            last_err: None,
            rx_hist: VecDeque::with_capacity(HISTORY),
            tx_hist: VecDeque::with_capacity(HISTORY),
            selected: 0,
            state: TableState::default(),
            notes: VecDeque::new(),
        }
    }

    fn apply(&mut self, report: StatusReport) {
        let rx: f64 = report.peers.iter().map(|p| p.rx_bps).sum();
        let tx: f64 = report.peers.iter().map(|p| p.tx_bps).sum();
        self.rx_hist.push_back(rx as u64);
        self.tx_hist.push_back(tx as u64);
        while self.rx_hist.len() > HISTORY {
            self.rx_hist.pop_front();
        }
        while self.tx_hist.len() > HISTORY {
            self.tx_hist.pop_front();
        }
        let n_peers = report.peers.len();
        if self.selected >= n_peers {
            self.selected = n_peers.saturating_sub(1);
        }
        self.state.select(if n_peers == 0 {
            None
        } else {
            Some(self.selected)
        });
        self.report = Some(report);
        self.last_err = None;
    }

    fn note(&mut self, msg: String) {
        self.notes.push_back(msg);
        while self.notes.len() > 50 {
            self.notes.pop_front();
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Poller thread: blocking IPC request once a second.
    let (tx, rx) = channel::<std::result::Result<StatusReport, String>>();
    {
        let sock = cli.sock.clone();
        std::thread::spawn(move || loop {
            let res = ipc::request(&sock, &IpcRequest::Status)
                .map_err(|e| e.to_string())
                .and_then(|r| match r {
                    IpcResponse::Status { report } => Ok(report),
                    IpcResponse::Error { message } => Err(message),
                    _ => Err("unexpected response".into()),
                });
            if tx.send(res).is_err() {
                return;
            }
            std::thread::sleep(POLL_INTERVAL);
        });
    }

    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut term = Terminal::new(backend)?;

    let res = run(&mut term, rx, &cli.sock);

    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen)?;
    term.show_cursor()?;
    res
}

fn run(
    term: &mut Terminal<CrosstermBackend<Stdout>>,
    rx: Receiver<std::result::Result<StatusReport, String>>,
    sock: &std::path::Path,
) -> Result<()> {
    let mut app = App::new();
    loop {
        // Drain any fresh status reports.
        while let Ok(res) = rx.try_recv() {
            match res {
                Ok(report) => app.apply(report),
                Err(e) => app.last_err = Some(e),
            }
        }

        term.draw(|f| draw(f, &mut app))?;

        if !event::poll(Duration::from_millis(150))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        match (key.code, key.modifiers) {
            (KeyCode::Char('q'), _)
            | (KeyCode::Esc, _)
            | (KeyCode::Char('c'), KeyModifiers::CONTROL) => return Ok(()),
            (KeyCode::Down | KeyCode::Char('j'), _) => app.selected += 1,
            (KeyCode::Up | KeyCode::Char('k'), _) => app.selected = app.selected.saturating_sub(1),
            (KeyCode::Char('r'), _) => {
                if let Ok(IpcResponse::Status { report }) = ipc::request(sock, &IpcRequest::Status)
                {
                    app.apply(report);
                }
            }
            (KeyCode::Char('p'), _) => {
                let vip = app
                    .report
                    .as_ref()
                    .and_then(|r| r.peers.get(app.selected))
                    .map(|p| p.vip.clone());
                if let Some(vip) = vip {
                    match ipc::request(sock, &IpcRequest::Ping { vip: vip.clone() }) {
                        Ok(IpcResponse::Pong { rtt_ms, .. }) => {
                            app.note(format!("ping {vip}: {rtt_ms:.1} ms"));
                        }
                        Ok(IpcResponse::Error { message }) => {
                            app.note(format!("ping {vip}: {message}"));
                        }
                        _ => app.note(format!("ping {vip}: no reply")),
                    }
                }
            }
            _ => {}
        }
        if let Some(n) = app.report.as_ref().map(|r| r.peers.len()) {
            if app.selected >= n {
                app.selected = n.saturating_sub(1);
            }
        }
    }
}

fn draw(f: &mut ratatui::Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Min(10),
            Constraint::Length(9),
        ])
        .split(f.area());

    draw_header(f, chunks[0], app);

    let mid = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(62), Constraint::Percentage(38)])
        .split(chunks[1]);
    draw_peers(f, mid[0], app);
    draw_charts(f, mid[1], app);
    draw_events(f, chunks[2], app);
}

fn draw_header(f: &mut ratatui::Frame, area: ratatui::layout::Rect, app: &App) {
    let block = Block::default().borders(Borders::ALL).title(" NexusMesh ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let (line1, line2) = match &app.report {
        Some(r) => {
            let n = &r.node;
            let state_style = match n.state.as_str() {
                "connected" => Style::default().fg(Color::Green),
                "connecting" => Style::default().fg(Color::Yellow),
                _ => Style::default().fg(Color::Red),
            };
            (
                Line::from(vec![
                    Span::styled("state: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(&n.state, state_style.add_modifier(Modifier::BOLD)),
                    Span::raw("   "),
                    Span::styled("vip: ", Style::default().fg(Color::DarkGray)),
                    Span::raw(n.vip.clone().unwrap_or_else(|| "—".into())),
                    Span::raw("   "),
                    Span::styled("node: ", Style::default().fg(Color::DarkGray)),
                    Span::raw(
                        n.node_id
                            .map(|i| i.to_string())
                            .unwrap_or_else(|| "—".into()),
                    ),
                    Span::raw("   "),
                    Span::styled("uptime: ", Style::default().fg(Color::DarkGray)),
                    Span::raw(fmt_uptime(n.uptime_secs)),
                ]),
                Line::from(vec![
                    Span::styled("server: ", Style::default().fg(Color::DarkGray)),
                    Span::raw(n.server_url.clone().unwrap_or_else(|| "—".into())),
                    Span::raw("   "),
                    Span::styled("public endpoint: ", Style::default().fg(Color::DarkGray)),
                    Span::raw(n.public_endpoint.clone().unwrap_or_else(|| "—".into())),
                    Span::raw("   "),
                    Span::styled("listen: ", Style::default().fg(Color::DarkGray)),
                    Span::raw(
                        n.listen_port
                            .map(|p| format!("{p}/udp"))
                            .unwrap_or_else(|| "—".into()),
                    ),
                ]),
            )
        }
        None => (
            Line::from(Span::styled(
                "waiting for daemon…",
                Style::default().fg(Color::Yellow),
            )),
            Line::from(
                app.last_err
                    .clone()
                    .unwrap_or_else(|| "no data yet".to_string()),
            ),
        ),
    };
    f.render_widget(Paragraph::new(vec![line1, line2]), inner);
}

fn draw_peers(f: &mut ratatui::Frame, area: ratatui::layout::Rect, app: &mut App) {
    let block = Block::default().borders(Borders::ALL).title(" Peers ");
    let inner = block.inner(area);

    let Some(r) = &app.report else {
        f.render_widget(block, area);
        return;
    };
    let rows = r.peers.iter().map(|p| {
        let (mode, mode_color) = match p.mode {
            ConnMode::Direct => ("direct", Color::Green),
            ConnMode::Punching => ("punching", Color::Yellow),
            ConnMode::Pending => ("pending", Color::DarkGray),
        };
        let rtt = p
            .rtt_ms
            .map(|v| format!("{v:.0}ms"))
            .unwrap_or_else(|| "—".into());
        Row::new(vec![
            Cell::from(p.vip.clone()),
            Cell::from(p.name.clone()),
            Cell::from(p.node_id.to_string()),
            Cell::from(mode).style(Style::default().fg(mode_color)),
            Cell::from(p.endpoint.clone().unwrap_or_else(|| "—".into())),
            Cell::from(rtt),
            Cell::from(human_rate(p.rx_bps)),
            Cell::from(human_rate(p.tx_bps)),
        ])
    });
    let header = Row::new(vec![
        "VIP", "NAME", "ID", "MODE", "ENDPOINT", "RTT", "RX", "TX",
    ])
    .style(Style::default().fg(Color::DarkGray))
    .bottom_margin(1);
    let table = Table::new(
        rows,
        [
            Constraint::Length(12),
            Constraint::Min(10),
            Constraint::Length(4),
            Constraint::Length(8),
            Constraint::Length(21),
            Constraint::Length(7),
            Constraint::Length(10),
            Constraint::Length(10),
        ],
    )
    .header(header)
    .block(block)
    .row_highlight_style(
        Style::default()
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("▶ ");
    let _ = inner;
    f.render_stateful_widget(table, area, &mut app.state);
}

fn draw_charts(f: &mut ratatui::Frame, area: ratatui::layout::Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    for (i, (title, hist, color)) in [
        (" RX ", &app.rx_hist, Color::Green),
        (" TX ", &app.tx_hist, Color::Cyan),
    ]
    .into_iter()
    .enumerate()
    {
        let block = Block::default().borders(Borders::ALL).title(title);
        let data: Vec<u64> = hist.iter().copied().collect();
        let max_label = data
            .iter()
            .max()
            .map(|m| human_rate(*m as f64))
            .unwrap_or_else(|| "0 B/s".into());
        let block = block.title_bottom(Line::from(format!("peak {max_label}")).right_aligned());
        let spark = Sparkline::default()
            .block(block)
            .data(&data)
            .style(Style::default().fg(color));
        f.render_widget(spark, chunks[i]);
    }
}

fn draw_events(f: &mut ratatui::Frame, area: ratatui::layout::Rect, app: &App) {
    let block = Block::default().borders(Borders::ALL).title(" Events ");
    let inner = block.inner(area);
    let height = inner.height as usize;

    let mut lines: Vec<Line> = app
        .report
        .as_ref()
        .map(|r| r.events.iter().map(|e| Line::from(e.clone())).collect())
        .unwrap_or_default();
    lines.extend(
        app.notes
            .iter()
            .map(|n| Line::from(Span::styled(n.clone(), Style::default().fg(Color::Cyan)))),
    );
    if let Some(err) = &app.last_err {
        lines.push(Line::from(Span::styled(
            format!("ipc: {err}"),
            Style::default().fg(Color::Red),
        )));
    }
    let start = lines.len().saturating_sub(height);
    let view: Vec<Line> = lines.into_iter().skip(start).collect();
    f.render_widget(
        Paragraph::new(view).block(block).wrap(Wrap { trim: true }),
        area,
    );
}

fn fmt_uptime(secs: u64) -> String {
    let (h, m, s) = (secs / 3600, secs / 60 % 60, secs % 60);
    let d = secs / 86400;
    if d > 0 {
        format!("{d}d{h:02}h")
    } else if h > 0 {
        format!("{h}h{m:02}m")
    } else {
        format!("{m}m{s:02}s")
    }
}
