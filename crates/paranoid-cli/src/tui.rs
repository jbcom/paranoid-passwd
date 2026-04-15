use anyhow::Context;
use arboard::Clipboard;
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
#[cfg(test)]
use paranoid_core::FrameworkId;
use paranoid_core::{
    AuditStage, CharsetOptions, CharsetSpec, GenerationReport, ParanoidRequest,
    combined_framework_requirements, execute_request, secure_preview,
};
#[cfg(test)]
use ratatui::backend::TestBackend;
use ratatui::{
    Frame, Terminal,
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Gauge, List, ListItem, Paragraph, Tabs, Wrap},
};
use std::{
    io,
    sync::mpsc::{self, Receiver},
    thread,
    time::Duration,
};

const BG: Color = Color::Rgb(8, 12, 20);
const PANEL: Color = Color::Rgb(13, 17, 25);
const TEXT: Color = Color::Rgb(228, 231, 242);
const GREEN: Color = Color::Rgb(52, 211, 153);
const BLUE: Color = Color::Rgb(96, 165, 250);
const AMBER: Color = Color::Rgb(251, 191, 36);
const RED: Color = Color::Rgb(248, 113, 113);
const PURPLE: Color = Color::Rgb(167, 139, 250);

#[derive(Debug, Clone, PartialEq, Eq)]
enum Screen {
    Configure,
    Audit,
    Results,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FocusField {
    Length,
    Count,
    BatchSize,
    Lowercase,
    Uppercase,
    Digits,
    Symbols,
    Space,
    ExcludeAmbiguous,
    Framework(usize),
    MinLowercase,
    MinUppercase,
    MinDigits,
    MinSymbols,
    CustomCharset,
    Launch,
}

#[derive(Debug)]
enum WorkerMessage {
    Stage(AuditStage),
    Done(Box<anyhow::Result<GenerationReport>>),
}

#[derive(Debug)]
struct App {
    screen: Screen,
    request: ParanoidRequest,
    focus_index: usize,
    editing_custom_charset: bool,
    current_stage: Option<AuditStage>,
    completed_stages: Vec<AuditStage>,
    worker: Option<Receiver<WorkerMessage>>,
    report: Option<GenerationReport>,
    status: String,
    detail_tab: usize,
}

impl Default for App {
    fn default() -> Self {
        Self {
            screen: Screen::Configure,
            request: ParanoidRequest {
                charset: CharsetSpec::Options(CharsetOptions::default()),
                ..ParanoidRequest::default()
            },
            focus_index: 0,
            editing_custom_charset: false,
            current_stage: None,
            completed_stages: Vec::new(),
            worker: None,
            report: None,
            status: "Use arrows to adjust values, Space to toggle, Enter to run.".to_string(),
            detail_tab: 0,
        }
    }
}

impl App {
    fn focus_order(&self) -> Vec<FocusField> {
        let mut fields = vec![
            FocusField::Length,
            FocusField::Count,
            FocusField::BatchSize,
            FocusField::Lowercase,
            FocusField::Uppercase,
            FocusField::Digits,
            FocusField::Symbols,
            FocusField::Space,
            FocusField::ExcludeAmbiguous,
        ];
        fields.extend((0..paranoid_core::frameworks().len()).map(FocusField::Framework));
        fields.extend([
            FocusField::MinLowercase,
            FocusField::MinUppercase,
            FocusField::MinDigits,
            FocusField::MinSymbols,
            FocusField::CustomCharset,
            FocusField::Launch,
        ]);
        fields
    }

    fn selected_field(&self) -> FocusField {
        self.focus_order()
            .get(self.focus_index)
            .cloned()
            .unwrap_or(FocusField::Length)
    }

    fn charset_options_mut(&mut self) -> &mut CharsetOptions {
        match &mut self.request.charset {
            CharsetSpec::Options(options) => options,
            CharsetSpec::NamedOrLiteral(_) => unreachable!("TUI always uses charset options"),
        }
    }

    fn charset_options(&self) -> &CharsetOptions {
        match &self.request.charset {
            CharsetSpec::Options(options) => options,
            CharsetSpec::NamedOrLiteral(_) => unreachable!("TUI always uses charset options"),
        }
    }

    fn adjust_focus(&mut self, delta: isize) {
        let len = self.focus_order().len() as isize;
        let next = (self.focus_index as isize + delta).clamp(0, len - 1);
        self.focus_index = next as usize;
    }

    fn toggle_or_adjust(&mut self, increment: isize) {
        match self.selected_field() {
            FocusField::Length => {
                self.request.length = self
                    .request
                    .length
                    .saturating_add_signed(increment)
                    .clamp(1, 256);
            }
            FocusField::Count => {
                self.request.count = self
                    .request
                    .count
                    .saturating_add_signed(increment)
                    .clamp(1, 10);
            }
            FocusField::BatchSize => {
                self.request.batch_size = self
                    .request
                    .batch_size
                    .saturating_add_signed(increment * 25)
                    .clamp(25, 2_000);
            }
            FocusField::Lowercase => self.charset_options_mut().include_lowercase = increment >= 0,
            FocusField::Uppercase => self.charset_options_mut().include_uppercase = increment >= 0,
            FocusField::Digits => self.charset_options_mut().include_digits = increment >= 0,
            FocusField::Symbols => self.charset_options_mut().include_symbols = increment >= 0,
            FocusField::Space => self.charset_options_mut().include_space = increment >= 0,
            FocusField::ExcludeAmbiguous => {
                self.charset_options_mut().exclude_ambiguous = increment >= 0;
            }
            FocusField::Framework(index) => {
                if let Some(framework) = paranoid_core::frameworks().get(index) {
                    if self.request.selected_frameworks.contains(&framework.id) {
                        self.request
                            .selected_frameworks
                            .retain(|item| item != &framework.id);
                    } else {
                        self.request.selected_frameworks.push(framework.id);
                    }
                    self.apply_frameworks();
                }
            }
            FocusField::MinLowercase => {
                self.request.requirements.min_lowercase = self
                    .request
                    .requirements
                    .min_lowercase
                    .saturating_add_signed(increment)
                    .clamp(0, 128);
            }
            FocusField::MinUppercase => {
                self.request.requirements.min_uppercase = self
                    .request
                    .requirements
                    .min_uppercase
                    .saturating_add_signed(increment)
                    .clamp(0, 128);
            }
            FocusField::MinDigits => {
                self.request.requirements.min_digits = self
                    .request
                    .requirements
                    .min_digits
                    .saturating_add_signed(increment)
                    .clamp(0, 128);
            }
            FocusField::MinSymbols => {
                self.request.requirements.min_symbols = self
                    .request
                    .requirements
                    .min_symbols
                    .saturating_add_signed(increment)
                    .clamp(0, 128);
            }
            FocusField::CustomCharset | FocusField::Launch => {}
        }
    }

    fn apply_frameworks(&mut self) {
        let combined = combined_framework_requirements(&self.request.selected_frameworks);
        self.request.length = self.request.length.max(combined.min_length.max(8));
        self.charset_options_mut().apply_frameworks(&combined);
    }

    fn start_audit(&mut self) {
        if let Err(error) = self.request.resolve() {
            self.status = format!("Blocked: {error}");
            self.screen = Screen::Configure;
            return;
        }
        self.current_stage = Some(AuditStage::Generate);
        self.completed_stages.clear();
        self.detail_tab = 0;
        self.report = None;
        self.screen = Screen::Audit;
        self.status = "Running password generation and statistical audit...".to_string();
        let request = self.request.clone();
        let (tx, rx) = mpsc::channel::<WorkerMessage>();
        self.worker = Some(rx);

        thread::spawn(move || {
            let result = execute_request(&request, true, |stage| {
                let _ = tx.send(WorkerMessage::Stage(stage));
            })
            .map_err(anyhow::Error::from);
            let _ = tx.send(WorkerMessage::Done(Box::new(result)));
        });
    }

    fn copy_password(&mut self) {
        if let Some(password) = self
            .report
            .as_ref()
            .and_then(|report| report.passwords.first())
        {
            match Clipboard::new()
                .and_then(|mut clipboard| clipboard.set_text(password.value.clone()))
            {
                Ok(()) => {
                    self.status = "Copied password to the system clipboard.".to_string();
                }
                Err(error) => {
                    self.status = format!("Clipboard unavailable: {error}");
                }
            }
        }
    }

    fn poll_worker(&mut self) {
        let messages = self
            .worker
            .as_ref()
            .map(|receiver| receiver.try_iter().collect::<Vec<_>>())
            .unwrap_or_default();
        let mut clear_worker = false;
        for message in messages {
            match message {
                WorkerMessage::Stage(stage) => {
                    if !self.completed_stages.contains(&stage)
                        && !matches!(stage, AuditStage::Complete)
                    {
                        self.completed_stages.push(stage);
                    }
                    self.current_stage = Some(stage);
                }
                WorkerMessage::Done(result) => {
                    clear_worker = true;
                    match *result {
                        Ok(report) => {
                            self.status =
                                "Audit complete. Review the results or copy the password."
                                    .to_string();
                            self.report = Some(report);
                            self.detail_tab = 0;
                            self.screen = Screen::Results;
                        }
                        Err(error) => {
                            self.status = format!("Audit failed: {error}");
                            self.current_stage = None;
                            self.completed_stages.clear();
                            self.screen = Screen::Configure;
                        }
                    }
                }
            }
        }
        if clear_worker {
            self.worker = None;
        }
    }

    fn handle_key(&mut self, key: KeyEvent) -> bool {
        if self.editing_custom_charset {
            return self.handle_custom_charset_key(key);
        }

        match self.screen {
            Screen::Configure => self.handle_configure_key(key),
            Screen::Audit => self.handle_audit_key(key),
            Screen::Results => self.handle_results_key(key),
        }
    }

    fn handle_custom_charset_key(&mut self, key: KeyEvent) -> bool {
        let custom = &mut self.charset_options_mut().custom_charset;
        let buffer = custom.get_or_insert_with(String::new);
        match key.code {
            KeyCode::Esc | KeyCode::Enter => self.editing_custom_charset = false,
            KeyCode::Backspace => {
                buffer.pop();
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => buffer.clear(),
            KeyCode::Char(ch) if (32..=126).contains(&(ch as u32)) => buffer.push(ch),
            _ => {}
        }
        false
    }

    fn handle_configure_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('q') => true,
            KeyCode::Up => {
                self.adjust_focus(-1);
                false
            }
            KeyCode::Down | KeyCode::Tab => {
                self.adjust_focus(1);
                false
            }
            KeyCode::Left => {
                self.toggle_or_adjust(-1);
                false
            }
            KeyCode::Right => {
                self.toggle_or_adjust(1);
                false
            }
            KeyCode::Char(' ') => {
                self.toggle_or_adjust(1);
                false
            }
            KeyCode::Enter => {
                match self.selected_field() {
                    FocusField::CustomCharset => self.editing_custom_charset = true,
                    FocusField::Launch => self.start_audit(),
                    _ => self.toggle_or_adjust(1),
                }
                false
            }
            _ => false,
        }
    }

    fn handle_audit_key(&mut self, key: KeyEvent) -> bool {
        matches!(key.code, KeyCode::Char('q'))
    }

    fn handle_results_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('q') => true,
            KeyCode::Left => {
                self.detail_tab = self.detail_tab.saturating_sub(1);
                false
            }
            KeyCode::Right | KeyCode::Tab => {
                self.detail_tab = (self.detail_tab + 1) % 6;
                false
            }
            KeyCode::Char('r') => {
                self.screen = Screen::Configure;
                self.current_stage = None;
                self.completed_stages.clear();
                self.detail_tab = 0;
                self.report = None;
                false
            }
            KeyCode::Char('c') => {
                self.copy_password();
                false
            }
            _ => false,
        }
    }

    fn validation_message(&self) -> (String, Style) {
        match self.request.resolve() {
            Ok(resolved) => {
                let bits = (resolved.charset.len() as f64).log2() * resolved.length as f64;
                (
                    format!(
                        "Ready: {} chars, {} passwords, {:.2} bits of entropy per generated password.",
                        resolved.charset.len(),
                        resolved.count,
                        bits
                    ),
                    Style::default().fg(GREEN),
                )
            }
            Err(error) => (error.to_string(), Style::default().fg(RED)),
        }
    }
}

pub fn run() -> anyhow::Result<()> {
    enable_raw_mode().context("failed to enable raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("failed to enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("failed to initialize terminal")?;
    terminal.clear().ok();
    let result = run_app(&mut terminal, App::default());
    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();
    terminal.show_cursor().ok();
    result
}

fn run_app<B: Backend>(terminal: &mut Terminal<B>, mut app: App) -> anyhow::Result<()> {
    loop {
        app.poll_worker();
        terminal
            .draw(|frame| render(frame, &app))
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        if event::poll(Duration::from_millis(80))? {
            if let Event::Key(key) = event::read()? {
                if app.handle_key(key) {
                    break;
                }
            }
        }
    }
    Ok(())
}

fn render(frame: &mut Frame<'_>, app: &App) {
    let area = frame.area();
    frame.render_widget(Block::default().style(Style::default().bg(BG)), area);
    match app.screen {
        Screen::Configure => render_configure(frame, area, app),
        Screen::Audit => render_audit(frame, area, app),
        Screen::Results => render_results(frame, area, app),
    }
}

fn render_configure(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(area);
    render_header(
        frame,
        chunks[0],
        "Configure",
        "Tune the same flow the old web wizard exposed.",
    );

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(chunks[1]);

    let order = app.focus_order();
    let options = app.charset_options();
    let mut items = vec![
        field_item(
            &FocusField::Length,
            app,
            format!("Password length: {}", app.request.length),
        ),
        field_item(
            &FocusField::Count,
            app,
            format!("Number of passwords: {}", app.request.count),
        ),
        field_item(
            &FocusField::BatchSize,
            app,
            format!("Audit batch size: {}", app.request.batch_size),
        ),
        field_item(
            &FocusField::Lowercase,
            app,
            format!("Lowercase [a-z]: {}", enabled(options.include_lowercase)),
        ),
        field_item(
            &FocusField::Uppercase,
            app,
            format!("Uppercase [A-Z]: {}", enabled(options.include_uppercase)),
        ),
        field_item(
            &FocusField::Digits,
            app,
            format!("Digits [0-9]: {}", enabled(options.include_digits)),
        ),
        field_item(
            &FocusField::Symbols,
            app,
            format!("Symbols: {}", enabled(options.include_symbols)),
        ),
        field_item(
            &FocusField::Space,
            app,
            format!(
                "Extended printable ASCII (space): {}",
                enabled(options.include_space)
            ),
        ),
        field_item(
            &FocusField::ExcludeAmbiguous,
            app,
            format!(
                "Exclude ambiguous characters: {}",
                enabled(options.exclude_ambiguous)
            ),
        ),
    ];
    for (index, framework) in paranoid_core::frameworks().iter().enumerate() {
        items.push(field_item(
            &FocusField::Framework(index),
            app,
            format!(
                "{}: {}",
                framework.name,
                enabled(app.request.selected_frameworks.contains(&framework.id))
            ),
        ));
    }
    items.extend([
        field_item(
            &FocusField::MinLowercase,
            app,
            format!("Min lowercase: {}", app.request.requirements.min_lowercase),
        ),
        field_item(
            &FocusField::MinUppercase,
            app,
            format!("Min uppercase: {}", app.request.requirements.min_uppercase),
        ),
        field_item(
            &FocusField::MinDigits,
            app,
            format!("Min digits: {}", app.request.requirements.min_digits),
        ),
        field_item(
            &FocusField::MinSymbols,
            app,
            format!("Min symbols: {}", app.request.requirements.min_symbols),
        ),
        field_item(
            &FocusField::CustomCharset,
            app,
            format!(
                "Custom charset override: {}",
                options
                    .custom_charset
                    .as_deref()
                    .filter(|value| !value.is_empty())
                    .map(secure_preview)
                    .unwrap_or_else(|| "off".to_string())
            ),
        ),
        field_item(
            &FocusField::Launch,
            app,
            "Generate + Run 7-Layer Audit".to_string(),
        ),
    ]);

    let list = List::new(items)
        .block(
            Block::default()
                .title("Wizard")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BLUE))
                .style(Style::default().bg(PANEL).fg(TEXT)),
        )
        .highlight_style(Style::default().add_modifier(Modifier::BOLD));
    frame.render_widget(list, body[0]);

    let (validation, validation_style) = app.validation_message();
    let resolved = app.request.resolve().ok();
    let selected_frameworks = app
        .request
        .selected_frameworks
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let detail_text = Text::from(vec![
        Line::from(vec![
            Span::styled(
                "Branding",
                Style::default().fg(GREEN).add_modifier(Modifier::BOLD),
            ),
            Span::raw("  deep navy + emerald, monospace-heavy, fail-closed."),
        ]),
        Line::raw(""),
        Line::from(format!(
            "Effective charset: {}",
            resolved
                .as_ref()
                .map(|value| format!("{} characters", value.charset.len()))
                .unwrap_or_else(|| "invalid".to_string())
        )),
        Line::from(format!(
            "Manual requirements: {} total constrained characters",
            app.request.requirements.min_lowercase
                + app.request.requirements.min_uppercase
                + app.request.requirements.min_digits
                + app.request.requirements.min_symbols
        )),
        Line::from(format!(
            "Frameworks: {}",
            if selected_frameworks.is_empty() {
                "none".to_string()
            } else {
                selected_frameworks.join(", ")
            }
        )),
        Line::raw(""),
        Line::styled(validation, validation_style),
        Line::raw(""),
        Line::from("Controls"),
        Line::from("  Up/Down: move"),
        Line::from("  Left/Right: adjust"),
        Line::from("  Space: toggle"),
        Line::from("  Enter: edit/run"),
        Line::from("  q: quit"),
        Line::raw(""),
        Line::styled(app.status.as_str(), Style::default().fg(AMBER)),
    ]);
    let detail = Paragraph::new(detail_text)
        .block(
            Block::default()
                .title("Audit Preview")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(GREEN))
                .style(Style::default().bg(PANEL).fg(TEXT)),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(detail, body[1]);

    let footer = format!(
        "Selected field: {} of {}{}",
        app.focus_index + 1,
        order.len(),
        if app.editing_custom_charset {
            "  — editing custom charset"
        } else {
            ""
        }
    );
    frame.render_widget(
        Paragraph::new(footer).style(Style::default().fg(TEXT).bg(BG)),
        chunks[2],
    );
}

fn render_audit(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(area);
    render_header(
        frame,
        chunks[0],
        "Generate & Audit",
        "Running the seven-layer audit on a native Rust core.",
    );

    let progress = stage_progress(app.current_stage);
    frame.render_widget(
        Gauge::default()
            .block(
                Block::default()
                    .title("Progress")
                    .borders(Borders::ALL)
                    .style(Style::default().bg(PANEL).fg(TEXT)),
            )
            .gauge_style(Style::default().fg(GREEN).bg(PANEL))
            .ratio(progress)
            .label(format!("{:.0}%", progress * 100.0)),
        chunks[1],
    );

    let items = [
        AuditStage::Generate,
        AuditStage::ChiSquared,
        AuditStage::SerialCorrelation,
        AuditStage::CollisionDetection,
        AuditStage::EntropyProofs,
        AuditStage::PatternDetection,
        AuditStage::ThreatAssessment,
    ]
    .into_iter()
    .map(|stage| {
        let status = if app.completed_stages.contains(&stage) {
            Span::styled(
                "OK",
                Style::default().fg(GREEN).add_modifier(Modifier::BOLD),
            )
        } else if app.current_stage == Some(stage) {
            Span::styled(
                "RUN",
                Style::default().fg(BLUE).add_modifier(Modifier::BOLD),
            )
        } else {
            Span::styled("PEND", Style::default().fg(AMBER))
        };
        ListItem::new(Line::from(vec![
            Span::raw(format!("{:<28}", stage.label())),
            Span::raw(" "),
            status,
        ]))
    })
    .collect::<Vec<_>>();

    frame.render_widget(
        List::new(items).block(
            Block::default()
                .title("Stages")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BLUE))
                .style(Style::default().bg(PANEL).fg(TEXT)),
        ),
        chunks[2],
    );

    frame.render_widget(
        Paragraph::new(app.status.clone())
            .style(Style::default().fg(TEXT).bg(BG))
            .wrap(Wrap { trim: false }),
        chunks[3],
    );
}

fn render_results(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let Some(report) = &app.report else {
        return;
    };
    let Some(audit) = &report.audit else {
        return;
    };
    let Some(primary) = report.passwords.first() else {
        return;
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(5),
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(area);
    render_header(
        frame,
        chunks[0],
        "Results",
        "Native generation complete. Review the verdict and derived details.",
    );

    let password_block = Paragraph::new(Text::from(vec![
        Line::styled(
            "primary",
            Style::default().fg(BLUE).add_modifier(Modifier::BOLD),
        ),
        Line::styled(
            primary.value.as_str(),
            Style::default().fg(GREEN).add_modifier(Modifier::BOLD),
        ),
        Line::raw(format!("SHA-256: {}", primary.sha256_hex)),
        Line::raw(format!(
            "Selected frameworks: {}",
            selected_framework_summary(primary)
        )),
        Line::raw(format!(
            "Additional passwords: {}",
            report.passwords.len().saturating_sub(1)
        )),
        Line::raw(format!(
            "Verdict: {}",
            if audit.overall_pass { "PASS" } else { "REVIEW" }
        )),
    ]))
    .block(
        Block::default()
            .title("Primary Password")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(GREEN))
            .style(Style::default().bg(PANEL).fg(TEXT)),
    );
    frame.render_widget(password_block, chunks[1]);

    let titles = [
        "Summary",
        "Compliance",
        "Entropy",
        "Stats",
        "Threats",
        "Self-Audit",
    ]
    .into_iter()
    .map(Line::from)
    .collect::<Vec<_>>();
    frame.render_widget(
        Tabs::new(titles)
            .select(app.detail_tab)
            .block(
                Block::default()
                    .title("Detail Views")
                    .borders(Borders::ALL)
                    .style(Style::default().bg(PANEL).fg(TEXT)),
            )
            .highlight_style(Style::default().fg(BLUE).add_modifier(Modifier::BOLD)),
        chunks[2],
    );

    frame.render_widget(
        Paragraph::new(result_tab_text(app.detail_tab, report))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(BLUE))
                    .style(Style::default().bg(PANEL).fg(TEXT)),
            )
            .wrap(Wrap { trim: false }),
        chunks[3],
    );

    frame.render_widget(
        Paragraph::new(format!(
            "{}  Controls: Left/Right switch detail tabs, c copies the password, r returns to configuration, q quits.",
            app.status
        ))
        .style(Style::default().fg(TEXT).bg(BG))
        .wrap(Wrap { trim: false }),
        chunks[4],
    );
}

fn render_header(frame: &mut Frame<'_>, area: Rect, title: &str, subtitle: &str) {
    frame.render_widget(
        Paragraph::new(Text::from(vec![
            Line::styled(
                format!("paranoid-passwd · {title}"),
                Style::default().fg(GREEN).add_modifier(Modifier::BOLD),
            ),
            Line::styled(subtitle, Style::default().fg(TEXT)),
        ]))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(GREEN))
                .style(Style::default().bg(PANEL)),
        ),
        area,
    );
}

fn stage_progress(stage: Option<AuditStage>) -> f64 {
    match stage {
        None => 0.0,
        Some(AuditStage::Generate) => 1.0 / 7.0,
        Some(AuditStage::ChiSquared) => 2.0 / 7.0,
        Some(AuditStage::SerialCorrelation) => 3.0 / 7.0,
        Some(AuditStage::CollisionDetection) => 4.0 / 7.0,
        Some(AuditStage::EntropyProofs) => 5.0 / 7.0,
        Some(AuditStage::PatternDetection) => 6.0 / 7.0,
        Some(AuditStage::ThreatAssessment) | Some(AuditStage::Complete) => 1.0,
    }
}

fn enabled(value: bool) -> &'static str {
    if value { "ON" } else { "off" }
}

fn field_item(field: &FocusField, app: &App, text: String) -> ListItem<'static> {
    let selected = &app.selected_field() == field;
    let prefix = if selected { "› " } else { "  " };
    let style = if selected {
        Style::default().fg(GREEN).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(TEXT)
    };
    ListItem::new(Line::from(vec![
        Span::styled(prefix.to_string(), style),
        Span::styled(text, style),
    ]))
}

fn result_tab_text(tab: usize, report: &GenerationReport) -> Text<'static> {
    let audit = report
        .audit
        .as_ref()
        .expect("results always carry an audit");
    let primary = report
        .passwords
        .first()
        .expect("results always carry at least one generated password");
    match tab {
        0 => Text::from(vec![
            Line::styled(
                if audit.overall_pass {
                    "CRYPTOGRAPHICALLY SOUND"
                } else {
                    "REVIEW FLAGGED ITEMS"
                },
                Style::default()
                    .fg(if audit.overall_pass { GREEN } else { RED })
                    .add_modifier(Modifier::BOLD),
            ),
            Line::raw(""),
            Line::raw(format!("Primary: {}", secure_preview(&primary.value))),
            Line::raw(format!("Hash: {}", primary.sha256_hex)),
            Line::raw(format!("Pattern issues: {}", primary.pattern_issues)),
            Line::raw(format!(
                "Character mix: lower={} upper={} digits={} symbols={}",
                primary.character_counts.lowercase,
                primary.character_counts.uppercase,
                primary.character_counts.digits,
                primary.character_counts.symbols
            )),
            Line::raw(format!(
                "Primary verdict: {}",
                if primary.all_pass { "PASS" } else { "REVIEW" }
            )),
            Line::raw(format!(
                "Generator-wide statistical verdict: {}",
                if audit.chi2_pass && audit.serial_pass && audit.collision_pass {
                    "PASS"
                } else {
                    "REVIEW"
                }
            )),
            Line::raw(""),
            Line::raw("Additional passwords"),
            Line::raw(additional_password_summary(report)),
        ]),
        1 => {
            let mut lines = vec![
                Line::raw(format!(
                    "Selected framework roll-up: {}",
                    if audit.selected_frameworks_pass {
                        "PASS"
                    } else {
                        "REVIEW"
                    }
                )),
                Line::raw(""),
            ];
            for (index, password) in report.passwords.iter().enumerate() {
                let label = if index == 0 {
                    "primary".to_string()
                } else {
                    format!("additional[{}]", index + 1)
                };
                let selected = password
                    .compliance
                    .iter()
                    .filter(|status| status.selected)
                    .map(|status| {
                        format!("{} {}", if status.passed { "✓" } else { "✗" }, status.name)
                    })
                    .collect::<Vec<_>>();
                if selected.is_empty() {
                    lines.push(Line::raw(format!("{label}: no frameworks selected")));
                } else {
                    lines.push(Line::raw(format!(
                        "{label}: {} ({})",
                        selected.join(", "),
                        if password.selected_compliance_pass {
                            "pass"
                        } else {
                            "review"
                        }
                    )));
                }
            }
            Text::from(lines)
        }
        2 => Text::from(vec![
            Line::raw(format!("Charset size: {}", audit.charset_size)),
            Line::raw(format!("Password length: {}", audit.password_length)),
            Line::raw(format!(
                "Bits per character: {:.4}",
                audit.entropy.bits_per_char
            )),
            Line::raw(format!(
                "Total entropy: {:.2} bits",
                audit.entropy.total_entropy
            )),
            Line::raw(format!(
                "Search space: 10^{:.2}",
                audit.entropy.log10_search_space
            )),
            Line::raw(format!(
                "Brute-force @ 1T/s: {:.2e} years",
                audit.entropy.brute_force_years
            )),
        ]),
        3 => Text::from(vec![
            Line::raw(format!(
                "Chi-squared: {:.2} (df={}, p={:.4})",
                audit.chi2_statistic, audit.chi2_df, audit.chi2_p_value
            )),
            Line::raw(format!(
                "Serial correlation: {:.6}",
                audit.serial_correlation
            )),
            Line::raw(format!(
                "Duplicates: {} / {}",
                audit.duplicates, audit.batch_size
            )),
            Line::raw(format!(
                "Rejection-sampling boundary: {} ({:.4}% rejected)",
                audit.rejection_max_valid, audit.rejection_rate_pct
            )),
            Line::raw(format!(
                "50% collision threshold: {:.2e}",
                audit.entropy.passwords_for_50pct
            )),
            Line::raw(format!(
                "Per-password verdicts: {}",
                if audit.passwords_all_pass {
                    "all pass"
                } else {
                    "review flagged items"
                }
            )),
        ]),
        4 => Text::from(vec![
            Line::styled(
                "Threat Model",
                Style::default().fg(PURPLE).add_modifier(Modifier::BOLD),
            ),
            Line::raw("T1 Training-data leakage — mitigated by OpenSSL-backed OS entropy."),
            Line::raw("T2 Token-distribution bias — mitigated by rejection sampling."),
            Line::raw("T3 Deterministic regeneration — mitigated by hardware entropy."),
            Line::raw("T4 Prompt injection steering — residual risk in source review."),
            Line::raw("T5 Hallucinated security claims — residual risk, review the math."),
            Line::raw("T6 Screen exposure — operational risk, clear copied passwords."),
        ]),
        _ => Text::from(vec![
            Line::styled(
                "Self-Audit",
                Style::default().fg(AMBER).add_modifier(Modifier::BOLD),
            ),
            Line::raw(
                "This rewrite keeps the original product intent but removes the browser trust boundary.",
            ),
            Line::raw("RNG and hashing are delegated to OpenSSL via Rust bindings."),
            Line::raw(
                "Batch statistics now describe the generation method while each emitted password gets its own verdict.",
            ),
            Line::raw(
                "Have a human cryptographer review the policy thresholds and statistical formulas before production use.",
            ),
        ]),
    }
}

fn additional_password_summary(report: &GenerationReport) -> String {
    let additional = report
        .passwords
        .iter()
        .skip(1)
        .enumerate()
        .map(|(index, password)| {
            format!(
                "  additional[{}]: {} ({})",
                index + 2,
                secure_preview(&password.value),
                if password.all_pass { "pass" } else { "review" }
            )
        })
        .collect::<Vec<_>>();

    if additional.is_empty() {
        "  none".to_string()
    } else {
        additional.join("\n")
    }
}

fn selected_framework_summary(password: &paranoid_core::GeneratedPassword) -> String {
    let selected = password
        .compliance
        .iter()
        .filter(|status| status.selected)
        .map(|status| format!("{}={}", status.id, if status.passed { "OK" } else { "no" }))
        .collect::<Vec<_>>();

    if selected.is_empty() {
        "none".to_string()
    } else {
        selected.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn render_to_string(app: &App) -> String {
        let backend = TestBackend::new(100, 36);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal.draw(|frame| render(frame, app)).expect("draw");
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>()
    }

    fn wait_for_worker(app: &mut App) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while app.worker.is_some() && Instant::now() < deadline {
            app.poll_worker();
            std::thread::sleep(Duration::from_millis(10));
        }
        app.poll_worker();
    }

    #[test]
    fn configure_screen_renders_wizard_copy() {
        let app = App::default();
        let rendered = render_to_string(&app);
        assert!(rendered.contains("Configure"));
        assert!(rendered.contains("Generate + Run 7-Layer Audit"));
    }

    #[test]
    fn framework_toggle_bumps_length_and_charset_requirements() {
        let mut app = App::default();
        app.request.length = 8;
        app.focus_index = app
            .focus_order()
            .iter()
            .position(|field| matches!(field, FocusField::Framework(1)))
            .expect("pci framework");
        app.toggle_or_adjust(1);

        assert!(
            app.request
                .selected_frameworks
                .contains(&FrameworkId::PciDss)
        );
        assert!(app.request.length >= 12);
        assert!(app.charset_options().include_uppercase);
        assert!(app.charset_options().include_digits);
    }

    #[test]
    fn results_view_contains_entropy_metrics() {
        let app = App {
            report: Some(
                execute_request(&ParanoidRequest::default(), true, |_| {}).expect("report"),
            ),
            screen: Screen::Results,
            detail_tab: 2,
            ..App::default()
        };

        let rendered = render_to_string(&app);
        assert!(rendered.contains("Total entropy"));
        assert!(rendered.contains("Brute-force"));
    }

    #[test]
    fn invalid_launch_stays_on_configure_and_sets_blocked_status() {
        let mut app = App::default();
        app.request.length = 4;
        app.request.requirements.min_lowercase = 5;

        app.start_audit();

        assert_eq!(app.screen, Screen::Configure);
        assert!(app.status.contains("Blocked:"));
        assert!(app.worker.is_none());
    }

    #[test]
    fn results_summary_explicitly_labels_absent_additional_passwords() {
        let app = App {
            report: Some(
                execute_request(&ParanoidRequest::default(), true, |_| {}).expect("report"),
            ),
            screen: Screen::Results,
            detail_tab: 0,
            ..App::default()
        };

        let rendered = render_to_string(&app);
        assert!(rendered.contains("Primary Password"));
        assert!(rendered.contains("Additional passwords"));
        assert!(rendered.contains("none"));
    }

    #[test]
    fn compliance_tab_distinguishes_primary_and_additional_passwords() {
        let request = ParanoidRequest {
            count: 2,
            selected_frameworks: vec![FrameworkId::Nist],
            ..ParanoidRequest::default()
        };
        let app = App {
            report: Some(execute_request(&request, true, |_| {}).expect("report")),
            screen: Screen::Results,
            detail_tab: 1,
            ..App::default()
        };

        let rendered = render_to_string(&app);
        assert!(rendered.contains("Selected framework roll-up"));
        assert!(rendered.contains("primary"));
        assert!(rendered.contains("additional[2]"));
        assert!(rendered.contains("NIST"));
    }

    #[test]
    fn full_flow_transitions_from_configure_to_results_and_back() {
        let mut app = App::default();
        app.focus_index = app
            .focus_order()
            .iter()
            .position(|field| matches!(field, FocusField::Launch))
            .expect("launch field");

        let should_quit = app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(!should_quit);
        assert_eq!(app.screen, Screen::Audit);
        assert!(app.worker.is_some());

        wait_for_worker(&mut app);

        assert_eq!(app.screen, Screen::Results);
        assert!(app.report.is_some());

        let should_quit = app.handle_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE));
        assert!(!should_quit);
        assert_eq!(app.screen, Screen::Configure);
        assert!(app.report.is_none());
        assert_eq!(app.detail_tab, 0);
    }
}
