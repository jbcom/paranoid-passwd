use arboard::Clipboard;
use iced::{
    Alignment, Element, Length, Task, Theme,
    widget::{button, checkbox, column, container, row, scrollable, text, text_input},
};
use paranoid_core::{
    AuditStage, CharsetOptions, CharsetSpec, FrameworkId, GenerationReport, ParanoidRequest,
    combined_framework_requirements, execute_request,
};
use std::{
    sync::mpsc::{self, Receiver},
    thread,
    time::Duration,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    Configure,
    Audit,
    Results,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DetailTab {
    Summary,
    Compliance,
    Entropy,
    Stats,
    Threats,
    SelfAudit,
}

impl DetailTab {
    const ALL: [Self; 6] = [
        Self::Summary,
        Self::Compliance,
        Self::Entropy,
        Self::Stats,
        Self::Threats,
        Self::SelfAudit,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Summary => "Summary",
            Self::Compliance => "Compliance",
            Self::Entropy => "Entropy",
            Self::Stats => "Stats",
            Self::Threats => "Threats",
            Self::SelfAudit => "Self-Audit",
        }
    }
}

#[derive(Debug)]
enum WorkerMessage {
    Stage(AuditStage),
    Done(Box<Result<GenerationReport, String>>),
}

#[derive(Debug, Clone)]
enum Message {
    LengthChanged(String),
    CountChanged(String),
    BatchChanged(String),
    MinLowerChanged(String),
    MinUpperChanged(String),
    MinDigitsChanged(String),
    MinSymbolsChanged(String),
    ToggleLowercase(bool),
    ToggleUppercase(bool),
    ToggleDigits(bool),
    ToggleSymbols(bool),
    ToggleSpace(bool),
    ToggleAmbiguous(bool),
    FrameworkChanged(FrameworkId, bool),
    CustomCharsetChanged(String),
    RunAudit,
    Poll,
    SelectTab(DetailTab),
    CopyPrimary,
    GoToConfigure,
}

struct GuiApp {
    request: ParanoidRequest,
    length_input: String,
    count_input: String,
    batch_input: String,
    min_lower_input: String,
    min_upper_input: String,
    min_digits_input: String,
    min_symbols_input: String,
    custom_charset_input: String,
    report: Option<GenerationReport>,
    screen: Screen,
    detail_tab: DetailTab,
    current_stage: Option<AuditStage>,
    completed_stages: Vec<AuditStage>,
    worker: Option<Receiver<WorkerMessage>>,
    status: String,
}

fn main() -> iced::Result {
    iced::application(boot, update, view)
        .title(title)
        .theme(theme)
        .run()
}

fn title(_app: &GuiApp) -> String {
    "paranoid-passwd".to_string()
}

fn theme(_app: &GuiApp) -> Theme {
    Theme::TokyoNight
}

fn boot() -> (GuiApp, Task<Message>) {
    let request = ParanoidRequest {
        charset: CharsetSpec::Options(CharsetOptions::default()),
        ..ParanoidRequest::default()
    };
    (
        GuiApp {
            length_input: request.length.to_string(),
            count_input: request.count.to_string(),
            batch_input: request.batch_size.to_string(),
            min_lower_input: "0".to_string(),
            min_upper_input: "0".to_string(),
            min_digits_input: "0".to_string(),
            min_symbols_input: "0".to_string(),
            custom_charset_input: String::new(),
            request,
            report: None,
            screen: Screen::Configure,
            detail_tab: DetailTab::Summary,
            current_stage: None,
            completed_stages: Vec::new(),
            worker: None,
            status: "Configure the generator, then run the 7-layer audit.".to_string(),
        },
        Task::none(),
    )
}

fn update(app: &mut GuiApp, message: Message) -> Task<Message> {
    match message {
        Message::LengthChanged(value) => {
            app.length_input = value.clone();
            if let Ok(length) = value.parse() {
                app.request.length = length;
            }
        }
        Message::CountChanged(value) => {
            app.count_input = value.clone();
            if let Ok(count) = value.parse() {
                app.request.count = count;
            }
        }
        Message::BatchChanged(value) => {
            app.batch_input = value.clone();
            if let Ok(batch_size) = value.parse() {
                app.request.batch_size = batch_size;
            }
        }
        Message::MinLowerChanged(value) => {
            app.min_lower_input = value.clone();
            if let Ok(count) = value.parse() {
                app.request.requirements.min_lowercase = count;
            }
        }
        Message::MinUpperChanged(value) => {
            app.min_upper_input = value.clone();
            if let Ok(count) = value.parse() {
                app.request.requirements.min_uppercase = count;
            }
        }
        Message::MinDigitsChanged(value) => {
            app.min_digits_input = value.clone();
            if let Ok(count) = value.parse() {
                app.request.requirements.min_digits = count;
            }
        }
        Message::MinSymbolsChanged(value) => {
            app.min_symbols_input = value.clone();
            if let Ok(count) = value.parse() {
                app.request.requirements.min_symbols = count;
            }
        }
        Message::ToggleLowercase(value) => {
            charset_options_mut(&mut app.request).include_lowercase = value
        }
        Message::ToggleUppercase(value) => {
            charset_options_mut(&mut app.request).include_uppercase = value
        }
        Message::ToggleDigits(value) => {
            charset_options_mut(&mut app.request).include_digits = value
        }
        Message::ToggleSymbols(value) => {
            charset_options_mut(&mut app.request).include_symbols = value
        }
        Message::ToggleSpace(value) => charset_options_mut(&mut app.request).include_space = value,
        Message::ToggleAmbiguous(value) => {
            charset_options_mut(&mut app.request).exclude_ambiguous = value;
        }
        Message::FrameworkChanged(framework, enabled) => {
            if enabled {
                if !app.request.selected_frameworks.contains(&framework) {
                    app.request.selected_frameworks.push(framework);
                }
            } else {
                app.request
                    .selected_frameworks
                    .retain(|candidate| candidate != &framework);
            }
            apply_frameworks(&mut app.request);
            sync_inputs_from_request(app);
        }
        Message::CustomCharsetChanged(value) => {
            app.custom_charset_input = value.clone();
            charset_options_mut(&mut app.request).custom_charset = if value.trim().is_empty() {
                None
            } else {
                Some(value)
            };
        }
        Message::RunAudit => {
            app.screen = Screen::Audit;
            app.current_stage = Some(AuditStage::Generate);
            app.completed_stages.clear();
            app.status = "Running native generation and batch audit...".to_string();
            let request = app.request.clone();
            let (tx, rx) = mpsc::channel::<WorkerMessage>();
            app.worker = Some(rx);
            thread::spawn(move || {
                let result = execute_request(&request, true, |stage| {
                    let _ = tx.send(WorkerMessage::Stage(stage));
                })
                .map_err(|error| error.to_string());
                let _ = tx.send(WorkerMessage::Done(Box::new(result)));
            });
            return Task::perform(
                async move {
                    thread::sleep(Duration::from_millis(80));
                },
                |_| Message::Poll,
            );
        }
        Message::Poll => {
            let messages = app
                .worker
                .as_ref()
                .map(|worker| worker.try_iter().collect::<Vec<_>>())
                .unwrap_or_default();
            let mut clear_worker = false;
            for worker_message in messages {
                match worker_message {
                    WorkerMessage::Stage(stage) => {
                        if !app.completed_stages.contains(&stage)
                            && !matches!(stage, AuditStage::Complete)
                        {
                            app.completed_stages.push(stage);
                        }
                        app.current_stage = Some(stage);
                    }
                    WorkerMessage::Done(result) => {
                        clear_worker = true;
                        match *result {
                            Ok(report) => {
                                app.report = Some(report);
                                app.screen = Screen::Results;
                                app.detail_tab = DetailTab::Summary;
                                app.status =
                                    "Audit complete. Review the results or copy the primary password."
                                        .to_string();
                            }
                            Err(error) => {
                                app.screen = Screen::Configure;
                                app.status = format!("Audit failed: {error}");
                            }
                        }
                    }
                }
            }
            if clear_worker {
                app.worker = None;
            } else if app.worker.is_some() {
                return Task::perform(
                    async move {
                        thread::sleep(Duration::from_millis(80));
                    },
                    |_| Message::Poll,
                );
            }
        }
        Message::SelectTab(tab) => app.detail_tab = tab,
        Message::CopyPrimary => {
            if let Some(password) = app
                .report
                .as_ref()
                .and_then(|report| report.passwords.first())
            {
                match Clipboard::new()
                    .and_then(|mut clipboard| clipboard.set_text(password.value.clone()))
                {
                    Ok(()) => {
                        app.status = "Copied the primary password to the clipboard.".to_string();
                    }
                    Err(error) => {
                        app.status = format!("Clipboard unavailable: {error}");
                    }
                }
            }
        }
        Message::GoToConfigure => {
            app.screen = Screen::Configure;
            app.current_stage = None;
            app.completed_stages.clear();
        }
    }
    Task::none()
}

fn view(app: &GuiApp) -> Element<'_, Message> {
    let content = match app.screen {
        Screen::Configure => configure_view(app),
        Screen::Audit => audit_view(app),
        Screen::Results => results_view(app),
    };
    container(content)
        .padding(24)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

fn configure_view(app: &GuiApp) -> Element<'_, Message> {
    let options = charset_options(&app.request);
    let frameworks = paranoid_core::frameworks().iter().fold(
        column![text("Frameworks").size(22)].spacing(8),
        |column, framework| {
            column.push(
                checkbox(app.request.selected_frameworks.contains(&framework.id))
                    .label(framework.name)
                    .on_toggle(move |enabled| Message::FrameworkChanged(framework.id, enabled)),
            )
        },
    );
    let validation = match app.request.resolve() {
        Ok(resolved) => format!(
            "Ready: {} password(s), {} chars, {:.2} bits per password.",
            resolved.count,
            resolved.length,
            (resolved.charset.len() as f64).log2() * resolved.length as f64
        ),
        Err(error) => error.to_string(),
    };
    let body = row![
        scrollable(
            column![
                text("paranoid-passwd").size(34),
                text("Configure the native generator and audit model."),
                row![
                    text_input("Length", &app.length_input).on_input(Message::LengthChanged),
                    text_input("Count", &app.count_input).on_input(Message::CountChanged),
                    text_input("Audit batch", &app.batch_input).on_input(Message::BatchChanged),
                ]
                .spacing(12),
                row![
                    text_input("Min lower", &app.min_lower_input)
                        .on_input(Message::MinLowerChanged),
                    text_input("Min upper", &app.min_upper_input)
                        .on_input(Message::MinUpperChanged),
                    text_input("Min digits", &app.min_digits_input)
                        .on_input(Message::MinDigitsChanged),
                    text_input("Min symbols", &app.min_symbols_input)
                        .on_input(Message::MinSymbolsChanged),
                ]
                .spacing(12),
                checkbox(options.include_lowercase)
                    .label("Lowercase")
                    .on_toggle(Message::ToggleLowercase),
                checkbox(options.include_uppercase)
                    .label("Uppercase")
                    .on_toggle(Message::ToggleUppercase),
                checkbox(options.include_digits)
                    .label("Digits")
                    .on_toggle(Message::ToggleDigits),
                checkbox(options.include_symbols)
                    .label("Symbols")
                    .on_toggle(Message::ToggleSymbols),
                checkbox(options.include_space)
                    .label("Include space")
                    .on_toggle(Message::ToggleSpace),
                checkbox(options.exclude_ambiguous)
                    .label("Exclude ambiguous")
                    .on_toggle(Message::ToggleAmbiguous),
                text_input("Custom charset override", &app.custom_charset_input)
                    .on_input(Message::CustomCharsetChanged),
                button("Generate + Run 7-Layer Audit").on_press(Message::RunAudit),
            ]
            .spacing(12)
        )
        .width(Length::FillPortion(3)),
        scrollable(
            column![
                frameworks,
                text("Validation").size(22),
                text(validation),
                text("The GUI uses the same typed request/result model as the CLI and TUI."),
                text(app.status.as_str()),
            ]
            .spacing(12)
        )
        .width(Length::FillPortion(2)),
    ]
    .spacing(20);

    column![body].into()
}

fn audit_view(app: &GuiApp) -> Element<'_, Message> {
    let progress = match app.current_stage {
        None => 0.0,
        Some(AuditStage::Generate) => 1.0 / 7.0,
        Some(AuditStage::ChiSquared) => 2.0 / 7.0,
        Some(AuditStage::SerialCorrelation) => 3.0 / 7.0,
        Some(AuditStage::CollisionDetection) => 4.0 / 7.0,
        Some(AuditStage::EntropyProofs) => 5.0 / 7.0,
        Some(AuditStage::PatternDetection) => 6.0 / 7.0,
        Some(AuditStage::ThreatAssessment) | Some(AuditStage::Complete) => 1.0,
    };
    let stages = [
        AuditStage::Generate,
        AuditStage::ChiSquared,
        AuditStage::SerialCorrelation,
        AuditStage::CollisionDetection,
        AuditStage::EntropyProofs,
        AuditStage::PatternDetection,
        AuditStage::ThreatAssessment,
    ]
    .into_iter()
    .fold(
        column![text("7-Layer Audit").size(30)].spacing(8),
        |column, stage| {
            let label = if app.completed_stages.contains(&stage) {
                format!("✓ {}", stage.label())
            } else if app.current_stage == Some(stage) {
                format!("→ {}", stage.label())
            } else {
                format!("· {}", stage.label())
            };
            column.push(text(label))
        },
    );
    column![
        text("Generate & Audit").size(34),
        text(format!("Progress: {:.0}%", progress * 100.0)),
        stages,
        text(app.status.as_str()),
    ]
    .spacing(14)
    .into()
}

fn results_view(app: &GuiApp) -> Element<'_, Message> {
    let Some(report) = &app.report else {
        return text("No report available.").into();
    };
    let Some(audit) = &report.audit else {
        return text("Audit summary unavailable.").into();
    };
    let Some(primary) = report.passwords.first() else {
        return text("No generated password available.").into();
    };

    let tabs = DetailTab::ALL
        .into_iter()
        .fold(row![].spacing(8), |row, tab| {
            row.push(button(tab.label()).on_press(Message::SelectTab(tab)))
        });

    let detail = match app.detail_tab {
        DetailTab::Summary => column![
            text(if audit.overall_pass {
                "CRYPTOGRAPHICALLY SOUND"
            } else {
                "REVIEW FLAGGED ITEMS"
            })
            .size(26),
            text(format!("Primary: {}", primary.value)),
            text(format!("SHA-256: {}", primary.sha256_hex)),
            text(format!(
                "Primary verdict: {}",
                if primary.all_pass { "PASS" } else { "REVIEW" }
            )),
            text(format!(
                "Additional passwords: {}",
                report.passwords.len().saturating_sub(1)
            )),
        ]
        .spacing(8),
        DetailTab::Compliance => report.passwords.iter().enumerate().fold(
            column![text("Selected Frameworks").size(24)].spacing(8),
            |column, (index, password)| {
                let label = if index == 0 {
                    "Primary".to_string()
                } else {
                    format!("Additional {}", index + 1)
                };
                let selected = password
                    .compliance
                    .iter()
                    .filter(|status| status.selected)
                    .map(|status| {
                        format!(
                            "{} {}",
                            if status.passed { "✓" } else { "✗" },
                            status.name
                        )
                    })
                    .collect::<Vec<_>>();
                column.push(text(format!(
                    "{label}: {}",
                    if selected.is_empty() {
                        "no frameworks selected".to_string()
                    } else {
                        selected.join(", ")
                    }
                )))
            },
        ),
        DetailTab::Entropy => column![
            text("Entropy").size(24),
            text(format!("Charset size: {}", audit.charset_size)),
            text(format!("Password length: {}", audit.password_length)),
            text(format!("Bits per character: {:.4}", audit.entropy.bits_per_char)),
            text(format!("Total entropy: {:.2} bits", audit.entropy.total_entropy)),
            text(format!(
                "Brute-force @ 1T/s: {:.2e} years",
                audit.entropy.brute_force_years
            )),
        ]
        .spacing(8),
        DetailTab::Stats => column![
            text("Batch Statistics").size(24),
            text(format!(
                "Chi-squared: {:.2} (df={}, p={:.4})",
                audit.chi2_statistic, audit.chi2_df, audit.chi2_p_value
            )),
            text(format!(
                "Serial correlation: {:.6}",
                audit.serial_correlation
            )),
            text(format!("Duplicates: {} / {}", audit.duplicates, audit.batch_size)),
            text(format!(
                "Rejection boundary: {} ({:.4}% rejected)",
                audit.rejection_max_valid, audit.rejection_rate_pct
            )),
        ]
        .spacing(8),
        DetailTab::Threats => column![
            text("Threat Model").size(24),
            text("T1 Training-data leakage — mitigated by OpenSSL-backed OS entropy."),
            text("T2 Token-distribution bias — mitigated by rejection sampling."),
            text("T3 Deterministic regeneration — mitigated by hardware entropy."),
            text("T4 Prompt injection steering — residual risk in source review."),
            text("T5 Hallucinated security claims — residual risk, review the math."),
            text("T6 Screen exposure — operational risk, clear copied passwords."),
        ]
        .spacing(8),
        DetailTab::SelfAudit => column![
            text("Self-Audit").size(24),
            text("The GUI consumes the same typed report as the CLI and TUI."),
            text("Batch statistics stay separated from per-password verdicts."),
            text("Selected frameworks are enforced per emitted password."),
            text("This desktop surface remains native-only; no webview trust boundary is reintroduced."),
        ]
        .spacing(8),
    };

    column![
        text("Results").size(34),
        text(format!("Primary password: {}", primary.value)),
        row![
            button("Copy primary password").on_press(Message::CopyPrimary),
            button("Back to configuration").on_press(Message::GoToConfigure),
        ]
        .spacing(12),
        tabs,
        scrollable(detail),
        text(app.status.as_str()),
    ]
    .spacing(16)
    .align_x(Alignment::Start)
    .into()
}

fn charset_options(request: &ParanoidRequest) -> &CharsetOptions {
    match &request.charset {
        CharsetSpec::Options(options) => options,
        CharsetSpec::NamedOrLiteral(_) => unreachable!("GUI uses charset options"),
    }
}

fn charset_options_mut(request: &mut ParanoidRequest) -> &mut CharsetOptions {
    match &mut request.charset {
        CharsetSpec::Options(options) => options,
        CharsetSpec::NamedOrLiteral(_) => unreachable!("GUI uses charset options"),
    }
}

fn apply_frameworks(request: &mut ParanoidRequest) {
    let combined = combined_framework_requirements(&request.selected_frameworks);
    request.length = request.length.max(combined.min_length.max(8));
    charset_options_mut(request).apply_frameworks(&combined);
}

fn sync_inputs_from_request(app: &mut GuiApp) {
    app.length_input = app.request.length.to_string();
    app.count_input = app.request.count.to_string();
    app.batch_input = app.request.batch_size.to_string();
    app.min_lower_input = app.request.requirements.min_lowercase.to_string();
    app.min_upper_input = app.request.requirements.min_uppercase.to_string();
    app.min_digits_input = app.request.requirements.min_digits.to_string();
    app.min_symbols_input = app.request.requirements.min_symbols.to_string();
    app.custom_charset_input = charset_options(&app.request)
        .custom_charset
        .clone()
        .unwrap_or_default();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framework_selection_updates_request_constraints() {
        let (mut app, _) = boot();
        let _ = update(
            &mut app,
            Message::FrameworkChanged(FrameworkId::PciDss, true),
        );
        assert!(
            app.request
                .selected_frameworks
                .contains(&FrameworkId::PciDss)
        );
        assert!(app.request.length >= 12);
        assert!(charset_options(&app.request).include_uppercase);
        assert!(charset_options(&app.request).include_digits);
    }

    #[test]
    fn numeric_inputs_update_request() {
        let (mut app, _) = boot();
        let _ = update(&mut app, Message::LengthChanged("40".to_string()));
        let _ = update(&mut app, Message::CountChanged("3".to_string()));
        assert_eq!(app.request.length, 40);
        assert_eq!(app.request.count, 3);
    }
}
