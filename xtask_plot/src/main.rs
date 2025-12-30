use std::sync::mpsc;
use std::thread;

use anyhow::Context;
use chrono::{DateTime, Duration, Local, Utc};
use eframe::egui;
use egui_plot::{Bar, BarChart, Line, Plot, Points};
use postgres::{Client, NoTls};
use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Metric {
    TotalViolations,
    LockViolations,
    SpawnViolations,
    SsotViolations,
    SsotLeakageViolations,
    SsotCacheViolations,
    FallbackViolations,
    RequiredConfigViolations,
    SensitiveViolations,
    HardcodeViolations,
    HardcodedLiteralViolations,
    HardcodedSleepViolations,
    StyleViolations,
    BlockingLockViolations,
    NoCacheViolations,
    FilesAffected,
}

fn metric_color(m: Metric) -> egui::Color32 {
    // Stable palette: legend + plot series stay consistent across runs.
    match m {
        Metric::TotalViolations => egui::Color32::from_rgb(30, 30, 30),         // black-ish
        Metric::FilesAffected => egui::Color32::from_rgb(120, 120, 120),        // gray
        Metric::LockViolations => egui::Color32::from_rgb(90, 180, 90),         // green
        Metric::SpawnViolations => egui::Color32::from_rgb(160, 110, 240),      // purple
        Metric::SsotViolations => egui::Color32::from_rgb(70, 200, 200),        // cyan
        Metric::SsotLeakageViolations => egui::Color32::from_rgb(50, 180, 180), // cyan-dark
        Metric::SsotCacheViolations => egui::Color32::from_rgb(100, 220, 220),  // cyan-light
        Metric::FallbackViolations => egui::Color32::from_rgb(70, 130, 220),    // blue
        Metric::RequiredConfigViolations => egui::Color32::from_rgb(140, 140, 140), // gray-alt
        Metric::SensitiveViolations => egui::Color32::from_rgb(240, 90, 200),   // magenta
        Metric::HardcodeViolations => egui::Color32::from_rgb(235, 140, 45),    // orange
        Metric::HardcodedLiteralViolations => egui::Color32::from_rgb(255, 165, 0), // orange-bright
        Metric::HardcodedSleepViolations => egui::Color32::from_rgb(200, 100, 30),  // orange-dark
        Metric::StyleViolations => egui::Color32::from_rgb(210, 200, 60),       // yellow-ish
        Metric::BlockingLockViolations => egui::Color32::from_rgb(220, 80, 60), // red-ish
        Metric::NoCacheViolations => egui::Color32::from_rgb(180, 60, 180),     // purple-ish
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum ViewMode {
    TimeSeries,
    ByFile,
}

impl Metric {
    fn label(self) -> &'static str {
        match self {
            Metric::TotalViolations => "total_violations",
            Metric::LockViolations => "lock_violations",
            Metric::SpawnViolations => "spawn_violations",
            Metric::SsotViolations => "ssot_violations",
            Metric::SsotLeakageViolations => "ssot_leakage_violations",
            Metric::SsotCacheViolations => "ssot_cache_violations",
            Metric::FallbackViolations => "fallback_violations",
            Metric::RequiredConfigViolations => "required_config_violations",
            Metric::SensitiveViolations => "sensitive_violations",
            Metric::HardcodeViolations => "hardcode_violations",
            Metric::HardcodedLiteralViolations => "hardcoded_literal_violations",
            Metric::HardcodedSleepViolations => "hardcoded_sleep_violations",
            Metric::StyleViolations => "style_violations",
            Metric::BlockingLockViolations => "blocking_lock_violations",
            Metric::NoCacheViolations => "no_cache_violations",
            Metric::FilesAffected => "files_affected",
        }
    }

    fn all() -> &'static [Metric] {
        &[
            Metric::TotalViolations,
            Metric::LockViolations,
            Metric::SpawnViolations,
            Metric::SsotViolations,
            Metric::SsotLeakageViolations,
            Metric::SsotCacheViolations,
            Metric::FallbackViolations,
            Metric::RequiredConfigViolations,
            Metric::SensitiveViolations,
            Metric::HardcodeViolations,
            Metric::HardcodedLiteralViolations,
            Metric::HardcodedSleepViolations,
            Metric::StyleViolations,
            Metric::BlockingLockViolations,
            Metric::NoCacheViolations,
            Metric::FilesAffected,
        ]
    }
}

#[derive(Clone, Debug)]
struct DataPoint {
    t: DateTime<Utc>,
    v: i64,
}

#[derive(Clone, Debug)]
struct Series {
    metric: Metric,
    points: Vec<DataPoint>,
}

#[derive(Clone, Debug)]
struct QueryResult {
    series: Vec<Series>,
    start: DateTime<Utc>,
    end: DateTime<Utc>,

    // Per-file breakdown from the newest analysis row inside the selected range.
    by_file_recorded_at: DateTime<Utc>,
    by_file: Vec<FileBreakdownEntry>,
}

#[derive(Clone, Debug)]
struct QueryRequest {
    start: DateTime<Utc>,
    end: DateTime<Utc>,
}

#[derive(Clone, Debug)]
struct FileBreakdownEntry {
    file: String,
    total: i64,
    lock_violations: i64,
    spawn_violations: i64,
    ssot_violations: i64,
    ssot_leakage_violations: i64,
    ssot_cache_violations: i64,
    fallback_violations: i64,
    required_config_violations: i64,
    sensitive_violations: i64,
    hardcode_violations: i64,
    hardcoded_literal_violations: i64,
    hardcoded_sleep_violations: i64,
    style_violations: i64,
    blocking_lock_violations: i64,
    no_cache_violations: i64,
}

struct PlotApp {
    db_url: String,

    // UI time range
    range_hours: i64,
    start: DateTime<Utc>,
    end: DateTime<Utc>,

    view_mode: ViewMode,

    // Interactive legend: click-to-mute
    muted: std::collections::HashSet<Metric>,

    max_files: usize,

    // Background query
    tx_req: mpsc::Sender<QueryRequest>,
    rx_res: mpsc::Receiver<anyhow::Result<QueryResult>>,

    last_result: Option<QueryResult>,
    last_error: Option<String>,
    waiting_for_result: bool,
}

impl PlotApp {
    fn new(db_url: String) -> Self {
        let (tx_req, rx_req) = mpsc::channel::<QueryRequest>();
        let (tx_res, rx_res) = mpsc::channel::<anyhow::Result<QueryResult>>();

        // Worker thread: executes DB queries when requested.
        // Important: do NOT exit the worker on a single connect/query failure, so Refresh keeps working.
        let db_url_for_thread = db_url.clone();
        thread::spawn(move || {
            while let Ok(req) = rx_req.recv() {
                let mut client = match Client::connect(&db_url_for_thread, NoTls) {
                    Ok(c) => c,
                    Err(e) => {
                        let _ = tx_res.send(Err(anyhow::anyhow!("DB connect failed: {}", e)));
                        continue;
                    }
                };

                let res = fetch_series(&mut client, req.start, req.end);
                let _ = tx_res.send(res);
            }
        });

        let now = Utc::now();
        let range_hours = 24;
        let start = now - Duration::hours(range_hours);
        let end = now;

        let mut app = Self {
            db_url,
            range_hours,
            start,
            end,
            view_mode: ViewMode::TimeSeries,
            muted: std::collections::HashSet::new(),
            max_files: 20,
            tx_req,
            rx_res,
            last_result: None,
            last_error: None,
            waiting_for_result: false,
        };

        // Initial load.
        app.request_query();
        app
    }

    fn request_query(&mut self) {
        let req = QueryRequest {
            start: self.start,
            end: self.end,
        };
        match self.tx_req.send(req) {
            Ok(_) => {
                self.waiting_for_result = true;
            }
            Err(_) => {
                self.last_error = Some("DB worker disconnected".to_string());
                self.waiting_for_result = false;
            }
        }
    }

    fn poll_results(&mut self) {
        loop {
            match self.rx_res.try_recv() {
                Ok(Ok(result)) => {
                    self.last_error = None;
                    self.last_result = Some(result);
                    self.waiting_for_result = false;
                }
                Ok(Err(e)) => {
                    self.last_error = Some(format!("{:#}", e));
                    self.waiting_for_result = false;
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.last_error = Some("DB worker disconnected".to_string());
                    self.waiting_for_result = false;
                    break;
                }
            }
        }
    }
}

impl eframe::App for PlotApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_results();
        if self.waiting_for_result {
            // Repaint only while we're expecting a DB response.
            ctx.request_repaint();
        }

        egui::TopBottomPanel::top("top_controls").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("View:");
                if ui
                    .selectable_label(self.view_mode == ViewMode::TimeSeries, "Time series")
                    .clicked()
                {
                    self.view_mode = ViewMode::TimeSeries;
                }
                if ui
                    .selectable_label(self.view_mode == ViewMode::ByFile, "By file")
                    .clicked()
                {
                    self.view_mode = ViewMode::ByFile;
                }

                ui.separator();
                ui.label("Range (hours):");
                let mut h = self.range_hours;
                if ui.add(egui::DragValue::new(&mut h).clamp_range(1..=24 * 365)).changed() {
                    self.range_hours = h;
                    let now = Utc::now();
                    self.end = now;
                    self.start = now - Duration::hours(self.range_hours);
                    self.request_query();
                }
                if ui.button("Now").clicked() {
                    let now = Utc::now();
                    self.end = now;
                    self.start = now - Duration::hours(self.range_hours);
                    self.request_query();
                }
                if ui.button("Refresh").clicked() {
                    self.request_query();
                }
            });

            if let Some(err) = self.last_error.as_ref() {
                ui.colored_label(egui::Color32::RED, err);
            }
        });

        egui::SidePanel::left("legend").resizable(true).default_width(260.0).show(ctx, |ui| {
            match self.view_mode {
                ViewMode::TimeSeries => {
                    ui.label("Metrics (click label to mute/unmute):");
                    ui.separator();

                    for &m in Metric::all() {
                        let muted = self.muted.contains(&m);
                        let label =
                            if muted { format!("(muted) {}", m.label()) } else { m.label().to_string() };
                        let resp = ui.add(egui::Label::new(label).sense(egui::Sense::click()));
                        if resp.clicked() {
                            if muted {
                                self.muted.remove(&m);
                            } else {
                                self.muted.insert(m);
                            }
                        }
                    }

                    ui.separator();
                    if ui.button("Unmute all").clicked() {
                        self.muted.clear();
                    }
                }
                ViewMode::ByFile => {
                    ui.label("By-file stacked bars:");
                    ui.separator();

                    ui.label("Legend (same as time-series; click label to mute/unmute):");
                    ui.separator();
                    for &m in Metric::all() {
                        let muted = self.muted.contains(&m);
                        let label =
                            if muted { format!("(muted) {}", m.label()) } else { m.label().to_string() };
                        let resp = ui.add(egui::Label::new(label).sense(egui::Sense::click()));
                        if resp.clicked() {
                            if muted {
                                self.muted.remove(&m);
                            } else {
                                self.muted.insert(m);
                            }
                        }
                    }

                    ui.separator();
                    ui.horizontal(|ui| {
                        ui.label("Max files:");
                        let mut mf = self.max_files as i32;
                        if ui.add(egui::DragValue::new(&mut mf).clamp_range(1..=500)).changed() {
                            self.max_files = mf as usize;
                        }
                    });

                    if ui.button("Unmute all").clicked() {
                        self.muted.clear();
                    }
                }
            }
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            let Some(result) = self.last_result.as_ref() else {
                ui.label("No data yet. Click Refresh.");
                return;
            };

            match self.view_mode {
                ViewMode::TimeSeries => {
                    let plot = Plot::new("xtask_plot_timeseries")
                        .legend(egui_plot::Legend::default())
                        .allow_zoom(true)
                        .allow_drag(true)
                        .x_axis_formatter(|mark: egui_plot::GridMark, _max_chars: usize, _range| {
                            let ms = mark.value.round() as i64;
                            let dt_utc = DateTime::<Utc>::from_timestamp_millis(ms)
                                .expect("FATAL: invalid timestamp millis in plot x axis");
                            let dt_local: DateTime<Local> = dt_utc.with_timezone(&Local);
                            dt_local.format("%Y-%m-%d %H:%M:%S").to_string()
                        })
                        .label_formatter(|name, value| {
                            let ms = value.x.round() as i64;
                            let dt_utc = DateTime::<Utc>::from_timestamp_millis(ms)
                                .expect("FATAL: invalid timestamp millis in plot label");
                            let dt_local: DateTime<Local> = dt_utc.with_timezone(&Local);
                            format!("{}\n{} (local)\n{}", name, dt_local.format("%Y-%m-%d %H:%M:%S"), value.y)
                        });

                    plot.show(ui, |plot_ui| {
                        for s in &result.series {
                            if self.muted.contains(&s.metric) {
                                continue;
                            }
                            let color = metric_color(s.metric);
                            let pts: Vec<[f64; 2]> = s
                                .points
                                .iter()
                                .map(|p| [p.t.timestamp_millis() as f64, p.v as f64])
                                .collect();
                            let line = Line::new(pts.clone())
                                .name(s.metric.label())
                                .color(color)
                                .width(2.0);
                            plot_ui.line(line);

                            // Draw datapoint markers on top of the line.
                            let dots = Points::new(pts)
                                .name(s.metric.label())
                                .color(color)
                                .radius(2.5);
                            plot_ui.points(dots);
                        }
                    });
                }
                ViewMode::ByFile => {
                    ui.label(format!(
                        "By-file breakdown (latest run in range @ {} UTC)",
                        result.by_file_recorded_at.format("%Y-%m-%d %H:%M:%S")
                    ));

                    let mut items = result.by_file.clone();
                    items.sort_by(|a, b| b.total.cmp(&a.total).then_with(|| a.file.cmp(&b.file)));
                    if items.len() > self.max_files {
                        items.truncate(self.max_files);
                    }

                    let labels: Vec<String> = items
                        .iter()
                        .map(|e| e.file.rsplit('/').next().unwrap_or(&e.file).to_string())
                        .collect();

                    let full_files: Vec<String> = items.iter().map(|e| e.file.clone()).collect();

                    // Color by violation *type* (stable palette), not severity.
                    // Keep these consistent across runs so the legend becomes muscle-memory.
                    // Color by violation type (stable palette).
                    let color_lock = metric_color(Metric::LockViolations);
                    let color_spawn = metric_color(Metric::SpawnViolations);
                    let color_ssot = metric_color(Metric::SsotViolations);
                    let color_fallback = metric_color(Metric::FallbackViolations);
                    let color_required = metric_color(Metric::RequiredConfigViolations);
                    let color_sensitive = metric_color(Metric::SensitiveViolations);
                    let color_hardcode = metric_color(Metric::HardcodeViolations);
                    let color_style = metric_color(Metric::StyleViolations);
                    let color_blocking_lock = metric_color(Metric::BlockingLockViolations);

                    let labels_for_x = labels.clone();

                    // Build stacked bar charts in a stable order.
                    let mut charts: Vec<BarChart> = vec![];

                    let files_tt = full_files.clone();
                    if !self.muted.contains(&Metric::LockViolations) {
                        let mut bars = vec![];
                        for (idx, e) in items.iter().enumerate() {
                            bars.push(Bar::new(idx as f64, e.lock_violations as f64));
                        }
                        let label = Metric::LockViolations.label().to_string();
                        let tt = files_tt.clone();
                        charts.push(
                            BarChart::new(bars)
                                .name(label.clone())
                                .width(0.85)
                                .color(color_lock)
                                .element_formatter(Box::new(move |bar, _| {
                                    let i = bar.argument.round() as isize;
                                    if i < 0 || (i as usize) >= tt.len() {
                                        return format!("{}\n{}", label, bar.value);
                                    }
                                    format!("{}\n{}\n{}", tt[i as usize], label, bar.value)
                                })),
                        );
                    }

                    let files_tt = full_files.clone();
                    if !self.muted.contains(&Metric::SpawnViolations) {
                        let mut bars = vec![];
                        for (idx, e) in items.iter().enumerate() {
                            bars.push(Bar::new(idx as f64, e.spawn_violations as f64));
                        }
                        let label = Metric::SpawnViolations.label().to_string();
                        let tt = files_tt.clone();
                        charts.push(
                            BarChart::new(bars)
                                .name(label.clone())
                                .width(0.85)
                                .color(color_spawn)
                                .element_formatter(Box::new(move |bar, _| {
                                    let i = bar.argument.round() as isize;
                                    if i < 0 || (i as usize) >= tt.len() {
                                        return format!("{}\n{}", label, bar.value);
                                    }
                                    format!("{}\n{}\n{}", tt[i as usize], label, bar.value)
                                })),
                        );
                    }

                    let files_tt = full_files.clone();
                    if !self.muted.contains(&Metric::SsotViolations) {
                        let mut bars = vec![];
                        for (idx, e) in items.iter().enumerate() {
                            bars.push(Bar::new(idx as f64, e.ssot_violations as f64));
                        }
                        let label = Metric::SsotViolations.label().to_string();
                        let tt = files_tt.clone();
                        charts.push(
                            BarChart::new(bars)
                                .name(label.clone())
                                .width(0.85)
                                .color(color_ssot)
                                .element_formatter(Box::new(move |bar, _| {
                                    let i = bar.argument.round() as isize;
                                    if i < 0 || (i as usize) >= tt.len() {
                                        return format!("{}\n{}", label, bar.value);
                                    }
                                    format!("{}\n{}\n{}", tt[i as usize], label, bar.value)
                                })),
                        );
                    }

                    let files_tt = full_files.clone();
                    if !self.muted.contains(&Metric::FallbackViolations) {
                        let mut bars = vec![];
                        for (idx, e) in items.iter().enumerate() {
                            bars.push(Bar::new(idx as f64, e.fallback_violations as f64));
                        }
                        let label = Metric::FallbackViolations.label().to_string();
                        let tt = files_tt.clone();
                        charts.push(
                            BarChart::new(bars)
                                .name(label.clone())
                                .width(0.85)
                                .color(color_fallback)
                                .element_formatter(Box::new(move |bar, _| {
                                    let i = bar.argument.round() as isize;
                                    if i < 0 || (i as usize) >= tt.len() {
                                        return format!("{}\n{}", label, bar.value);
                                    }
                                    format!("{}\n{}\n{}", tt[i as usize], label, bar.value)
                                })),
                        );
                    }

                    let files_tt = full_files.clone();
                    if !self.muted.contains(&Metric::RequiredConfigViolations) {
                        let mut bars = vec![];
                        for (idx, e) in items.iter().enumerate() {
                            bars.push(Bar::new(idx as f64, e.required_config_violations as f64));
                        }
                        let label = Metric::RequiredConfigViolations.label().to_string();
                        let tt = files_tt.clone();
                        charts.push(
                            BarChart::new(bars)
                                .name(label.clone())
                                .width(0.85)
                                .color(color_required)
                                .element_formatter(Box::new(move |bar, _| {
                                    let i = bar.argument.round() as isize;
                                    if i < 0 || (i as usize) >= tt.len() {
                                        return format!("{}\n{}", label, bar.value);
                                    }
                                    format!("{}\n{}\n{}", tt[i as usize], label, bar.value)
                                })),
                        );
                    }

                    let files_tt = full_files.clone();
                    if !self.muted.contains(&Metric::SensitiveViolations) {
                        let mut bars = vec![];
                        for (idx, e) in items.iter().enumerate() {
                            bars.push(Bar::new(idx as f64, e.sensitive_violations as f64));
                        }
                        let label = Metric::SensitiveViolations.label().to_string();
                        let tt = files_tt.clone();
                        charts.push(
                            BarChart::new(bars)
                                .name(label.clone())
                                .width(0.85)
                                .color(color_sensitive)
                                .element_formatter(Box::new(move |bar, _| {
                                    let i = bar.argument.round() as isize;
                                    if i < 0 || (i as usize) >= tt.len() {
                                        return format!("{}\n{}", label, bar.value);
                                    }
                                    format!("{}\n{}\n{}", tt[i as usize], label, bar.value)
                                })),
                        );
                    }

                    let files_tt = full_files.clone();
                    if !self.muted.contains(&Metric::HardcodeViolations) {
                        let mut bars = vec![];
                        for (idx, e) in items.iter().enumerate() {
                            bars.push(Bar::new(idx as f64, e.hardcode_violations as f64));
                        }
                        let label = Metric::HardcodeViolations.label().to_string();
                        let tt = files_tt.clone();
                        charts.push(
                            BarChart::new(bars)
                                .name(label.clone())
                                .width(0.85)
                                .color(color_hardcode)
                                .element_formatter(Box::new(move |bar, _| {
                                    let i = bar.argument.round() as isize;
                                    if i < 0 || (i as usize) >= tt.len() {
                                        return format!("{}\n{}", label, bar.value);
                                    }
                                    format!("{}\n{}\n{}", tt[i as usize], label, bar.value)
                                })),
                        );
                    }

                    let files_tt = full_files.clone();
                    if !self.muted.contains(&Metric::StyleViolations) {
                        let mut bars = vec![];
                        for (idx, e) in items.iter().enumerate() {
                            bars.push(Bar::new(idx as f64, e.style_violations as f64));
                        }
                        let label = Metric::StyleViolations.label().to_string();
                        let tt = files_tt.clone();
                        charts.push(
                            BarChart::new(bars)
                                .name(label.clone())
                                .width(0.85)
                                .color(color_style)
                                .element_formatter(Box::new(move |bar, _| {
                                    let i = bar.argument.round() as isize;
                                    if i < 0 || (i as usize) >= tt.len() {
                                        return format!("{}\n{}", label, bar.value);
                                    }
                                    format!("{}\n{}\n{}", tt[i as usize], label, bar.value)
                                })),
                        );
                    }

                    let files_tt = full_files.clone();
                    if !self.muted.contains(&Metric::BlockingLockViolations) {
                        let mut bars = vec![];
                        for (idx, e) in items.iter().enumerate() {
                            bars.push(Bar::new(idx as f64, e.blocking_lock_violations as f64));
                        }
                        let label = Metric::BlockingLockViolations.label().to_string();
                        let tt = files_tt.clone();
                        charts.push(
                            BarChart::new(bars)
                                .name(label.clone())
                                .width(0.85)
                                .color(color_blocking_lock)
                                .element_formatter(Box::new(move |bar, _| {
                                    let i = bar.argument.round() as isize;
                                    if i < 0 || (i as usize) >= tt.len() {
                                        return format!("{}\n{}", label, bar.value);
                                    }
                                    format!("{}\n{}\n{}", tt[i as usize], label, bar.value)
                                })),
                        );
                    }

                    // Overlay bars for TotalViolations / FilesAffected so the legend is truly identical.
                    let show_total = !self.muted.contains(&Metric::TotalViolations);
                    let show_files_affected = !self.muted.contains(&Metric::FilesAffected);

                    let total_chart = if show_total {
                        let mut bars = vec![];
                        for (idx, e) in items.iter().enumerate() {
                            bars.push(Bar::new(idx as f64, e.total as f64));
                        }
                        Some(
                            BarChart::new(bars)
                                .name(Metric::TotalViolations.label())
                                .width(0.90)
                                .color(metric_color(Metric::TotalViolations)),
                        )
                    } else {
                        None
                    };

                    let files_chart = if show_files_affected {
                        let mut bars = vec![];
                        for (idx, _e) in items.iter().enumerate() {
                            bars.push(Bar::new(idx as f64, 1.0));
                        }
                        Some(
                            BarChart::new(bars)
                                .name(Metric::FilesAffected.label())
                                .width(0.30)
                                .color(metric_color(Metric::FilesAffected)),
                        )
                    } else {
                        None
                    };

                    let plot = Plot::new("xtask_plot_by_file")
                        .legend(egui_plot::Legend::default())
                        .allow_zoom(true)
                        .allow_drag(true)
                        .x_axis_formatter(move |mark: egui_plot::GridMark, _max_chars: usize, _range| {
                            let idx = mark.value.round() as isize;
                            if idx < 0 || (idx as usize) >= labels_for_x.len() {
                                "".to_string()
                            } else {
                                labels_for_x[idx as usize].clone()
                            }
                        })
                        .y_axis_formatter(|mark: egui_plot::GridMark, _max_chars: usize, _range| {
                            format!("{}", mark.value.round() as i64)
                        });

                    plot.show(ui, |plot_ui| {
                        // stack charts in order
                        let mut stacked: Vec<BarChart> = vec![];
                        for (i, chart) in charts.into_iter().enumerate() {
                            if i == 0 {
                                stacked.push(chart);
                            } else {
                                let mut refs: Vec<&BarChart> = vec![];
                                for s in &stacked {
                                    refs.push(s);
                                }
                                stacked.push(chart.stack_on(&refs));
                            }
                        }
                        for c in stacked {
                            plot_ui.bar_chart(c);
                        }
                        if let Some(c) = total_chart {
                            plot_ui.bar_chart(c);
                        }
                        if let Some(c) = files_chart {
                            plot_ui.bar_chart(c);
                        }
                    });
                }
            }
        });
    }
}

fn fetch_series(
    client: &mut Client,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> anyhow::Result<QueryResult> {
    // Pull all key metrics for each run; render them as separate series.
    let rows = client
        .query(
            r#"
SELECT
  recorded_at,
  total_violations,
  lock_violations,
  spawn_violations,
  ssot_violations,
  COALESCE(ssot_leakage_violations, 0) as ssot_leakage_violations,
  COALESCE(ssot_cache_violations, 0) as ssot_cache_violations,
  fallback_violations,
  required_config_violations,
  sensitive_violations,
  hardcode_violations,
  COALESCE(hardcoded_literal_violations, 0) as hardcoded_literal_violations,
  COALESCE(hardcoded_sleep_violations, 0) as hardcoded_sleep_violations,
  style_violations,
  blocking_lock_violations,
  COALESCE(no_cache_violations, 0) as no_cache_violations,
  files_affected
FROM analysis
WHERE recorded_at >= $1 AND recorded_at <= $2
ORDER BY recorded_at ASC
"#,
            &[&start, &end],
        )
        .context("query analysis table failed")?;

    let mut series_map: std::collections::HashMap<Metric, Vec<DataPoint>> = std::collections::HashMap::new();
    for &m in Metric::all() {
        series_map.insert(m, Vec::new());
    }

    for row in rows {
        let t: DateTime<Utc> = row.get::<_, DateTime<Utc>>(0);
        let vals: [i64; 16] = [
            row.get::<_, i64>(1),  // total_violations
            row.get::<_, i64>(2),  // lock_violations
            row.get::<_, i64>(3),  // spawn_violations
            row.get::<_, i64>(4),  // ssot_violations
            row.get::<_, i64>(5),  // ssot_leakage_violations
            row.get::<_, i64>(6),  // ssot_cache_violations
            row.get::<_, i64>(7),  // fallback_violations
            row.get::<_, i64>(8),  // required_config_violations
            row.get::<_, i64>(9),  // sensitive_violations
            row.get::<_, i64>(10), // hardcode_violations
            row.get::<_, i64>(11), // hardcoded_literal_violations
            row.get::<_, i64>(12), // hardcoded_sleep_violations
            row.get::<_, i64>(13), // style_violations
            row.get::<_, i64>(14), // blocking_lock_violations
            row.get::<_, i64>(15), // no_cache_violations
            row.get::<_, i64>(16), // files_affected
        ];

        let metrics = Metric::all();
        for (idx, &m) in metrics.iter().enumerate() {
            let v = vals[idx];
            if let Some(vec) = series_map.get_mut(&m) {
                vec.push(DataPoint { t, v });
            }
        }
    }

    let mut out: Vec<Series> = Vec::new();
    for &m in Metric::all() {
        let points = series_map.remove(&m).unwrap_or_default();
        out.push(Series { metric: m, points });
    }

    let (by_file_recorded_at, by_file) = fetch_by_file_breakdown(client, start, end)?;
    Ok(QueryResult {
        series: out,
        start,
        end,
        by_file_recorded_at,
        by_file,
    })
}

fn fetch_by_file_breakdown(
    client: &mut Client,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> anyhow::Result<(DateTime<Utc>, Vec<FileBreakdownEntry>)> {
    let row = client
        .query_opt(
            r#"
SELECT recorded_at, payload_json
FROM analysis
WHERE recorded_at >= $1 AND recorded_at <= $2
ORDER BY recorded_at DESC
LIMIT 1
"#,
            &[&start, &end],
        )
        .context("query latest payload_json failed")?
        .context("no analysis rows found in selected time range")?;

    let recorded_at: DateTime<Utc> = row.get(0);
    let payload: Value = row.get(1);

    let by_file = payload
        .get("by_file")
        .context("payload_json missing required key: by_file")?
        .as_array()
        .context("payload_json.by_file is not an array")?;

    let mut out: Vec<FileBreakdownEntry> = vec![];
    for v in by_file {
        let obj = v.as_object().context("payload_json.by_file entry is not an object")?;

        let file = obj
            .get("file")
            .context("payload_json.by_file entry missing file")?
            .as_str()
            .context("payload_json.by_file.file is not a string")?
            .to_string();

        let total = obj
            .get("total")
            .context("payload_json.by_file entry missing total")?
            .as_u64()
            .context("payload_json.by_file.total is not a u64")? as i64;

        let lock_violations = obj
            .get("lock_violations")
            .context("payload_json.by_file entry missing lock_violations")?
            .as_u64()
            .context("payload_json.by_file.lock_violations is not a u64")? as i64;
        let spawn_violations = obj
            .get("spawn_violations")
            .context("payload_json.by_file entry missing spawn_violations")?
            .as_u64()
            .context("payload_json.by_file.spawn_violations is not a u64")? as i64;
        let ssot_violations = obj
            .get("ssot_violations")
            .context("payload_json.by_file entry missing ssot_violations")?
            .as_u64()
            .context("payload_json.by_file.ssot_violations is not a u64")? as i64;
        let ssot_leakage_violations = obj
            .get("ssot_leakage_violations")
            .and_then(|v| v.as_u64())
            .map(|v| v as i64)
            .unwrap_or(0);
        let ssot_cache_violations = obj
            .get("ssot_cache_violations")
            .and_then(|v| v.as_u64())
            .map(|v| v as i64)
            .unwrap_or(0);
        let fallback_violations = obj
            .get("fallback_violations")
            .context("payload_json.by_file entry missing fallback_violations")?
            .as_u64()
            .context("payload_json.by_file.fallback_violations is not a u64")? as i64;
        let required_config_violations = obj
            .get("required_config_violations")
            .context("payload_json.by_file entry missing required_config_violations")?
            .as_u64()
            .context("payload_json.by_file.required_config_violations is not a u64")? as i64;
        let sensitive_violations = obj
            .get("sensitive_violations")
            .context("payload_json.by_file entry missing sensitive_violations")?
            .as_u64()
            .context("payload_json.by_file.sensitive_violations is not a u64")? as i64;
        let hardcode_violations = obj
            .get("hardcode_violations")
            .context("payload_json.by_file entry missing hardcode_violations")?
            .as_u64()
            .context("payload_json.by_file.hardcode_violations is not a u64")? as i64;
        let hardcoded_literal_violations = obj
            .get("hardcoded_literal_violations")
            .and_then(|v| v.as_u64())
            .map(|v| v as i64)
            .unwrap_or(0);
        let hardcoded_sleep_violations = obj
            .get("hardcoded_sleep_violations")
            .and_then(|v| v.as_u64())
            .map(|v| v as i64)
            .unwrap_or(0);
        let style_violations = obj
            .get("style_violations")
            .context("payload_json.by_file entry missing style_violations")?
            .as_u64()
            .context("payload_json.by_file.style_violations is not a u64")? as i64;
        let blocking_lock_violations = obj
            .get("blocking_lock_violations")
            .context("payload_json.by_file entry missing blocking_lock_violations")?
            .as_u64()
            .context("payload_json.by_file.blocking_lock_violations is not a u64")? as i64;
        let no_cache_violations = obj
            .get("no_cache_violations")
            .and_then(|v| v.as_u64())
            .map(|v| v as i64)
            .unwrap_or(0);

        out.push(FileBreakdownEntry {
            file,
            total,
            lock_violations,
            spawn_violations,
            ssot_violations,
            ssot_leakage_violations,
            ssot_cache_violations,
            fallback_violations,
            required_config_violations,
            sensitive_violations,
            hardcode_violations,
            hardcoded_literal_violations,
            hardcoded_sleep_violations,
            style_violations,
            blocking_lock_violations,
            no_cache_violations,
        });
    }

    Ok((recorded_at, out))
}

fn main() {
    let db_url = match std::env::var("XTASK_ANALYSIS_DB_URL") {
        Ok(v) => v,
        Err(_) => {
            eprintln!("FATAL: XTASK_ANALYSIS_DB_URL not set (required for xtask_plot)");
            std::process::exit(1);
        }
    };
    if db_url.trim().is_empty() {
        eprintln!("FATAL: XTASK_ANALYSIS_DB_URL is empty");
        std::process::exit(1);
    }

    let options = eframe::NativeOptions::default();
    let res = eframe::run_native(
        "xtask_plot",
        options,
        Box::new(move |_cc| Box::new(PlotApp::new(db_url))),
    );
    if let Err(e) = res {
        eprintln!("FATAL: failed to start xtask_plot GUI: {e}");
        std::process::exit(1);
    }
}


