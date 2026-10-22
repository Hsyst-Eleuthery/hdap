use crate::app::{App, SortKey, Toast, ToastKind};
use crate::i18n::{fill1, fill2, fill4};
use egui::{Align, Align2, Color32, RichText};
use image;
use std::sync::atomic::Ordering;

/// Icon fallback: egui has no file icons built-in, so we draw simple glyphs.
fn icon_char(is_dir: bool) -> &'static str {
    if is_dir {
        "📁"
    } else {
        "📄"
    }
}

fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1} {}", UNITS[i])
}

fn human_count(n: f64) -> String {
    const SUFFIX: [&str; 5] = ["", "k", "M", "G", "T"];
    let mut v = n;
    let mut i = 0;
    while v >= 1000.0 && i < SUFFIX.len() - 1 {
        v /= 1000.0;
        i += 1;
    }
    if i == 0 {
        format!("{v:.0}")
    } else {
        format!("{v:.1}{}", SUFFIX[i])
    }
}

/// Handle files dropped from the OS onto the window and queue them for upload.
fn handle_dropped_files(ui: &mut egui::Ui, app: &mut App) {
    let dropped = ui.ctx().input(|i| i.raw.dropped_files.clone());
    for f in dropped {
        app.queue_upload(f.path());
    }
}

/// Show the pending-upload banner (clone the queue to avoid borrow conflicts).
fn render_pending_upload(ui: &mut egui::Ui, app: &mut App) {
    let Some(pending) = app.pending_upload.clone() else {
        return;
    };
    let (name, data) = pending;
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(format!(
                    "{} {name} ({} bytes)",
                    app.strings.upload_banner_lbl,
                    data.len()
                ))
                .strong(),
            );
            if ui.button("🗑").clicked() {
                app.clear_pending();
            }
        });
        let dest = if app.cwd.is_empty() {
            name.clone()
        } else {
            format!("{}/{}", app.cwd, name)
        };
        if ui.button(app.strings.upload_now).clicked() {
            app.do_upload();
        }
        ui.monospace(format!("→ {dest}"));
    });
}

const TOAST_TTL: f64 = 5.0;

fn toast_color(kind: &ToastKind) -> Color32 {
    match kind {
        ToastKind::Info => Color32::from_rgb(80, 170, 220),
        ToastKind::Success => Color32::from_rgb(90, 200, 120),
        ToastKind::Error => Color32::from_rgb(220, 90, 90),
    }
}

/// Overlay toasts in the top-right corner, stacked newest last.
fn render_toasts(ui: &mut egui::Ui, now: f64, app: &mut App) {
    if app.toasts.is_empty() {
        return;
    }
    let toasts: Vec<Toast> = app.toasts.clone();
    egui::Area::new(egui::Id::new("toasts"))
        .anchor(Align2::RIGHT_TOP, [-14.0, 10.0])
        .order(egui::Order::Foreground)
        .show(ui.ctx(), |ui| {
            let mut fade: Option<u64> = None;
            for t in &toasts {
                let age = now - t.born;
                let alpha = ((TOAST_TTL - age) / 1.2).clamp(0.0, 1.0) as f32;
                let kind_col = toast_color(&t.kind).gamma_multiply(alpha);
                egui::Frame::popup(ui.style())
                    .fill(Color32::from_rgba_unmultiplied(
                        32,
                        32,
                        36,
                        (alpha * 235.0) as u8,
                    ))
                    .corner_radius(8.0)
                    .inner_margin(egui::Margin::same(10))
                    .show(ui, |ui| {
                        ui.set_max_width(300.0);
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("● ").color(kind_col).strong());
                            ui.label(RichText::new(&t.text).color(
                                Color32::from_rgba_unmultiplied(
                                    240,
                                    240,
                                    240,
                                    (alpha * 255.0) as u8,
                                ),
                            ));
                            if ui
                                .small_button("✕")
                                .on_hover_text(app.strings.discard)
                                .clicked()
                            {
                                fade = Some(t.id);
                            }
                        });
                    });
            }
            if let Some(id) = fade {
                app.toasts.retain(|t| t.id != id);
            }
        });
}

/// Compute progress stats for a PoW that is still running.
fn pow_stats(pow: &crate::app::PowState) -> (u64, f64, f64) {
    let attempts = pow.attempts.load(Ordering::Relaxed);
    let elapsed_s = pow.started.elapsed().as_secs_f64().max(0.001);
    let rate = attempts as f64 / elapsed_s;
    (attempts, rate, elapsed_s)
}

/// Render the mining dialog (HPS-style "working" modal) centered over the
/// explorer. Live-refreshing; the cancel button aborts the solver thread.
fn render_pow_modal(ui: &mut egui::Ui, app: &mut App) {
    let Some(state) = &app.pow else {
        return;
    };
    let target_bits = state.target_bits;
    let (attempts, rate, elapsed_s) = pow_stats(state);
    // expected cost of the proof ≈ 2^(target_bits)
    let expected = 2f64.powi(target_bits as i32);
    let frac = ((attempts as f64) / expected).min(1.0);
    let eta_s = if rate > 0.0 {
        ((expected - attempts as f64).max(0.0)) / rate
    } else {
        f64::INFINITY
    };

    let mut cancel = false;
    egui::Modal::new(egui::Id::new("pow-modal")).show(ui.ctx(), |ui| {
        ui.set_max_width(360.0);
        ui.horizontal(|ui| {
            ui.spinner();
            ui.heading(app.strings.pow_title);
        });
        ui.label(RichText::new(app.strings.pow_mining).weak());
        ui.add_space(6.0);
        ui.add(
            egui::ProgressBar::new(frac as f32)
                .animate(true)
                .show_percentage(),
        );
        ui.label(format!("{} {target_bits} bits", app.strings.pow_difficulty));
        ui.add_space(2.0);
        ui.monospace(fill2(
            app.strings.pow_attempts,
            &human_count(attempts as f64),
            &human_count(rate),
        ));
        ui.monospace(fill2(
            app.strings.pow_expected,
            &human_count(expected),
            &fmt_eta(eta_s),
        ));
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label(fill1(app.strings.pow_elapsed, &fmt_eta(elapsed_s)));
            if ui
                .button(RichText::new(app.strings.pow_cancel).color(Color32::LIGHT_RED))
                .clicked()
            {
                cancel = true;
            }
        });
    });
    if cancel {
        app.cancel_band();
    }
}

/// Render the integrated file preview modal (text, image, audio).
fn render_preview_modal(ui: &mut egui::Ui, app: &mut App) {
    let Some(preview) = &app.preview else {
        return;
    };

    let mut close = false;
    egui::Modal::new(egui::Id::new("preview-modal")).show(ui.ctx(), |ui| {
        ui.set_max_width(800.0);
        ui.set_max_height(600.0);
        ui.horizontal(|ui| {
            ui.heading(app.strings.preview_title);
            if ui
                .button(RichText::new("✕").color(Color32::LIGHT_RED))
                .clicked()
            {
                close = true;
            }
        });
        ui.add_space(8.0);
        ui.label(RichText::new(&preview.path).small().weak());
        ui.add_space(4.0);
        match preview.content_type {
            crate::app::PreviewContentType::Text => {
                let mut text = String::from_utf8_lossy(&preview.data).to_string();
                egui::ScrollArea::both().show(ui, |ui| {
                    ui.add_sized(
                        [ui.available_width(), ui.available_height() - 40.0],
                        egui::TextEdit::multiline(&mut text)
                            .font(egui::TextStyle::Monospace)
                            .interactive(false),
                    );
                });
            }
            crate::app::PreviewContentType::Image => {
                if let Ok(image) = image::load_from_memory(&preview.data) {
                    let rgba = image.to_rgba8();
                    let size = [rgba.width() as usize, rgba.height() as usize];
                    let color_image = egui::ColorImage::from_rgba_unmultiplied(size, &rgba);
                    let texture = ui.ctx().load_texture(
                        format!("preview-{}", preview.path),
                        color_image,
                        egui::TextureOptions::LINEAR,
                    );
                    let max_size =
                        egui::Vec2::new(ui.available_width(), ui.available_height() - 60.0);
                    let aspect = size[0] as f32 / size[1] as f32;
                    let size = if max_size.x / aspect <= max_size.y {
                        egui::Vec2::new(max_size.x, max_size.x / aspect)
                    } else {
                        egui::Vec2::new(max_size.y * aspect, max_size.y)
                    };
                    ui.add(egui::Image::new(&texture).fit_to_exact_size(size));
                } else {
                    ui.label(format!("⚠ {}", app.strings.preview_image_error));
                }
            }
            crate::app::PreviewContentType::Audio => {
                ui.label(app.strings.preview_audio_not_supported);
                ui.add_space(8.0);
                if ui.button(app.strings.download).clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .set_file_name(&preview.path)
                        .save_file()
                    {
                        let _ = std::fs::write(path, &preview.data);
                    }
                }
            }
            crate::app::PreviewContentType::Unknown => {
                ui.label(app.strings.preview_unknown);
                ui.add_space(8.0);
                if ui.button(app.strings.download).clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .set_file_name(&preview.path)
                        .save_file()
                    {
                        let _ = std::fs::write(path, &preview.data);
                    }
                }
            }
        }
    });
    if close {
        app.close_preview();
    }
}

fn fmt_eta(s: f64) -> String {
    if s.is_infinite() || s.is_nan() {
        "∞".to_string()
    } else if s < 60.0 {
        format!("{s:.1}s")
    } else if s < 3600.0 {
        format!("{:02}:{:02}", (s / 60.0) as u64, (s % 60.0) as u64)
    } else {
        format!(
            "{}h:{:02}m",
            (s / 3600.0) as u64,
            ((s % 3600.0) / 60.0) as u64
        )
    }
}

/// Full-screen connection wizard shown before the first successful login.
/// Label + field on one line, tight spacing.
fn field_row(ui: &mut egui::Ui, label: &str, text: egui::TextEdit) {
    ui.horizontal(|ui| {
        ui.add_sized([76.0, 20.0], egui::Label::new(RichText::new(label).small()));
        ui.add(text.desired_width(200.0));
    });
}

fn render_wizard(ui: &mut egui::Ui, app: &mut App) {
    let mut do_connect = false;
    egui::CentralPanel::default().show(ui, |ui| {
        ui.vertical_centered(|ui| {
            ui.add_space(6.0);
            ui.label(RichText::new("HDAP").size(20.0).strong());
            ui.label(RichText::new(app.strings.wizard_subtitle).size(12.0).weak());
        });
        ui.add_space(2.0);
        ui.vertical_centered(|ui| {
            egui::Frame::group(ui.style())
                .fill(Color32::from_rgb(36, 36, 42))
                .corner_radius(8.0)
                .inner_margin(egui::Margin::same(10))
                .show(ui, |ui| {
                    ui.set_max_width(300.0);
                    field_row(
                        ui,
                        app.strings.label_node,
                        egui::TextEdit::singleline(&mut app.host),
                    );
                    field_row(
                        ui,
                        app.strings.label_port,
                        egui::TextEdit::singleline(&mut app.port),
                    );
                    field_row(
                        ui,
                        app.strings.label_pin,
                        egui::TextEdit::singleline(&mut app.pin)
                            .hint_text(app.strings.pin_empty_tofu),
                    );
                    ui.horizontal(|ui| {
                        ui.add_sized(
                            [76.0, 20.0],
                            egui::Label::new(RichText::new(app.strings.label_options).small()),
                        );
                        ui.checkbox(&mut app.insecure, app.strings.plaintext_dev);
                    });
                    ui.separator();
                    field_row(
                        ui,
                        app.strings.label_home,
                        egui::TextEdit::singleline(&mut app.home_dir)
                            .hint_text(app.strings.home_empty_temp),
                    );
                    field_row(
                        ui,
                        app.strings.label_nick,
                        egui::TextEdit::singleline(&mut app.nickname)
                            .hint_text(app.strings.nick_example),
                    );
                    field_row(
                        ui,
                        app.strings.label_pass,
                        egui::TextEdit::singleline(&mut app.password).password(true),
                    );
                    ui.horizontal(|ui| {
                        ui.add_sized(
                            [76.0, 20.0],
                            egui::Label::new(RichText::new(app.strings.label_lang).small()),
                        );
                        let mut lang = app.lang;
                        egui::ComboBox::from_id_salt("wizard_lang")
                            .selected_text(app.lang.name())
                            .show_ui(ui, |ui| {
                                for l in crate::i18n::Lang::ALL {
                                    ui.selectable_value(&mut lang, l, l.name());
                                }
                            });
                        if lang != app.lang {
                            app.set_lang(lang);
                        }
                    });
                    if app.pin.is_empty() && !app.insecure {
                        ui.label(RichText::new(app.strings.pin_note).small().weak());
                    }
                    ui.horizontal(|ui| {
                        let label = if app.connecting {
                            app.strings.connecting
                        } else {
                            app.strings.connect
                        };
                        if ui
                            .add_enabled(!app.connecting, egui::Button::new(label))
                            .clicked()
                        {
                            do_connect = true;
                        }
                        if app.connecting {
                            ui.spinner();
                            ui.label(
                                RichText::new(format!("{:.0}s", app.connect_elapsed())).small(),
                            );
                            if ui.small_button(app.strings.cancel).clicked() {
                                app.cancel_connect();
                            }
                        }
                        ui.label(RichText::new(&app.status).small().weak());
                    });
                });
        });
    });
    if do_connect {
        app.connect();
    }
}

/// Render the whole explorer inside the main `ui` (egui 0.36 `eframe::App`).
/// Explicit house move: the user names the new pyle and signs a newer adeia.
/// Kept manual on purpose: the client cannot reliably infer that an old home
/// is gone, and an automatic move would be an irreversible identity action.
fn render_house_move_panel(ui: &mut egui::Ui, app: &mut App) {
    ui.label(crate::theme::heading(app.strings.house_move_title));
    ui.add(egui::Label::new(crate::theme::muted(app.strings.house_move_about)).wrap());
    ui.separator();
    ui.label(crate::theme::muted(app.strings.house_move_new_pyle));
    ui.add(
        egui::TextEdit::singleline(&mut app.house_move_new_pyle)
            .desired_width(ui.available_width())
            .font(egui::TextStyle::Monospace)
            .hint_text(app.strings.house_move_hint),
    );
    ui.add_space(4.0);
    ui.label(crate::theme::muted(app.strings.house_move_adeia));
    ui.add(
        egui::TextEdit::multiline(&mut app.house_move_adeia)
            .desired_width(ui.available_width())
            .desired_rows(12)
            .font(egui::TextStyle::Monospace),
    );
    ui.add_space(4.0);
    if !app.house_move_status.is_empty() {
        ui.add(egui::Label::new(crate::theme::muted(&app.house_move_status)).wrap());
    }
    let ready = !app.house_move_busy
        && !app.house_move_new_pyle.trim().is_empty()
        && !app.house_move_adeia.trim().is_empty();
    if app.house_move_busy {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(app.strings.house_move_signing);
        });
    }
    if ui
        .add_enabled(ready, egui::Button::new(app.strings.house_move_submit))
        .clicked()
    {
        app.submit_house_move();
    }
    ui.separator();
    if ui.button(app.strings.close_panel).clicked() {
        app.side_panel = None;
    }
}

/// Signed fallback list: authorizes named pyles to take over the identity if
/// the current home stops answering. Re-signing is required after an adeia
/// edit because the document pins the ACL hash.
fn render_diadosi_panel(ui: &mut egui::Ui, app: &mut App) {
    ui.label(crate::theme::heading(app.strings.diadosi_title));
    ui.add(egui::Label::new(crate::theme::muted(app.strings.diadosi_about)).wrap());
    let home = app
        .session
        .as_ref()
        .map(|s| s.server_id.clone())
        .unwrap_or_else(|| "—".to_string());
    ui.label(crate::theme::muted(crate::i18n::fill1(
        app.strings.diadosi_home,
        &home,
    )));
    ui.separator();
    ui.label(crate::theme::muted(app.strings.diadosi_fallbacks));
    ui.add(
        egui::TextEdit::singleline(&mut app.diadosi_fallbacks)
            .desired_width(ui.available_width())
            .font(egui::TextStyle::Monospace)
            .hint_text(app.strings.diadosi_hint),
    );
    if ui.button(app.strings.diadosi_suggest_btn).clicked() {
        app.suggest_diadosi_fallbacks();
    }
    ui.add_space(4.0);
    if !app.diadosi_status.is_empty() {
        ui.add(egui::Label::new(crate::theme::muted(&app.diadosi_status)).wrap());
    }
    let ready = !app.diadosi_busy && !app.diadosi_fallbacks.trim().is_empty();
    if app.diadosi_busy {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(app.strings.diadosi_signing);
        });
    }
    if ui
        .add_enabled(ready, egui::Button::new(app.strings.diadosi_submit))
        .clicked()
    {
        app.submit_diadosi();
    }
    ui.separator();
    if ui.button(app.strings.close_panel).clicked() {
        app.side_panel = None;
    }
}

/// The connected pyle stopped answering. This is a deliberate prompt, not a
/// silent status line: the user chooses to leave for the login screen (and
/// then sign a house move on another pyle) or keep the session and retry.
fn render_link_down_modal(ui: &mut egui::Ui, app: &mut App) {
    if !app.link_down || app.session.is_none() {
        return;
    }
    egui::Window::new(app.strings.link_down_title)
        .id(egui::Id::new("hdap_link_down_modal"))
        .collapsible(false)
        .resizable(false)
        .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ui.ctx(), |ui| {
            ui.set_max_width(460.0);
            ui.add(
                egui::Label::new(fill2(
                    app.strings.link_down_body,
                    &app.endpoint(),
                    &app.link_error,
                ))
                .wrap(),
            );
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui.button(app.strings.link_down_login).clicked() {
                    app.leave_for_login();
                }
                if ui.button(app.strings.link_down_stay).clicked() {
                    app.dismiss_link_down();
                }
            });
        });
}

/// Expandable "Bolha: N pyles (core, extended, untrusted)" detail window.
fn render_bubble_window(ui: &mut egui::Ui, app: &mut App) {
    if !app.bubble_open {
        return;
    }
    let mut open = true;
    egui::Window::new(app.strings.bubble_title)
        .open(&mut open)
        .resizable(true)
        .default_width(560.0)
        .show(ui.ctx(), |ui| {
            let b = app.bubble.clone();
            ui.label(
                RichText::new(fill4(
                    app.strings.bubble_summary,
                    &b.total.to_string(),
                    &b.core.to_string(),
                    &b.extended.to_string(),
                    &b.untrusted.to_string(),
                ))
                .strong(),
            );
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut app.bubble_filter)
                        .desired_width(ui.available_width())
                        .hint_text(app.strings.bubble_filter_hint),
                );
            });
            ui.separator();
            ui.label(crate::theme::muted(app.strings.hash_lookup));
            ui.horizontal(|ui| {
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut app.hash_input)
                        .desired_width(ui.available_width() - 80.0)
                        .font(egui::TextStyle::Monospace)
                        .hint_text("64 hex"),
                );
                let entered = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                let button = ui
                    .button(app.strings.hash_search)
                    .on_hover_text(app.strings.hash_lookup)
                    .clicked();
                if app.hash_busy {
                    ui.spinner();
                }
                if (button || entered) && !app.hash_busy {
                    app.lookup_hash();
                }
            });
            if let Some(found) = app.hash_result.clone() {
                if !found.error.is_empty() {
                    ui.add(
                        egui::Label::new(
                            RichText::new(&found.error).color(Color32::from_rgb(230, 120, 90)),
                        )
                        .wrap(),
                    );
                } else {
                    ui.add(
                        egui::Label::new(crate::theme::muted(format!(
                            "{} · {} · {} · {}",
                            found.status,
                            if found.verified {
                                "verified"
                            } else {
                                "unverified"
                            },
                            found.owner,
                            found.path,
                        )))
                        .wrap(),
                    );
                    if !found.holders.is_empty() {
                        ui.add(
                            egui::Label::new(crate::theme::muted(format!(
                                "{}: {}",
                                app.strings.hash_holders,
                                found.holders.join(", ")
                            )))
                            .wrap(),
                        );
                    }
                    if ui.button(app.strings.open).clicked() {
                        app.open_hash_result();
                    }
                }
            }
            ui.separator();
            if b.peers.is_empty() {
                ui.label(crate::theme::muted(app.strings.bubble_empty));
                return;
            }
            egui::ScrollArea::vertical()
                .max_height(340.0)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    let filter = app.bubble_filter.trim().to_ascii_lowercase();
                    for peer in b.peers.iter().filter(|p| {
                        filter.is_empty()
                            || p.node_id.to_ascii_lowercase().contains(&filter)
                            || p.endpoint.to_ascii_lowercase().contains(&filter)
                    }) {
                        let color = match peer.tier.as_str() {
                            "core" => Color32::from_rgb(90, 200, 120),
                            "extended" => Color32::from_rgb(220, 180, 80),
                            _ => Color32::from_rgb(220, 90, 90),
                        };
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(&peer.tier).color(color).strong());
                            ui.monospace(&peer.node_id);
                        });
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(&peer.endpoint).weak().small());
                            ui.label(
                                RichText::new(format!(
                                    "{} · fail {} · seen {}",
                                    if peer.verified {
                                        "verified"
                                    } else {
                                        "unverified"
                                    },
                                    peer.failures,
                                    peer.last_seen
                                ))
                                .weak()
                                .small(),
                            );
                        });
                        ui.separator();
                    }
                });
        });
    if !open {
        app.bubble_open = false;
    }
}

pub fn render(ui: &mut egui::Ui, app: &mut App) {
    handle_dropped_files(ui, app);

    // `app.rs` cannot touch egui, so it parks clipboard requests here and the
    // view is the one that actually owns `Context::copy_text`. Draining it
    // every frame is what makes the copy button do anything at all.
    if let Some(text) = app.pending_clipboard.take() {
        ui.ctx().copy_text(text);
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    app.tick(now, TOAST_TTL);
    render_toasts(ui, now, app);
    render_pow_modal(ui, app);
    render_preview_modal(ui, app);
    render_bubble_window(ui, app);
    render_link_down_modal(ui, app);

    // Connection wizard replaces the whole layout until logged in.
    if app.session.is_none() {
        render_wizard(ui, app);
        return;
    }

    let mut upload_requested = false;
    egui::Panel::top("toolbar").show(ui, |ui| {
        // Row 1: navigation + the primary actions. Kept short on purpose:
        // a crowded toolbar is what pushed buttons off the window before.
        ui.horizontal(|ui| {
            if ui
                .add_enabled(!app.back_stack.is_empty(), egui::Button::new("←"))
                .on_hover_text(app.strings.back)
                .clicked()
            {
                app.back();
            }
            if ui
                .add_enabled(!app.forward_stack.is_empty(), egui::Button::new("→"))
                .on_hover_text(app.strings.forward)
                .clicked()
            {
                app.forward();
            }
            if ui
                .add_enabled(!app.cwd.is_empty(), egui::Button::new("↑"))
                .on_hover_text(app.strings.up)
                .clicked()
            {
                app.up();
            }
            if ui.button("↻").on_hover_text(app.strings.reload).clicked() {
                app.sync_space();
            }
            ui.separator();
            if ui
                .add_enabled(!app.read_only(), egui::Button::new(app.strings.upload))
                .on_hover_text(if app.read_only() {
                    app.strings.upload_hover_ro
                } else {
                    app.strings.upload_hover
                })
                .clicked()
            {
                upload_requested = true;
            }
            if ui
                .button(app.strings.config)
                .on_hover_text(app.strings.config_hover)
                .clicked()
            {
                app.toggle_panel(crate::app::SidePanel::Config);
            }
            if ui
                .button(app.strings.band_btn)
                .on_hover_text(app.strings.band_hover)
                .clicked()
            {
                app.begin_band(0);
            }
            app.last_actions_rect = Some(ui.min_rect());

            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                let (uid, ttl) = app
                    .session
                    .as_ref()
                    .map(|s| (s.user_id.clone(), s.friendly_ttl()))
                    .unwrap_or_default();
                if app.session.is_some() {
                    if ui
                        .button(app.strings.sign_out)
                        .on_hover_text(app.strings.sign_out_hover)
                        .clicked()
                    {
                        app.disconnect();
                    }
                    if app.read_only() {
                        ui.label(
                            RichText::new(app.strings.readonly_badge)
                                .small()
                                .color(crate::theme::ORCHID),
                        );
                    }
                    ui.label(crate::theme::badge(fill1(
                        app.strings.u_band,
                        &human_size(app.band),
                    )));
                    ui.label(crate::theme::muted(fill2(
                        app.strings.u_expires,
                        &uid,
                        &ttl,
                    )));
                    ui.label(
                        RichText::new(app.strings.connected).color(crate::theme::VIOLET_LIGHT),
                    );
                } else {
                    ui.label(RichText::new(app.strings.not_connected).color(Color32::RED));
                }
            });
        });

        // Row 2: the logical URI of where you are, editable. Always the full
        // `HDAP!<pyle>@<user>/<caminho>` — a bare "/" tells you nothing about
        // which node or which identity you are looking at.
        //
        // It is a real address bar, not a label: type a path and it navigates,
        // like any file manager. While the field has focus the text is the
        // user's, so the view stops overwriting it with the computed location.
        ui.horizontal(|ui| {
            ui.label(RichText::new("URI").small().color(crate::theme::ORCHID));
            let computed = app.logical_uri();
            if !app.uri_editing {
                // Only snap back to the computed URI when the user is not
                // mid-edit; otherwise every redraw would erase what was typed.
                app.uri_edit = computed.clone();
            }
            let resp = ui.add(
                egui::TextEdit::singleline(&mut app.uri_edit)
                    .desired_width(f32::INFINITY)
                    .font(egui::TextStyle::Monospace)
                    .text_color(crate::theme::VIOLET_LIGHT)
                    .hint_text(app.strings.uri_edit_hint),
            );
            if resp.changed() {
                app.uri_editing = true;
            }
            // Focus is what tells us the field is "the user's" — otherwise
            // blur after an Enter would let the next frame wipe the text.
            if resp.has_focus() {
                app.uri_editing = true;
            } else if app.uri_editing && !resp.changed() {
                app.uri_editing = false;
            }
            // Enter (or the button) submits; blur without Enter is just focus moving on,
            // and must not navigate — losing focus mid-typing is not consent.
            // `lost_focus()` is what a single-line `TextEdit` reports after
            // Enter: it consumes the key and gives focus back in the same
            // frame, so checking `has_focus()` made the address bar ignore
            // Enter entirely (the button still worked).
            let submitted = ui.button("↵").on_hover_text(app.strings.uri_go).clicked()
                || (resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)));
            if submitted {
                let typed = app.uri_edit.clone();
                // Whatever happens, stop treating the field as the user's: the
                // next frame shows the location we actually ended up at.
                app.uri_editing = false;
                app.submit_uri(&typed);
            }
            if ui
                .button("📋")
                .on_hover_text(app.strings.copy_uri)
                .clicked()
            {
                app.request_clipboard(&computed);
            }
            ui.checkbox(&mut app.uri_with_hash, app.strings.with_hash);
            app.last_uri_shown = computed;
            app.uri_rect = Some(ui.min_rect());
        });
    });

    if upload_requested {
        if let Some(path) = rfd::FileDialog::new().pick_file() {
            app.queue_upload(&path);
        }
    }

    egui::Panel::bottom("status").show(ui, |ui| {
        ui.add_space(2.0);
        ui.horizontal(|ui| {
            if let Some(busy) = &app.busy {
                ui.spinner();
                ui.label(busy);
                ui.separator();
            }
            ui.label(RichText::new(&app.status).monospace());
            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                if app.session.is_some() {
                    ui.label(
                        RichText::new(fill1(app.strings.u_band_colon, &human_size(app.band)))
                            .weak(),
                    );
                    ui.separator();
                    if app.bubble_busy {
                        ui.spinner();
                    }
                    let label = if app.bubble_open {
                        app.strings.bubble_hide
                    } else {
                        app.strings.bubble_show
                    };
                    if ui
                        .small_button(label)
                        .on_hover_text(app.strings.bubble_title)
                        .clicked()
                    {
                        app.bubble_open = !app.bubble_open;
                    }
                    let b = &app.bubble;
                    ui.label(
                        RichText::new(fill4(
                            app.strings.bubble_summary,
                            &b.total.to_string(),
                            &b.core.to_string(),
                            &b.extended.to_string(),
                            &b.untrusted.to_string(),
                        ))
                        .small()
                        .weak(),
                    );
                }
            });
        });
        if let Some((_, local, n, hash)) = &app.last_download {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!("{} {local} ({n} B)", app.strings.last_download)).weak(),
                );
                ui.label(RichText::new(format!("sha256 {hash}")).weak());
            });
        }
        ui.add_space(2.0);
    });

    // `exact_size`, not `default_size`: egui treats `default_size` as only the
    // initial value and then lets the *content* decide the final width, which
    // is handed straight back to the parent (the file grid). A 64-hex server
    // id or a sha256 line is unbreakable, so it inflated the sidebar and
    // squeezed the grid — and any re-measure that changed the content width
    // (hover relayout, language change, resize) dragged the divider.
    let sidebar = egui::Panel::left("sidebar")
        .resizable(false)
        .exact_size(230.0)
        .show(ui, |ui| {
            // The stack (Places, People, Band, Network, Panels, Identity) is
            // taller than the viewport at the default window size, and a panel
            // without a scroll area just clips the overflow away. Scroll, as the
            // right-hand panel already does.
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.add_space(2.0);
                    ui.label(crate::theme::heading(app.strings.s_places));
                    let home = format!(
                        "🏠 {}",
                        app.active_owner()
                            .unwrap_or_else(|| app.strings.s_root.into())
                    );
                    if ui.selectable_label(app.cwd.is_empty(), home).clicked() {
                        app.return_home();
                    }
                    // Name the destination: "up" without a target is a guess, and on a
                    // deep tree the user cannot see where they are from the sidebar.
                    let above = if app.cwd.is_empty() {
                        app.strings.s_root.to_string()
                    } else {
                        let p = parent_of(&app.cwd);
                        if p.is_empty() {
                            app.strings.s_root.to_string()
                        } else {
                            p.rsplit('/').next().unwrap_or(p).to_string()
                        }
                    };
                    if ui
                        .add_enabled(!app.cwd.is_empty(), egui::Button::new(format!("↑ {above}")))
                        .clicked()
                    {
                        app.up();
                    }

                    ui.add_space(6.0);
                    ui.separator();
                    ui.add_space(4.0);
                    ui.label(crate::theme::heading(app.strings.s_people));
                    // Other users' spaces: a nickname, a global id, or a full
                    // `HDAP!<pyle>@<user>/` URI — the node shows only what their
                    // `adeia` grants you, pulling from another pyle when the URI says so.
                    ui.horizontal(|ui| {
                        let resp = ui.add(
                            egui::TextEdit::singleline(&mut app.person_input)
                                .desired_width(ui.available_width() - 40.0)
                                .hint_text(app.strings.person_hint),
                        );
                        let submitted =
                            resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        let person = app.person_input.clone();
                        let going = app.visit_busy || app.mirror_busy;
                        let clicked = ui
                            .add_enabled(!going, egui::Button::new(app.strings.s_open))
                            .clicked();
                        if !going && (clicked || submitted) {
                            app.visit(&person);
                        }
                    });
                    if app.visit_busy {
                        ui.label(crate::theme::muted(app.strings.resolving));
                    } else if app.read_only() {
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(format!("🔭 {}", app.visiting))
                                    .small()
                                    .color(crate::theme::ORCHID),
                            );
                            if ui.small_button(app.strings.back_home).clicked() {
                                app.return_home();
                            }
                        });
                    } else if !app.visit_status.is_empty() {
                        ui.label(crate::theme::muted(&app.visit_status));
                    }

                    ui.add_space(6.0);
                    ui.separator();
                    ui.add_space(4.0);
                    ui.label(crate::theme::heading(app.strings.s_band));
                    // Band is a resource you spend to upload, and it is earned by CPU,
                    // so it gets a permanent card with the mining button on it. Burying
                    // it in a toolbar row is how it ended up looking unavailable.
                    egui::Frame::group(ui.style())
                        .inner_margin(egui::Margin::symmetric(8, 6))
                        .fill(crate::theme::SURFACE_ALT)
                        .show(ui, |ui| {
                            ui.label(crate::theme::badge(human_size(app.band)));
                            ui.label(crate::theme::muted(app.strings.band_available));
                            let mining = app.pow.is_some();
                            if ui
                                .add_sized(
                                    [ui.available_width(), 26.0],
                                    egui::Button::new(if mining {
                                        app.strings.band_mining
                                    } else {
                                        app.strings.band_mine
                                    }),
                                )
                                .clicked()
                                && !mining
                            {
                                app.begin_band(0);
                            }
                            app.band_rect = Some(ui.min_rect());
                        });
                    if app.band == 0 && app.session.is_some() {
                        ui.label(
                            RichText::new(app.strings.band_empty)
                                .small()
                                .color(crate::theme::ORCHID),
                        );
                    }

                    ui.add_space(6.0);
                    ui.separator();
                    ui.add_space(4.0);
                    ui.label(crate::theme::heading(app.strings.s_network));
                    if let Some(s) = &app.session {
                        let (sid, pin) = (s.server_id.clone(), s.tls_pin.clone());
                        // Wrapped, not bare `ui.monospace`: ids and hashes are
                        // unbreakable, so an unwrapped label asks for its full text
                        // width instead of the panel's.
                        ui.add(
                            egui::Label::new(
                                crate::theme::muted(fill1(app.strings.u_node, &sid)).monospace(),
                            )
                            .wrap(),
                        );
                        if let Some(p) = pin {
                            let pinned = !app.pin.trim().is_empty();
                            ui.horizontal(|ui| {
                                ui.label(crate::theme::muted("pin"));
                                ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(format!("{p}…")).monospace(),
                                    )
                                    .wrap(),
                                );
                                if pinned {
                                    ui.label(
                                        RichText::new(app.strings.pinned)
                                            .small()
                                            .color(crate::theme::VIOLET_LIGHT),
                                    );
                                }
                            });
                        }
                    } else {
                        ui.label(crate::theme::muted(app.strings.not_connected));
                    }

                    ui.add_space(6.0);
                    ui.separator();
                    ui.add_space(4.0);
                    ui.label(crate::theme::heading(app.strings.s_panels));
                    ui.horizontal(|ui| {
                        if ui.button(app.strings.config).clicked() {
                            app.toggle_panel(crate::app::SidePanel::Config);
                        }
                        if ui.button(app.strings.prices_btn).clicked() {
                            let was = app.side_panel == Some(crate::app::SidePanel::Prices);
                            app.toggle_panel(crate::app::SidePanel::Prices);
                            if !was {
                                app.refresh_prices();
                            }
                        }
                    });
                    if ui.button(app.strings.aliases_btn).clicked() {
                        app.toggle_panel(crate::app::SidePanel::Aliases);
                    }

                    ui.add_space(6.0);
                    ui.separator();
                    ui.add_space(4.0);
                    ui.label(crate::theme::heading(app.strings.s_identity));
                    match &app.identity {
                        Some(id) => {
                            let gid = id.global_id();
                            ui.add(
                                egui::Label::new(crate::theme::selected_text(gid).monospace())
                                    .wrap(),
                            );
                        }
                        None => {
                            ui.label(crate::theme::muted(app.strings.none));
                        }
                    }
                    if app.identity.is_some() && ui.button(app.strings.house_move_btn).clicked() {
                        app.open_house_move();
                    }
                    if app.identity.is_some() && ui.button(app.strings.diadosi_btn).clicked() {
                        app.open_diadosi();
                    }
                });
        });
    // The panel's own rect, not `ui.min_rect()`: the inner Ui spans the whole
    // strip, while `min_rect` only covers the content that happened to be
    // drawn, so it reads wider when a long id is present.
    app.sidebar_rect = Some(sidebar.response.rect);

    // Only allocate the panel when it has something to show: an always-on
    // right panel eats 300px of the file grid for nothing.
    if let Some(panel) = app.side_panel {
        let right = egui::Panel::right("side")
            .resizable(false)
            .exact_size(360.0)
            .show(ui, |ui| {
                // One viewport, clamped to the strip egui gave this panel. A
                // nested ScrollArea or an `INFINITY`-wide child used to make
                // the content wider than the panel, shifting its left edge
                // under the file grid ("half panel cut").
                let width = ui.available_width();
                ui.set_min_width(width);
                ui.set_max_width(width);
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .max_height(ui.available_height())
                    .show(ui, |ui| {
                        ui.set_min_width(width);
                        ui.set_max_width(width);
                        match panel {
                            crate::app::SidePanel::Prices => {
                                crate::editor::render_prices_panel(ui, app)
                            }
                            crate::app::SidePanel::Aliases => {
                                crate::editor::render_aliases_panel(ui, app)
                            }
                            crate::app::SidePanel::Editor => crate::editor::render(ui, app),
                            crate::app::SidePanel::Config => {
                                crate::editor::render_config_panel(ui, app)
                            }
                            crate::app::SidePanel::HouseMove => render_house_move_panel(ui, app),
                            crate::app::SidePanel::Diadosi => render_diadosi_panel(ui, app),
                        }
                    });
            });
        // The panel's rect must stay inside the strip it was given: content
        // wider than `exact_size` makes egui push the panel past the window
        // edge (the whole panel drifts right, hiding its controls). Captured so
        // a test can assert the editor's permission rows fit.
        app.right_rect = Some(right.response.rect);
    } else {
        app.right_rect = None;
    }

    egui::CentralPanel::default().show(ui, |ui| {
        ui.add_space(1.0);
        render_pending_upload(ui, app);

        // Breadcrumbs + search + sort. The path lives next to the files it
        // describes, and the toolbar above keeps the full URI.
        ui.horizontal(|ui| {
            let crumbs = path_crumbs(&app.cwd);
            if crumbs.is_empty() {
                ui.label(
                    RichText::new("/")
                        .strong()
                        .color(crate::theme::VIOLET_LIGHT),
                );
            } else {
                for (i, (label, full)) in crumbs.iter().enumerate() {
                    if i > 0 {
                        ui.label(RichText::new("/").color(crate::theme::VIOLET_MUTED));
                    }
                    if ui
                        .link(
                            RichText::new(label)
                                .strong()
                                .color(crate::theme::VIOLET_LIGHT),
                        )
                        .clicked()
                    {
                        app.cd(full);
                    }
                }
            }
            ui.separator();
            ui.label(RichText::new("🔍").small());
            ui.add(
                egui::TextEdit::singleline(&mut app.search)
                    .hint_text(app.strings.search)
                    .desired_width(160.0),
            );
            let by_name = app.sort_key == SortKey::Name;
            if ui
                .selectable_label(by_name, app.strings.sort_name)
                .on_hover_text(app.strings.sort_name_hover)
                .clicked()
            {
                app.toggle_sort(SortKey::Name);
            }
            if ui
                .selectable_label(!by_name, app.strings.sort_size)
                .on_hover_text(app.strings.sort_size_hover)
                .clicked()
            {
                app.toggle_sort(SortKey::Size);
            }
            ui.label(RichText::new(if app.sort_desc { "↓" } else { "↑" }).small());
        });
        ui.add_space(2.0);

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                let entries = app.entries.clone();
                egui::Grid::new("filelist")
                    .num_columns(4)
                    .spacing([12.0, 2.0])
                    .striped(true)
                    .show(ui, |ui| {
                        // header row (sortable)
                        ui.strong(app.strings.col_name);
                        ui.strong(app.strings.col_size);
                        ui.strong(app.strings.col_hash);
                        ui.strong(app.strings.col_actions);
                        ui.end_row();
                        for e in &entries {
                            let is_selected = Some(&e.path) == app.selected.as_ref();
                            let label = format!("{} {}", icon_char(e.is_dir), e.name);
                            let resp = ui.selectable_label(is_selected, label);
                            // Right-click a row: no hidden actions. Copying the
                            // entry's URI is the common "share this" gesture,
                            // and selecting it saves a left-click first.
                            let entry_uri = app.entry_uri(e);
                            resp.context_menu(|ui| {
                                if ui.button(app.strings.copy_uri).clicked() {
                                    app.request_clipboard(&entry_uri);
                                    ui.close();
                                }
                                if ui.button(app.strings.select).clicked() {
                                    app.select(&e.path);
                                    ui.close();
                                }
                            });
                            if resp.clicked() && !e.is_dir {
                                app.select(&e.path);
                            }
                            if resp.double_clicked() {
                                if !e.is_dir && !crate::app::is_document(&e.path) {
                                    app.open_preview(&e.path, &e.hash);
                                } else {
                                    app.open_entry(&e.path, e.is_dir);
                                }
                            }
                            if e.is_dir {
                                ui.label(human_size(0));
                            } else {
                                ui.label(human_size(e.size));
                            }
                            render_hash_cell(ui, e.is_dir, &e.hash);
                            if e.is_dir {
                                if ui.small_button(app.strings.open).clicked() {
                                    app.open_entry(&e.path, true);
                                }
                            } else if is_selected {
                                if ui.small_button(app.strings.download).clicked() {
                                    if let Some(dest) =
                                        rfd::FileDialog::new().set_file_name(&e.name).save_file()
                                    {
                                        app.download_selected_to(&dest);
                                    }
                                }
                                if ui
                                    .add_enabled(
                                        !app.read_only(),
                                        egui::Button::new(app.strings.delete),
                                    )
                                    .on_hover_text(if app.read_only() {
                                        app.strings.delete_hover_ro
                                    } else {
                                        ""
                                    })
                                    .clicked()
                                {
                                    app.delete_selected();
                                }
                            } else {
                                if ui.small_button(app.strings.select).clicked() {
                                    app.select(&e.path);
                                }
                            }
                            ui.end_row();
                        }
                    });
                if app.entries.is_empty() {
                    ui.add_space(16.0);
                    ui.centered_and_justified(|ui| {
                        ui.label(app.strings.grid_empty.to_string());
                    });
                }
            });
    });
}

/// Render the hash column (weak/empty for dirs), or nothing.
fn render_hash_cell(ui: &mut egui::Ui, is_dir: bool, text: &str) {
    if is_dir {
        ui.label("");
        return;
    }
    let shown = if text.len() > 12 {
        format!("{}…{}", &text[..6], &text[text.len() - 4..])
    } else {
        text.to_string()
    };
    ui.label(RichText::new(shown).weak().monospace())
        .on_hover_text(if text.is_empty() { "" } else { text });
}

fn parent_of(cwd: &str) -> &str {
    match cwd.rfind('/') {
        Some(i) => &cwd[..i],
        None => "",
    }
}

/// Split a directory path into (short label, full path) breadcrumb segments.
fn path_crumbs(cwd: &str) -> Vec<(String, String)> {
    if cwd.is_empty() {
        return Vec::new();
    }
    let mut parts: Vec<&str> = cwd.split('/').collect();
    if cwd.starts_with('/') {
        parts.remove(0);
    }
    let mut acc = String::new();
    let mut out = Vec::with_capacity(parts.len());
    for p in parts {
        if p.is_empty() {
            continue;
        }
        if !acc.is_empty() {
            acc.push('/');
        }
        acc.push_str(p);
        out.push((p.to_string(), acc.clone()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crumbs_split_paths() {
        assert!(path_crumbs("").is_empty());
        let c = path_crumbs("docs");
        assert_eq!(c[0], ("docs".to_string(), "docs".to_string()));
        let c = path_crumbs("docs/sub");
        assert_eq!(
            c,
            vec![
                ("docs".to_string(), "docs".to_string()),
                ("sub".to_string(), "docs/sub".to_string())
            ]
        );
        assert_eq!(parent_of("docs/sub"), "docs");
        assert_eq!(parent_of("docs"), "");
    }

    #[test]
    fn sizes_are_human() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(2048), "2.0 KiB");
        assert_eq!(human_size(10 * 1024 * 1024), "10.0 MiB");
    }

    #[test]
    fn pow_stats_reports_progress() {
        // progress bar math / expected attempts for difficulty
        let expected = 2f64.powi(8);
        assert_eq!(expected, 256.0);
        assert_eq!(human_count(1_250_000.0), "1.2M");
        assert_eq!(fmt_eta(90.0), "01:30");
        assert_eq!(fmt_eta(f64::INFINITY), "∞");
    }
}
