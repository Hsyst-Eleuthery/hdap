//! Visual identity: a violet/violet-neon palette for both schemes.
//!
//! egui ships no widget theming of its own, so the whole look lives here and
//! is applied once at startup. Kept separate from `view.rs` because a palette
//! is not a widget: it changes what every other panel looks like.

use egui::{Color32, Stroke, Visuals};

/// Deep violet — primary accent, used for selection and progress.
pub const VIOLET: Color32 = Color32::from_rgb(0x7C, 0x4D, 0xFF);
/// Lighter violet for text/accents that must read on dark backgrounds.
pub const VIOLET_LIGHT: Color32 = Color32::from_rgb(0xB3, 0x9C, 0xFF);
/// Darker violet for hover states and separators.
pub const VIOLET_DEEP: Color32 = Color32::from_rgb(0x4A, 0x2F, 0xA8);
/// Magenta-violet used for the second accent (badges, links).
pub const ORCHID: Color32 = Color32::from_rgb(0xE0, 0x6C, 0xFF);
/// Muted violet-grey for secondary text.
pub const VIOLET_MUTED: Color32 = Color32::from_rgb(0x9A, 0x93, 0xB8);

/// Tinted overlay so panels read as violet surfaces instead of grey.
pub const SURFACE: Color32 = Color32::from_rgb(0x24, 0x1E, 0x38);
pub const SURFACE_ALT: Color32 = Color32::from_rgb(0x2E, 0x26, 0x45);

/// Apply the palette to both schemes. Spacing is identical for both, so it
/// goes through `all_styles_mut`; the colours need to know which scheme they
/// are painting, so those are applied per theme.
pub fn apply(ctx: &egui::Context) {
    ctx.all_styles_mut(|style| {
        style.spacing.item_spacing = egui::vec2(6.0, 4.0);
        style.spacing.button_padding = egui::vec2(8.0, 4.0);
        style.spacing.window_margin = egui::Margin::same(8);
        style.spacing.interact_size.y = 20.0;
        style.spacing.item_spacing.x = 7.0;
    });
    ctx.style_mut_of(egui::Theme::Dark, |s| paint(&mut s.visuals, true));
    ctx.style_mut_of(egui::Theme::Light, |s| paint(&mut s.visuals, false));
}

fn paint(visuals: &mut Visuals, dark: bool) {
    {
        if dark {
            visuals.panel_fill = SURFACE;
            visuals.window_fill = SURFACE_ALT;
            visuals.extreme_bg_color = Color32::from_rgb(0x1A, 0x15, 0x2A);
            visuals.faint_bg_color = SURFACE_ALT;
            visuals.override_text_color = None;
            visuals.hyperlink_color = VIOLET_LIGHT;
            visuals.warn_fg_color = ORCHID;
            visuals.error_fg_color = Color32::from_rgb(0xFF, 0x7A, 0x9C);
        } else {
            visuals.panel_fill = Color32::from_rgb(0xFA, 0xF7, 0xFF);
            visuals.window_fill = Color32::WHITE;
            visuals.extreme_bg_color = Color32::WHITE;
            visuals.faint_bg_color = Color32::from_rgb(0xF1, 0xEC, 0xFB);
            visuals.override_text_color = None;
            visuals.hyperlink_color = VIOLET_DEEP;
            visuals.warn_fg_color = Color32::from_rgb(0xB0, 0x4A, 0x00);
            visuals.error_fg_color = Color32::from_rgb(0xC0, 0x1B, 0x4B);
        }

        // Selection is the single most visible state in a file grid, so it
        // carries the brand colour instead of the default grey wash.
        visuals.selection.bg_fill = VIOLET.gamma_multiply(if dark { 0.38 } else { 0.22 });
        visuals.selection.stroke = Stroke::new(1.0, VIOLET_LIGHT);

        visuals.widgets.noninteractive.bg_fill = SURFACE_ALT;
        visuals.widgets.noninteractive.weak_bg_fill = SURFACE_ALT;
        visuals.widgets.noninteractive.bg_stroke = Stroke::new(
            1.0,
            VIOLET_DEEP.gamma_multiply(if dark { 0.35 } else { 0.20 }),
        );
        visuals.widgets.noninteractive.fg_stroke =
            Stroke::new(1.0, if dark { VIOLET_MUTED } else { VIOLET_DEEP });
        visuals.widgets.noninteractive.corner_radius = 4.0.into();

        // Buttons carry the violet fill so every action reads as part of
        // the same product.
        visuals.widgets.inactive.bg_fill =
            VIOLET_DEEP.gamma_multiply(if dark { 0.55 } else { 0.30 });
        visuals.widgets.inactive.weak_bg_fill = SURFACE_ALT;
        visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, VIOLET.gamma_multiply(0.8));
        visuals.widgets.inactive.fg_stroke =
            Stroke::new(1.0, if dark { Color32::WHITE } else { VIOLET_DEEP });
        visuals.widgets.inactive.corner_radius = 5.0.into();

        visuals.widgets.hovered.bg_fill =
            VIOLET_DEEP.gamma_multiply(if dark { 0.85 } else { 0.45 });
        visuals.widgets.hovered.weak_bg_fill = SURFACE_ALT;
        visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, VIOLET_LIGHT);
        visuals.widgets.hovered.fg_stroke =
            Stroke::new(1.0, if dark { Color32::WHITE } else { VIOLET_DEEP });
        visuals.widgets.hovered.corner_radius = 5.0.into();

        visuals.widgets.active.bg_fill = VIOLET;
        visuals.widgets.active.weak_bg_fill = VIOLET.gamma_multiply(0.5);
        visuals.widgets.active.bg_stroke = Stroke::new(1.0, VIOLET_LIGHT);
        visuals.widgets.active.fg_stroke = Stroke::new(1.0, Color32::WHITE);
        visuals.widgets.active.corner_radius = 5.0.into();

        visuals.widgets.open.bg_fill = VIOLET.gamma_multiply(0.7);
        visuals.widgets.open.weak_bg_fill = SURFACE_ALT;
        visuals.widgets.open.bg_stroke = Stroke::new(1.0, VIOLET);
        visuals.widgets.open.fg_stroke =
            Stroke::new(1.0, if dark { Color32::WHITE } else { VIOLET_DEEP });
        visuals.widgets.open.corner_radius = 5.0.into();

        // Checkboxes/radio (used by the guided forms) get the same accent.
        visuals.widgets.inactive.bg_stroke = Stroke::new(1.5, VIOLET);
        visuals.widgets.hovered.bg_stroke = Stroke::new(1.5, VIOLET_LIGHT);
        visuals.widgets.active.bg_fill = VIOLET;

        visuals.window_stroke = Stroke::new(1.0, VIOLET.gamma_multiply(0.5));
        visuals.window_corner_radius = 8.0.into();
        visuals.popup_shadow.color = Color32::from_black_alpha(if dark { 110 } else { 40 });
    }
}

/// A bold section header in the brand colour.
pub fn heading(text: impl Into<String>) -> egui::RichText {
    egui::RichText::new(text).strong().color(VIOLET_LIGHT)
}

/// Secondary/quiet text, violet-tinted rather than plain grey.
pub fn muted(text: impl Into<String>) -> egui::RichText {
    egui::RichText::new(text).small().color(VIOLET_MUTED)
}

/// A filled badge (band balance, item counts).
pub fn badge(text: impl Into<String>) -> egui::RichText {
    egui::RichText::new(text).strong().color(ORCHID)
}

/// The violet "you are here" colour for the selected row label.
pub fn selected_text(text: impl Into<String>) -> egui::RichText {
    egui::RichText::new(text).strong().color(VIOLET_LIGHT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_palette_is_applied_to_both_schemes() {
        let ctx = egui::Context::default();
        apply(&ctx);
        let dark = ctx.style_of(egui::Theme::Dark);
        let light = ctx.style_of(egui::Theme::Light);
        assert_eq!(
            dark.visuals.selection.bg_fill,
            VIOLET.gamma_multiply(0.38),
            "dark selection must be the brand violet"
        );
        assert_eq!(
            light.visuals.selection.bg_fill,
            VIOLET.gamma_multiply(0.22),
            "light selection must be the brand violet too"
        );
        assert_ne!(
            dark.visuals.widgets.inactive.bg_fill,
            Color32::from_gray(60),
            "buttons must be tinted, not the default grey"
        );
    }
}
