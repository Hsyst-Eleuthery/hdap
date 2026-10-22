#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

struct GuiApp(hdap_gui::app::App);

impl eframe::App for GuiApp {
    fn ui(&mut self, ui: &mut eframe::egui::Ui, _frame: &mut eframe::Frame) {
        hdap_gui::view::render(ui, &mut self.0);
    }
}

fn main() -> eframe::Result {
    // Without a hook, a panic in a worker thread can leave the UI waiting on a
    // result that never arrives, with nothing in the log to explain it.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        eprintln!("hdap-gui: PANIC: {info}");
        default_hook(info);
    }));
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([960.0, 640.0])
            .with_title("HDAP — Hsyst Descentralized Archive Protocol"),
        ..Default::default()
    };
    eframe::run_native(
        "hdap-gui",
        options,
        Box::new(|cc| {
            // Compact defaults so the explorer fits comfortably without
            // needing fullscreen (smaller paddings / item spacing).
            hdap_gui::theme::apply(&cc.egui_ctx);
            Ok(Box::new(GuiApp(hdap_gui::app::App::default())))
        }),
    )
}
