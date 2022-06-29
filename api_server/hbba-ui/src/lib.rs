#[macro_use]
extern crate serde;
#[macro_use]
extern crate serde_json;
#[cfg(feature = "log")]
#[macro_use]
extern crate tracing;

use std::sync::RwLock;

use eframe::egui::{CentralPanel, Context, FontData, FontDefinitions, ScrollArea, Ui};
use eframe::{App, CreationContext, Frame};
use once_cell::sync::Lazy;
use wasm_bindgen::prelude::*;

use crate::help::Help;
use crate::user::User;

pub(crate) mod help;
mod utils;

pub(crate) mod user;

#[wasm_bindgen]
pub fn start() {
    utils::set_panic_hook();

    #[cfg(feature = "log")]
    tracing_wasm::set_as_global_default();

    eframe::start_web(
        "view",
        Box::new(|ctx: &CreationContext| Box::new(Application::new(ctx))),
    )
    .unwrap();
}

pub struct Application {
    load_font: bool,
    user: User,
}

impl App for Application {
    fn update(&mut self, ctx: &Context, _frame: &mut Frame) {
        if !self.load_font(ctx) {
            return;
        }

        CentralPanel::default().show(ctx, |ui| {
            ScrollArea::both()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.add(Help);
                    self.user.ui(ui);
                });
        });

        ctx.request_repaint();
    }
}

impl Application {
    pub fn new(_ctx: &CreationContext) -> Self {
        Self {
            load_font: false,
            user: User::new(),
        }
    }

    fn load_font(&mut self, ctx: &Context) -> bool {
        if !self.load_font {
            if let Some(font_data) = FONT_DATA.read().ok().and_then(|f| f.clone()) {
                const FONT_NAME: &str = "思源宋体";
                let mut font_def = FontDefinitions::default();
                font_def.font_data.insert(FONT_NAME.to_string(), font_data);
                for l in font_def.families.values_mut() {
                    l.insert(0, FONT_NAME.to_string());
                }
                ctx.set_fonts(font_def);
                self.load_font = true;
            } else {
                CentralPanel::default().show(ctx, |ui| {
                    ui.centered_and_justified(Ui::spinner);
                });
                ctx.request_repaint();
            }
        }
        self.load_font
    }
}

static FONT_DATA: Lazy<RwLock<Option<FontData>>> = Lazy::new(|| {
    use reqwasm::http::Request;
    fn fetch_font() {
        wasm_bindgen_futures::spawn_local(async {
            let resp = Request::get("res/SourceHanSerifCN-Medium.otf")
                .send()
                .await
                .ok()
                .and_then(|resp| {
                    if resp.status() == 200 {
                        Some(resp)
                    } else {
                        None
                    }
                });
            if let Some(resp) = resp {
                if let Ok(data) = resp.binary().await {
                    let mut font = FontData::from_owned(data);
                    if let Ok(mut fd) = FONT_DATA.write() {
                        font.tweak.scale = 1.4;
                        *fd = Some(font);
                        return;
                    }
                }
            }
            fetch_font();
        })
    }

    fetch_font();
    RwLock::default()
});
