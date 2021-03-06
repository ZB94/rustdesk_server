use crossbeam_channel::{unbounded, Receiver, Sender};
use eframe::egui::{
    Align2, Color32, Grid, Label, Layout, RichText, ScrollArea, Sense, TextEdit, Window,
};
use eframe::emath::Align;
use instant::{Duration, Instant};
use reqwasm::http::Method;
use serde::Serialize;
use std::fmt::Display;

use crate::Ui;

pub struct User {
    username: String,
    password: String,
    pwd_current: String,
    pwd_new1: String,
    pwd_new2: String,
    perm: Permission,
    remembered: bool,
    access_token: Option<String>,
    create_user: (String, String, Permission, bool),
    users: Vec<UserInfo>,
    refer_user: Option<Instant>,
    chanel: (Sender<(u16, Response)>, Receiver<(u16, Response)>),
    message: Vec<(Color32, String)>,
    server_address: (Instant, Option<ServerAddress>),
}

impl User {
    pub fn new() -> Self {
        Self {
            username: "".to_string(),
            password: "".to_string(),
            pwd_current: "".to_string(),
            pwd_new1: "".to_string(),
            pwd_new2: "".to_string(),
            perm: Permission::User,
            remembered: true,
            access_token: None,
            create_user: ("".to_string(), "".to_string(), Permission::User, false),
            users: vec![],
            refer_user: None,
            chanel: unbounded(),
            message: Vec::with_capacity(5),
            server_address: (Instant::now(), None),
        }
    }

    fn logout(&mut self) {
        self.pwd_current.clear();
        self.pwd_new1.clear();
        self.pwd_new2.clear();
        self.create_user = Default::default();
        self.users.clear();
        self.refer_user = None;
        self.server_address = (Instant::now(), None);
        self.access_token = None;
    }

    #[inline]
    pub fn is_login(&self) -> bool {
        self.access_token.is_some()
    }

    pub fn ui(&mut self, ui: &mut Ui) {
        if self.is_login() {
            self.ui_user(ui);
        } else {
            self.ui_login(ui);
        }
        self.ui_message(ui);
    }

    fn ui_user(&mut self, ui: &mut Ui) {
        self.show_user_info(ui);
        self.show_server_address(ui);
        if self.perm == Permission::Admin {
            self.show_user_manage(ui);
        }
    }

    fn show_server_address(&mut self, ui: &mut Ui) {
        Window::new("??????????????????")
            .resizable(false)
            .show(ui.ctx(), |ui| {
                Grid::new("server address")
                    .spacing([4.0, 8.0])
                    .max_col_width(400.0)
                    .show(ui, |ui| {
                        if let Some(server) = &mut self.server_address.1 {
                            let admin = self.perm == Permission::Admin;
                            for (label, value) in [
                                ("ID????????????", &mut server.id_server),
                                ("??????????????????", &mut server.relay_server),
                                ("API????????????", &mut server.api_server),
                                ("KEY???", &mut server.pubkey),
                            ] {
                                ui.label(label);
                                if ui.button("??????").clicked() {
                                    ui.ctx().output().copied_text = value.clone();
                                }
                                if admin {
                                    ui.add(TextEdit::singleline(value).desired_width(400.0));
                                } else {
                                    ui.add(
                                        TextEdit::singleline(&mut value.as_str())
                                            .desired_width(400.0),
                                    );
                                }
                                ui.end_row();
                            }

                            ui.label("API?????????????????????");
                            ui.label("");
                            ui.hyperlink_to("????????????", "/api_server.crt")
                                .on_hover_ui(|ui| {
                                    ui.label("??????Windows??????????????????????????????????????????????????????????????????????????????'?????????????????????????????????'");
                                    ui.label("??????Linux??????????????????????????????'/etc/ssl/certs'??????????????????Ubuntu???????????????");
                                });
                            ui.end_row();

                            if admin {
                                ui.label("");
                                ui.label("");
                                let change = ui
                                    .with_layout(Layout::right_to_left(), |ui| {
                                        ui.button("??????").clicked()
                                    })
                                    .inner;
                                if change {
                                    let sa = server.clone();
                                    self.req(Operation::ChangeServerAddress, Some(sa), false)
                                }
                                ui.end_row();
                            }
                        } else {
                            ui.spinner();
                            if self.is_login()
                                && self.server_address.0.elapsed() >= Duration::from_secs(1)
                            {
                                self.req(Operation::GetServerAddress, Option::<()>::None, true);
                                self.server_address.0 = Instant::now();
                            }
                            ui.end_row();
                        }
                    });
            });
    }

    fn show_user_info(&mut self, ui: &mut Ui) {
        Window::new("????????????")
            .resizable(false)
            .show(ui.ctx(), |ui| {
                Grid::new("user info").spacing([4.0, 8.0]).show(ui, |ui| {
                    ui.label("?????????");
                    ui.label(&self.username);
                    ui.end_row();

                    ui.label("??????");
                    ui.label(self.perm.name());
                    ui.end_row();

                    ui.label("????????????");
                    ui.add(
                        TextEdit::singleline(&mut self.pwd_current)
                            .password(true)
                            .hint_text("?????????????????????"),
                    );
                    ui.end_row();

                    ui.label("????????????");
                    ui.add(
                        TextEdit::singleline(&mut self.pwd_new1)
                            .password(true)
                            .hint_text("??????????????????"),
                    );
                    ui.end_row();

                    ui.label("????????????");
                    ui.add(
                        TextEdit::singleline(&mut self.pwd_new2)
                            .password(true)
                            .hint_text("?????????????????????"),
                    );
                    ui.end_row();

                    ui.label("");
                    ui.with_layout(Layout::right_to_left(), |ui| {
                        if ui
                            .button(RichText::new("??????").color(Color32::RED))
                            .clicked()
                        {
                            self.logout();
                        }
                        if ui.button("????????????").clicked() {
                            if self.pwd_current.is_empty()
                                || self.pwd_new1.is_empty()
                                || self.pwd_new2.is_empty()
                            {
                                self.add_error(
                                    Operation::ChangePassword,
                                    "?????????????????????????????????????????????????????????",
                                );
                                return;
                            }

                            if self.pwd_new1 != self.pwd_new2 {
                                self.add_error(
                                    Operation::ChangePassword,
                                    "????????????????????????????????????",
                                );
                                return;
                            }

                            self.req(
                                Operation::ChangePassword,
                                Some(json!({
                                    "old_password": self.pwd_current.clone(),
                                    "new_password": self.pwd_new1.clone()
                                })),
                                false,
                            );
                            self.pwd_current.clear();
                            self.pwd_new1.clear();
                            self.pwd_new2.clear();
                        }
                    });
                    ui.end_row();
                });
            });
    }

    fn show_user_manage(&mut self, ui: &mut Ui) {
        if self
            .refer_user
            .map(|i| i.elapsed() >= Duration::from_millis(300))
            .unwrap_or_default()
        {
            self.refer_user = None;
            self.get_user_info(false, true);
        }

        Window::new("????????????")
            .resizable(false)
            .show(ui.ctx(), |ui| {
                ui.group(|ui| {
                    if ui.button("????????????").clicked() {
                        self.get_user_info(false, false);
                    }
                    ScrollArea::new([false, true])
                        .max_height(300.0)
                        .show(ui, |ui| {
                            Grid::new("user manage list")
                                .spacing([4.0, 4.0])
                                .striped(true)
                                .show(ui, |ui| {
                                    ui.label("?????????");
                                    ui.label("??????");
                                    ui.label("??????");
                                    ui.label("??????");
                                    ui.end_row();

                                    let mut remove_list = vec![];
                                    let mut update_list = vec![];
                                    for user in &mut self.users {
                                        let UserInfo {
                                            username,
                                            perm,
                                            disabled,
                                        } = user;

                                        ui.label(username.as_str());
                                        ui.label(perm.name());
                                        if ui.checkbox(disabled, "").clicked() {
                                            update_list.push(json!({
                                                "username": username.clone(),
                                                "perm": *perm,
                                                "disabled": *disabled
                                            }));
                                        }

                                        if ui.button("??????").clicked() {
                                            remove_list.push(json!({
                                                "username": username.clone(),
                                                "perm": perm
                                            }));
                                        }
                                        ui.end_row();
                                    }

                                    for data in remove_list {
                                        self.req(Operation::DeleteUser, Some(data), false);
                                        self.get_user_info(true, true);
                                    }

                                    for data in update_list {
                                        self.req(Operation::SetDisabled, Some(data), false);
                                    }
                                });
                        });
                });
                ui.add_space(8.0);

                ui.group(|ui| {
                    Grid::new("user manage create").show(ui, |ui| {
                        let (username, password, perm, disabled) = &mut self.create_user;

                        ui.label("?????????");
                        ui.text_edit_singleline(username);
                        ui.end_row();

                        ui.label("??????");
                        ui.text_edit_singleline(password);
                        ui.end_row();

                        ui.label("??????");
                        ui.horizontal(|ui| {
                            ui.selectable_value(perm, Permission::User, Permission::User.name());
                            ui.selectable_value(perm, Permission::Admin, Permission::Admin.name());
                        });
                        ui.end_row();

                        ui.label("??????");
                        ui.checkbox(disabled, "");
                        ui.end_row();

                        ui.label("");
                        ui.with_layout(Layout::right_to_left(), |ui| {
                            if ui.button("??????").clicked() {
                                if self.create_user.0.is_empty() || self.create_user.1.is_empty() {
                                    self.add_error(Operation::CreateUser, "??????????????????????????????");
                                    return;
                                }
                                self.req(
                                    Operation::CreateUser,
                                    Some(json!({
                                        "username": self.create_user.0.clone(),
                                        "password": self.create_user.1.clone(),
                                        "perm": self.create_user.2,
                                        "disabled": self.create_user.3
                                    })),
                                    false,
                                );
                                self.get_user_info(true, true);
                            }
                        });
                        ui.end_row();
                    });
                });
            });
    }

    /// ????????????????????????
    ///
    /// `wait`???`true`?????????????????????????????????
    #[inline]
    fn get_user_info(&mut self, wait: bool, ignore_ok: bool) {
        if wait {
            self.refer_user = Some(Instant::now());
        } else {
            self.req::<()>(Operation::GetUserList, None, ignore_ok);
        }
    }

    fn ui_login(&mut self, ui: &mut Ui) {
        Window::new("??????")
            .anchor(Align2::CENTER_TOP, [0.0, 200.0])
            .collapsible(false)
            .resizable(false)
            .show(ui.ctx(), |ui| {
                Grid::new("login").spacing([4.0, 8.0]).show(ui, |ui| {
                    ui.label("?????????");
                    ui.text_edit_singleline(&mut self.username);
                    ui.end_row();

                    ui.label("??????");
                    ui.add(TextEdit::singleline(&mut self.password).password(true));
                    ui.end_row();

                    ui.label("????????????");
                    ui.horizontal(|ui| {
                        ui.selectable_value(
                            &mut self.perm,
                            Permission::User,
                            Permission::User.name(),
                        );
                        ui.selectable_value(
                            &mut self.perm,
                            Permission::Admin,
                            Permission::Admin.name(),
                        );
                    });
                    ui.end_row();

                    ui.checkbox(&mut self.remembered, "????????????")
                        .on_hover_text("?????????????????????????????????????????????????????????");
                    ui.with_layout(Layout::right_to_left(), |ui| {
                        if ui.button("??????").clicked() {
                            if self.username.is_empty() || self.password.is_empty() {
                                self.add_error(Operation::Login, "??????????????????????????????");
                                return;
                            }

                            let user = json!({
                                "username": self.username.clone(),
                                "password": self.password.clone(),
                                "perm": self.perm
                            });

                            self.req(Operation::Login, Some(user), false);
                        }
                    });
                    ui.end_row();
                })
            });
    }

    fn ui_message(&mut self, ui: &mut Ui) {
        while let Ok((code, resp)) = self.chanel.1.try_recv() {
            if code == 401 {
                self.access_token = None;
                self.add_error(resp.op, "??????????????????????????????????????????????????????");
                while let Ok(_) = self.chanel.1.try_recv() {}
                return;
            }

            if let Some(err) = resp.error {
                self.add_error(resp.op, err);
                continue;
            }

            match (resp.ignore_ok, resp.data) {
                (_, Some(ResponseBody::Login { access_token })) => {
                    if !self.remembered {
                        self.password.clear();
                    }
                    self.access_token = Some(access_token);
                    if self.perm == Permission::Admin {
                        self.get_user_info(true, true);
                    }
                }
                (ignore, Some(ResponseBody::Users { users })) => {
                    self.users = users;
                    if !ignore {
                        self.add_info(Operation::GetUserList, "????????????");
                    }
                }
                (ignore, Some(ResponseBody::ServerAddress(server))) => {
                    self.server_address.1 = Some(server);
                    if !ignore {
                        self.add_info(Operation::GetServerAddress, "????????????");
                    }
                }
                (false, Some(ResponseBody::Empty {})) => {
                    self.add_info(resp.op, "????????????");
                }
                _ => {}
            }
        }

        ui.with_layout(Layout::bottom_up(Align::Center), |ui| {
            let remove = self
                .message
                .iter()
                .enumerate()
                .rev()
                .filter_map(|(idx, (color, msg))| {
                    let text = RichText::new(msg).color(*color);
                    let label = Label::new(text).sense(Sense::click());
                    ui.add(label).clicked().then(|| idx)
                })
                .collect::<Vec<_>>();
            for idx in remove {
                self.message.remove(idx);
            }
        });
    }

    fn req<T>(&self, op: Operation, data: Option<T>, ignore_ok: bool)
    where
        T: Serialize + 'static,
    {
        let sender = self.chanel.0.clone();
        let (method, url) = op.request_info();
        crate::utils::request(
            method,
            url,
            data,
            self.access_token.clone(),
            move |resp: Result<(_, Response), _>| match resp {
                Ok(mut d) => {
                    d.1.op = op;
                    d.1.ignore_ok = ignore_ok;
                    let _ = sender.send(d);
                }
                Err(e) => {
                    let _ = sender.send((0, Response::error(op, format!("????????????: {}", e))));
                }
            },
        )
    }

    #[inline]
    fn add_error<S: Display>(&mut self, op: Operation, error: S) {
        self.add_message(op, error, Color32::RED);
    }

    #[inline]
    fn add_info<S: Display>(&mut self, op: Operation, info: S) {
        self.add_message(op, info, Color32::GREEN);
    }

    fn add_message<S: Display, C: Into<Color32>>(&mut self, op: Operation, message: S, color: C) {
        if self.message.len() == self.message.capacity() {
            self.message.remove(0);
        }
        self.message
            .push((color.into(), format!("{}: {}", op.tag(), message)));
    }
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Hash, Copy, Clone)]
pub enum Permission {
    User,
    Admin,
}

impl Permission {
    pub fn name(&self) -> &'static str {
        match self {
            Self::User => "????????????",
            Self::Admin => "?????????",
        }
    }
}

impl Default for Permission {
    fn default() -> Self {
        Self::User
    }
}

#[derive(Debug, Deserialize)]
pub struct Response {
    #[serde(skip, default)]
    op: Operation,
    #[serde(skip, default)]
    ignore_ok: bool,
    pub error: Option<String>,
    #[serde(flatten)]
    pub data: Option<ResponseBody>,
}

impl Response {
    pub fn error<S: ToString>(op: Operation, error: S) -> Self {
        Self {
            op,
            ignore_ok: false,
            error: Some(error.to_string()),
            data: None,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum ResponseBody {
    Login { access_token: String },
    Users { users: Vec<UserInfo> },
    ServerAddress(ServerAddress),
    Empty {},
}

#[derive(Debug, Deserialize)]
pub struct UserInfo {
    pub username: String,
    pub perm: Permission,
    pub disabled: bool,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum Operation {
    Default,
    Login,
    ChangePassword,
    GetUserList,
    CreateUser,
    DeleteUser,
    SetDisabled,
    GetServerAddress,
    ChangeServerAddress,
}

impl Operation {
    pub fn tag(&self) -> &'static str {
        match self {
            Operation::Default => "??????",
            Operation::Login => "??????",
            Operation::ChangePassword => "????????????",
            Operation::GetUserList => "??????????????????",
            Operation::CreateUser => "????????????",
            Operation::DeleteUser => "????????????",
            Operation::SetDisabled => "????????????????????????",
            Operation::GetServerAddress => "?????????????????????",
            Operation::ChangeServerAddress => "?????????????????????",
        }
    }

    fn request_info(&self) -> (Method, &'static str) {
        match self {
            Operation::Default => {
                panic!("????????????")
            }
            Operation::Login => (Method::POST, "/manage/login"),
            Operation::ChangePassword => (Method::POST, "/manage/change_password"),
            Operation::GetUserList => (Method::GET, "/manage/user"),
            Operation::CreateUser => (Method::POST, "/manage/user"),
            Operation::DeleteUser => (Method::DELETE, "/manage/user"),
            Operation::SetDisabled => (Method::PUT, "/manage/user"),
            Operation::GetServerAddress => (Method::GET, "/manage/server_address"),
            Operation::ChangeServerAddress => (Method::PUT, "/manage/server_address"),
        }
    }
}

impl Default for Operation {
    fn default() -> Self {
        Self::Default
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServerAddress {
    pub id_server: String,
    pub relay_server: String,
    pub api_server: String,
    pub pubkey: String,
}
