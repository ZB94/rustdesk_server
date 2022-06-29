use eframe::egui::{Response, Widget};
use once_cell::sync::Lazy;
use std::sync::RwLock;

use crate::Ui;
use reqwasm::http::Method;

static DOWNLOAD_LIST: Lazy<RwLock<Vec<Link>>> = Lazy::new(|| {
    #[derive(Debug, Deserialize)]
    struct DownloadList {
        pub links: Vec<Link>,
    }

    crate::utils::request::<(), _, _>(
        Method::GET,
        "/download_list",
        None,
        None,
        |r: Result<(_, DownloadList), _>| {
            if let Ok((_, dl)) = r {
                *DOWNLOAD_LIST.write().unwrap() = dl.links;
            }
        },
    );

    Default::default()
});

pub struct Help;

impl Widget for Help {
    fn ui(self, ui: &mut Ui) -> Response {
        ui.vertical(|ui| {
            ui.heading("客户端使用说明");
            ui.collapsing("1. 下载客户端", |ui| {
                ui.horizontal(|ui| {
                    ui.label("客户端官方地址：");
                    ui.hyperlink("https://rustdesk.com/");
                });

                ui.horizontal(|ui| {
                    ui.label("客户端官方下载地址：");
                    ui.hyperlink("https://github.com/rustdesk/rustdesk/releases");
                });

                ui.label("直接下载：");
                ui.group(|ui| {
                    let dl = DOWNLOAD_LIST.read().unwrap();

                    if dl.is_empty() {
                        ui.label("当前服务器未配置直接下载地址，请在官网下载地址下载客户端");
                    } else {
                        for link in dl.iter() {
                            ui.hyperlink_to(&link.name, &link.url);
                        }
                    }
                });
            });
            ui.collapsing("2. 设置客户端ID/中继服务器", |ui| {
                ui.hyperlink_to("详细图文设置可点击本链接查看", "https://rustdesk.com/docs/zh-cn/self-host/install/#%E6%AD%A5%E9%AA%A43-%E5%9C%A8%E5%AE%A2%E6%88%B7%E7%AB%AF%E8%AE%BE%E7%BD%AE-hbbshbbr-%E5%9C%B0%E5%9D%80");
                ui.label("1. 打开客户端界面，打开设置菜单（菜单按钮位于左边的'你的桌面'面板中'ID'的右方，为垂直排列的三个实心圆点");
                ui.label("2. 点击'ID/中继服务器'");
                ui.label("3. 在弹出窗口中填写本服务的ID服务器、中继服务器、API服务器和KEY");
                ui.label("4. 点击确认按钮完成设置");

                ui.label("");
                ui.label("当前服务配置请登录后查看");
            });
            ui.collapsing("3. 登录并同步地址簿（可选）", |ui| {
                ui.label("如果正确设置了客户端的API服务器地址，可以在客户端中登入账号，在不同客户端间同步地址簿");
                ui.label("注意：账号只能由管理员手动添加，无法任意注册。如已有账号可在本页面登录并修改密码");

                ui.label("");
                ui.label("登录流程：");
                ui.label("1. 点击客户端界面右方的'地址簿'标签");
                ui.label("2. 点击登录按钮（如未显示该按钮为已有其他用户登入，可以在设置菜单中登出");
                ui.label("3. 输入用户名和密码，并点击确认按钮进行登录");

                ui.label("");
                ui.label("地址簿使用方法：");
                ui.label("地址簿可以添加标签和ID，并为ID设置不同标签，点击标签可快速查找包含该标签ID");

                ui.group(|ui| {
                    ui.label("添加ID：");
                    ui.label("1. 打开标签右方的菜单");
                    ui.label("2. 点击'添加ID'");
                    ui.label("3. 根据弹出窗口说明填入ID");
                    ui.label("4. 点击确认按钮完成添加ID")
                });

                ui.group(|ui| {
                    ui.label("添加标签：");
                    ui.label("1. 打开标签右方的菜单");
                    ui.label("2. 点击'添加标签'");
                    ui.label("3. 根据弹出窗口说明填入标签");
                    ui.label("4. 点击确认按钮完成添加标签");
                });

                ui.group(|ui| {
                    ui.label("设置ID标签：");
                    ui.label("打开要设置标签的ID的设置菜单");
                    ui.label("点击'修改标签'");
                    ui.label("在弹出窗口中选中要为ID设置的标签");
                    ui.label("点击确认按钮完成设置ID标签");
                });
            });
        })
        .response
    }
}

#[derive(Debug, Deserialize)]
pub struct Link {
    pub name: String,
    pub url: String,
}
