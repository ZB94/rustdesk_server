use reqwasm::http::Method;

pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    //
    // For more details see
    // https://github.com/rustwasm/console_error_panic_hook#readme
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

pub fn request<T, F, R>(
    method: Method,
    url: &'static str,
    data: Option<T>,
    token: Option<String>,
    on_done: F,
) where
    T: serde::Serialize + 'static,
    R: serde::de::DeserializeOwned,
    F: Fn(Result<(u16, R), reqwasm::Error>) + Send + 'static,
{
    wasm_bindgen_futures::spawn_local(async move {
        let mut req = reqwasm::http::Request::new(url).method(method);
        if let Some(data) = data {
            let data = match serde_json::to_string(&data) {
                Ok(data) => data,
                Err(e) => return on_done(Err(e.into())),
            };
            req = req
                .header("content-type", "application/json; charset=utf8")
                .body(data);
        }

        if let Some(token) = token {
            req = req.header("Authorization", &format!("bearer {}", token));
        }

        let r = match req.send().await {
            Ok(resp) => {
                let code = resp.status();
                resp.json().await.map(|r| (code, r))
            }
            Err(e) => Err(e),
        };

        on_done(r)
    })
}
