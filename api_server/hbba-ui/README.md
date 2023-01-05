## 编译步骤

1. 安装`wasm-pack`
2. 设置环境变量`RUSTFLAGS`的值为`--cfg=web_sys_unstable_apis`。（启用复制黏贴功能）
3. 执行`wasm-pack build -t web --no-typescript`


### nushell
```nu
with-env { RUSTFLAGS: --cfg=web_sys_unstable_apis } { wasm-pack build -t web --no-typescript }
```

### bash
```bash
RUSTFLAGS="--cfg=web_sys_unstable_apis" wasm-pack build -t web --no-typescript
```

