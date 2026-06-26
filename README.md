# totp-auth

给 Nginx `auth_request` 使用的本地轻量 TOTP 验证服务。

## 构建

```sh
go build -trimpath -ldflags="-s -w" -o totp-auth .
```

## 生成 TOTP Secret

```sh
./totp-auth create token --issuer example.com --account admin
```

输出里的 `TOTP_SECRET` 用作服务环境变量，`otpauth_url` 可导入 Google Authenticator、1Password、Bitwarden 等验证器。

## 启动

只使用 TOTP：

```sh
export TOTP_SECRET='BASE32TOTPSECRET'
export COOKIE_SECRET='change-me-to-a-long-random-string'

./totp-auth \
  --only-totp \
  --listen 127.0.0.1:9092 \
  --cookie-domain .example.com \
  --default-redirect https://auth.example.com:<your-port>/
```

用户名、密码和 TOTP：

```sh
export AUTH_USERNAME='admin'
export AUTH_PASSWORD_HASH='pbkdf2:sha256:1000000$...$...'
export TOTP_SECRET='BASE32TOTPSECRET'
export COOKIE_SECRET='change-me-to-a-long-random-string'

./totp-auth \
  --listen 127.0.0.1:9092 \
  --cookie-domain .example.com \
  --default-redirect https://auth.example.com:<your-port>/
```

生成密码哈希：

```sh
./totp-auth hash-password 'your-password'
```

常用参数：

- `--only-totp`：只校验 TOTP，不需要用户名和密码。
- `--listen`：监听地址，默认 `127.0.0.1:9092`。
- `--cookie-domain`：Cookie 域名，例如 `.example.com`。
- `--cookie-max-age`：Cookie 有效期，默认 `168h`。
- `--default-redirect`：缺少 `rd` 参数时的默认跳转地址。
- `--allowed-redirect-hosts`：额外允许的跳转 Host，多个值用逗号分隔。
- `--login-rate-limit`：登录失败次数限制，默认 `5`。
- `--login-rate-window`：登录失败限制窗口，默认 `5m`。

## Linux systemd

Linux 发布包里包含 `totp-auth.service` 和 `totp-auth.env.example`。示例安装方式：

```sh
sudo install -m 0755 totp-auth /usr/local/bin/totp-auth
sudo useradd --system --home /nonexistent --shell /usr/sbin/nologin totp-auth
sudo install -d -m 0750 -o root -g totp-auth /etc/totp-auth
sudo install -m 0640 -o root -g totp-auth totp-auth.env.example /etc/totp-auth/totp-auth.env
sudo install -m 0644 totp-auth.service /etc/systemd/system/totp-auth.service
sudo systemctl daemon-reload
sudo systemctl enable --now totp-auth
```

启动前先编辑 `/etc/totp-auth/totp-auth.env`，填入 `TOTP_SECRET`、`COOKIE_SECRET`，以及需要用户名密码模式时的 `AUTH_USERNAME` 和 `AUTH_PASSWORD_HASH`。

## Nginx 配置

认证服务域名，例如 `auth.example.com`，可以使用一个最简但足够安全的 `auth.conf`：

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name auth.example.com;

    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name auth.example.com;

    ssl_certificate /etc/letsencrypt/live/example.site/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.site/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;

    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header Content-Security-Policy "upgrade-insecure-requests" always;

    location / {
        proxy_pass http://127.0.0.1:9092;
        proxy_http_version 1.1;

        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Host $http_host;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

要保护的服务里添加内部认证入口：

```nginx
location = /_auth {
    internal;
    proxy_pass http://127.0.0.1:9092/verify;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";

    proxy_set_header X-Original-URL https://$host:<your-port>$request_uri;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-Host $host:<your-port>;
    proxy_set_header X-Real-IP $remote_addr;
}
```

对应服务的反代配置：

```nginx
location / {
    auth_request /_auth;
    auth_request_set $auth_redirect $upstream_http_location;
    error_page 401 =302 https://auth.example.com:<your-port>$auth_redirect;

    proxy_pass http://your_upstream;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
}
```
