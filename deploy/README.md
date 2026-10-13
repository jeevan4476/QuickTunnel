# QuickTunnel Production Deployment Guide

This directory contains production deployment configurations for running QuickTunnel in self-hosted environments.

---

## Deployment Options

### 1. Docker & Docker Compose
For containerized deployments on a VPS or cloud instance:

```bash
cd deploy
docker compose up -d
```

Configure your domain and secret via `.env`:
```bash
QT_DOMAIN=tunnel.example.com
QT_SECRET=$(quicktunnel genkey)
```

---

### 2. Linux systemd Service
For bare-metal or VM deployments with security hardening (`NoNewPrivileges`, `ProtectSystem`, `CAP_NET_BIND_SERVICE`):

1. **Copy binary**:
   ```bash
   sudo cp target/release/quicktunnel /usr/local/bin/
   sudo chmod +x /usr/local/bin/quicktunnel
   ```

2. **Create quicktunnel system user**:
   ```bash
   sudo useradd -r -s /bin/false quicktunnel
   ```

3. **Install environment file**:
   ```bash
   sudo mkdir -p /etc/quicktunnel
   echo 'QT_DOMAIN=tunnel.example.com' | sudo tee /etc/quicktunnel/server.env
   echo "QT_SECRET=$(quicktunnel genkey)" | sudo tee -a /etc/quicktunnel/server.env
   sudo chmod 600 /etc/quicktunnel/server.env
   ```

4. **Install and start systemd unit**:
   ```bash
   sudo cp deploy/quicktunnel-server.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now quicktunnel-server
   ```

5. **Verify logs**:
   ```bash
   journalctl -u quicktunnel-server -f
   ```

---

### 3. TLS Termination with Caddy (Recommended for Auto-HTTPS)
Caddy automatically provisions wildcard Let's Encrypt certificates using the DNS-01 challenge:

1. Install Caddy with the Cloudflare DNS plugin (or your DNS provider).
2. Copy `deploy/caddy/Caddyfile` to `/etc/caddy/Caddyfile`.
3. Set `CLOUDFLARE_API_TOKEN` in Caddy's environment.
4. Run `quicktunnel server` on `--http-bind 127.0.0.1:8080`.
5. Start Caddy (`sudo systemctl restart caddy`).

---

### 4. TLS Termination with Nginx
If using an existing Nginx server:

1. Obtain a wildcard certificate using `certbot certonly --manual --preferred-challenges dns -d *.tunnel.example.com -d tunnel.example.com`.
2. Copy `deploy/nginx/nginx.conf` and update your SSL certificate paths.
3. Reload Nginx (`sudo nginx -s reload`).

---

## Firewall Configuration

Ensure your server allows traffic on the required ports:

- **TCP 7000**: QuickTunnel control listener (clients connect here).
- **TCP 80 / 443**: Public visitor HTTP / HTTPS traffic.
- **TCP 20000-29999**: Dynamic TCP mode proxy allocations.

On `ufw`:
```bash
sudo ufw allow 7000/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 20000:29999/tcp
```
On `firewalld`:
```bash
sudo firewall-cmd --permanent --add-port={7000/tcp,80/tcp,443/tcp,20000-29999/tcp}
sudo firewall-cmd --reload
```
