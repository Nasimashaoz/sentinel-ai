# Deploying Sentinel AI on a VPS

This guide covers deploying on a fresh Ubuntu 22.04 / 24.04 VPS (DigitalOcean, Hetzner, Linode, AWS EC2).

## Option A — One-Line Install (Fastest)

```bash
curl -sSL https://raw.githubusercontent.com/Nasimashaoz/sentinel-ai/main/install.sh | bash
```

This installs Sentinel AI to `/opt/sentinel-ai` and registers it as a `systemd` service that starts on boot.

## Option B — Docker Compose

```bash
# Install Docker
curl -fsSL https://get.docker.com | sh

# Clone and configure
git clone https://github.com/Nasimashaoz/sentinel-ai
cd sentinel-ai
cp .env.example .env
nano .env   # fill in your API keys

# Launch (detached)
docker-compose up -d

# Monitor
docker-compose logs -f sentinel
```

## Securing the Dashboard

The dashboard runs on port `8080`. **Do not expose it publicly** without a reverse proxy + authentication.

### Nginx reverse proxy with basic auth:

```nginx
server {
    listen 443 ssl;
    server_name sentinel.yourdomain.com;

    ssl_certificate     /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    auth_basic           "Sentinel AI";
    auth_basic_user_file /etc/nginx/.htpasswd;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

```bash
# Create password
sudo apt install apache2-utils
sudo htpasswd -c /etc/nginx/.htpasswd admin
```

## Firewall Rules

```bash
sudo ufw allow 22/tcp      # SSH
sudo ufw allow 443/tcp     # HTTPS dashboard
sudo ufw deny 8080         # Block direct dashboard access
sudo ufw enable
```

## Auto-restart on Crash

The systemd service created by `install.sh` already includes `Restart=always`. Verify:

```bash
systemctl status sentinel-ai
journalctl -u sentinel-ai -f
```
