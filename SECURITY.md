# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| v1.1.x | ✅ Active |
| v1.0.x | ⚠️ Security fixes only |
| < v1.0 | ❌ Not supported |

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Instead, report privately via one of these methods:

1. **GitHub Security Advisory** (preferred):
   Go to [Security → Advisories → New draft advisory](https://github.com/Nasimashaoz/sentinel-ai/security/advisories/new)

2. **Email**: Create a GitHub issue titled `[SECURITY] Private Disclosure Request` and we will share a private email channel.

## What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (optional but appreciated)

## Response Timeline

| Stage | Time |
|---|---|
| Acknowledgement | Within 48 hours |
| Initial assessment | Within 5 days |
| Fix + patch release | Within 14 days for critical |
| Public disclosure | After fix is released |

## Security Best Practices for Deployment

### Protect your `.env` file
```bash
chmod 600 .env
chown root:root .env
```

### Never expose the dashboard publicly without auth
```nginx
# nginx reverse proxy with basic auth
server {
    listen 443 ssl;
    location / {
        auth_basic "Sentinel AI";
        auth_basic_user_file /etc/nginx/.htpasswd;
        proxy_pass http://localhost:8080;
    }
}
```

### Firewall the Prometheus port
```bash
# Only allow Prometheus scraper IP
ufw allow from YOUR_PROMETHEUS_IP to any port 9090
ufw deny 9090
```

### Firewall the mesh coordinator
```bash
# Only allow your node IPs
ufw allow from NODE_IP_1 to any port 8888
ufw allow from NODE_IP_2 to any port 8888
ufw deny 8888
```

### Rotate the mesh secret regularly
```bash
# Generate a strong secret
openssl rand -hex 32
# Update MESH_NODE_SECRET in .env on all servers
```

## Scope

**In scope:**
- Authentication bypass in the web dashboard or mesh coordinator
- Remote code execution via log injection
- Secrets leaking via the `/metrics` or `/api` endpoints
- SSRF in the threat intel enrichment module
- Privilege escalation in the installer script

**Out of scope:**
- Social engineering attacks
- Attacks requiring physical access to the server
- Third-party services (Telegram, Twilio, Discord API)
