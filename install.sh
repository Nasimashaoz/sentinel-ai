#!/bin/bash
# Sentinel AI — One-Line VPS Installer
# Usage: curl -sSL https://raw.githubusercontent.com/Nasimashaoz/sentinel-ai/main/install.sh | bash

set -e

echo ""
echo "🛡️  Installing Sentinel AI..."
echo ""

# Check prerequisites
command -v python3 >/dev/null 2>&1 || { echo "Python 3 required but not found. Install with: apt install python3"; exit 1; }
command -v git >/dev/null 2>&1 || { echo "Git required. Install with: apt install git"; exit 1; }

# Clone
git clone https://github.com/Nasimashaoz/sentinel-ai /opt/sentinel-ai
cd /opt/sentinel-ai

# Install dependencies
pip3 install -r requirements.txt

# Setup config
if [ ! -f .env ]; then
  cp .env.example .env
  echo ""
  echo "⚙️  Edit /opt/sentinel-ai/.env to configure your alert channels"
  echo "    nano /opt/sentinel-ai/.env"
fi

# Install as systemd service
cat > /etc/systemd/system/sentinel-ai.service << EOF
[Unit]
Description=Sentinel AI Security Agent
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/sentinel-ai
ExecStart=/usr/bin/python3 /opt/sentinel-ai/sentinel.py
Restart=always
RestartSec=10
StandardOutput=append:/var/log/sentinel-ai.log
StandardError=append:/var/log/sentinel-ai.log

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable sentinel-ai
systemctl start sentinel-ai

echo ""
echo "✅  Sentinel AI installed and running as a system service!"
echo ""
echo "   Check status: systemctl status sentinel-ai"
echo "   View logs:    tail -f /var/log/sentinel-ai.log"
echo "   Dashboard:    http://localhost:8080"
echo "   Stop:         systemctl stop sentinel-ai"
echo ""
echo "🔐  Sentinel AI is now protecting your server 24/7"
echo ""
