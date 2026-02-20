#!/bin/bash

# ATPlus v3.0 Go Installer Script (Systemd Service)
# This script installs Golang, compiles main.go, and configures ATPlus.

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (use sudo)"
  exit 1
fi

echo "###########################################"
echo "#        🚀 ATPlus v3.0 Go Installer      #"
echo "###########################################"
echo ""

# Stop existing service if it exists
systemctl stop atplus 2>/dev/null

echo "[+] Checking for Golang compiler..."
if ! command -v go &> /dev/null; then
    echo "[-] Go is not installed. Installing Go..."
    if [ -x "$(command -v apt-get)" ]; then
        apt-get update && apt-get install -y golang
    elif [ -x "$(command -v yum)" ]; then
        yum install -y golang
    else
        echo "[-] Error: Unsupported package manager. Please install 'golang' manually."
        exit 1
    fi
fi

echo "[+] Downloading ATPlus Go source..."
mkdir -p /usr/local/src/atplus
wget -q -O /usr/local/src/atplus/main.go https://raw.githubusercontent.com/ramin-mahmoodi/ATPlus/main/main.go

echo "[+] Compiling ATPlus..."
cd /usr/local/src/atplus
go build -o /usr/local/bin/atplus main.go

if [ ! -f "/usr/local/bin/atplus" ]; then
    echo "[-] Compilation failed! Please check your Go installation."
    exit 1
fi

chmod +x /usr/local/bin/atplus
echo "[+] Compilation successful!"
echo ""

echo "Select Server Type:"
echo "1) Europe Server (Exit)"
echo "2) Iran Server (Bridge)"
read -p "Choice [1/2]: " SERVER_TYPE

read -p "Enter Tunnel Bridge Port (e.g., 443): " BRIDGE_PORT
read -p "Enter Port Sync Port (e.g., 444): " SYNC_PORT
read -p "Enter Secret Password (must match on both servers): " PASSWORD

if [ "$SERVER_TYPE" == "1" ]; then
    MODE="europe"
    read -p "Enter Iran Server IP: " IRAN_IP
    EXEC_CMD="/usr/local/bin/atplus --mode europe --iran-ip $IRAN_IP --bridge-port $BRIDGE_PORT --sync-port $SYNC_PORT --password \"$PASSWORD\""
elif [ "$SERVER_TYPE" == "2" ]; then
    MODE="iran"
    read -p "Do you want Auto-Sync Xray ports? (y/n): " AUTO_SYNC_INPUT
    if [[ "$AUTO_SYNC_INPUT" == "y" || "$AUTO_SYNC_INPUT" == "Y" ]]; then
        EXEC_CMD="/usr/local/bin/atplus --mode iran --bridge-port $BRIDGE_PORT --sync-port $SYNC_PORT --password \"$PASSWORD\" --auto-sync"
    else
        read -p "Enter ports manually (e.g. 80,443,2083): " MANUAL_PORTS
        EXEC_CMD="/usr/local/bin/atplus --mode iran --bridge-port $BRIDGE_PORT --sync-port $SYNC_PORT --password \"$PASSWORD\" --manual-ports $MANUAL_PORTS"
    fi
else
    echo "Invalid choice. Exiting."
    exit 1
fi

SERVICE_FILE="/etc/systemd/system/atplus.service"

cat > $SERVICE_FILE <<EOF
[Unit]
Description=ATPlus Reverse TCP Tunnel (Go Edition)
After=network.target

[Service]
Type=simple
User=root
ExecStart=$EXEC_CMD
Restart=always
RestartSec=5
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable atplus
systemctl restart atplus

echo ""
echo "✅ ATPlus (Go) has been installed and started as a service!"
echo "To check the status, run: systemctl status atplus"
echo "To view live logs, run: journalctl -u atplus -f"
echo "To stop the Service run: systemctl stop atplus"
