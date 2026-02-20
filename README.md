# AmirTunnel-Pro
High-performance, Reverse TCP Tunnel with dynamic Xray port synchronization. Designed for maximum speed and intranet-to-internet bridging.

Markdown
# 🚀 AmirTunnel-Pro v2.0 (High Performance & Anti-DPI)

High-performance, Reverse TCP Tunnel with dynamic Xray port synchronization. Specifically designed to bypass upload speed restrictions and provide a seamless, secure connection between Iran and External servers.

## ⚡ Quick Start (Auto-Install & Run in Background)

Use this single command to download the script and run it inside a **Screen** session. This ensures the tunnel keeps running even after you close the terminal.

```bash
wget --no-check-certificate -O AmirTunnelPro.py http://raw.githubusercontent.com/amircpuir/AmirTunnel-Pro/main/AmirTunnelPro.py && screen -S amirtunnel python3 AmirTunnelPro.py
🛠 How to Use
1. Setup on Iran Server (Bridge)
Run the command above and select Option 2 (Iran Server).

Enter your Tunnel Bridge Port (e.g., 443).

Enter your Port Sync Port (e.g., 444).

Enter a Secret Password (e.g., `mylongpassword123`). This keeps your tunnel safe from scanners and DPI.

Choose y for Auto-Sync or n for Manual Entry.

2. Setup on Europe Server (Exit)
Run the command above and select Option 1 (Europe Server).

Enter your Iran Server IP.

Use the same ports you configured on the Iran server.

📺 Managing your Session (Screen Commands)
Since the script runs inside a "Screen" session named amirtunnel:

To Detach: Press Ctrl + A then D (This leaves the tunnel running in the background).

To Re-attach: Run screen -r amirtunnel to see the logs and the menu again.

To Kill: Run screen -XS amirtunnel quit.

🚀 Key Features (v2.0)
Security & Anti-DPI: Uses a Secret Password to authenticate servers and XOR obfuscation to hide target ports from DPI inspection.

Dynamic Connection Pool: Automatically scales connections based on demand (from 20 up to 500) to save RAM and avoid suspicion.

TCP Keep-Alive: Actively drops dead/zombie sessions to ensure a 100% reliable connection.

Persistence: Runs in a screen session to prevent disconnection issues.

Zero Latency: Re-written core logic minimizes CPU usage and removes subprocess overheads.

🔧 Troubleshooting
If you see Address already in use, it means a previous session is still holding the ports. Kill all python processes using:

Bash
pkill -f python3
