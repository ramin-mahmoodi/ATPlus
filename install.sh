#!/bin/bash

# ATPlus v2.0 Installer Script (Systemd Service)
# This script configures and installs ATPlus as a background service.

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (use sudo)"
  exit 1
fi

echo "###########################################"
echo "#        🚀 ATPlus v2.0 Installer         #"
echo "###########################################"
echo ""

# Stop existing service if it exists
systemctl stop atplus 2>/dev/null

echo "Downloading ATPlus..."
cat > /usr/local/bin/ATPlus.py << 'EOF'
import asyncio
import os
import socket
import struct
import argparse
try:
    import resource
except ImportError:
    resource = None

def print_banner(mode_name):
    os.system('clear')
    CYAN, YELLOW, MAGENTA, BOLD, END = "\033[96m", "\033[93m", "\033[95m", "\033[1m", "\033[0m"
    banner = f"""
{MAGENTA}{BOLD}###########################################
#            🚀 ATPlus v2.0               #
#      📢 Channel: @Telhost1             #
###########################################{END}
{CYAN}      AMIR
     (____)              {YELLOW}      .---.
     ( o o)              {YELLOW}     /     \\\\
  /--- \\ / ---\\          {YELLOW}    (| o o |)
 /            \\         {YELLOW}     |  V  |
|   {MAGENTA}WELCOME{YELLOW}    |   {BOLD}<--->{END}   {YELLOW}    /     \\\\
 \\            /          {YELLOW}   / /   \\\\ \\\\
  \\__________/           {YELLOW}  (__|___|__){END}
    {CYAN}Horned Man{END}             {YELLOW}    Linux Tux{END}
{BOLD}[+] Authentication & Obfuscation Enabled
[+] Dynamic Pool & Health Checks Active
[+] Mode: {mode_name}{END}
-------------------------------------------"""
    print(banner)

BUFFER_SIZE = 64 * 1024
OS_SOCK_BUFFER = 256 * 1024  # Reduced from 2MB to 256KB to save RAM
MIN_CONNECTIONS = 20         # Start with low amount
MAX_CONNECTIONS = 500        # Max dynamic cap

def optimize_system():
    if resource is not None:
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (1000000, 1000000))
        except (ValueError, OSError):
            pass

def tune_socket(writer):
    sock = writer.get_extra_info('socket')
    if sock:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        # Apply standard keep-alive to detect dead connections (zombies)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        try:
            # Linux specific keep-alive timings
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
        except AttributeError:
            pass # Ignore if OS doesn't support these specific options
            
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, OS_SOCK_BUFFER)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, OS_SOCK_BUFFER)

def get_auth_key(password):
    # Derive a simple 16-byte key from user password
    import hashlib
    return hashlib.md5(password.encode()).digest()

def obfuscate_port(port, auth_key):
    # XOR the 2-byte port with the first 2 bytes of the auth key
    port_bytes = struct.pack('!H', port)
    return bytes([port_bytes[0] ^ auth_key[0], port_bytes[1] ^ auth_key[1]])

def deobfuscate_port(obfuscated_bytes, auth_key):
    port_bytes = bytes([obfuscated_bytes[0] ^ auth_key[0], obfuscated_bytes[1] ^ auth_key[1]])
    return struct.unpack('!H', port_bytes)[0]

async def fast_pipe(reader, writer):
    try:
        while True:
            data = await reader.read(BUFFER_SIZE)
            if not data: break
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
        pass
    except Exception as e:
        pass
    finally:
        if not writer.is_closing():
            writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

async def start_europe(args=None):
    print_banner("EUROPE (XRAY CONNECTOR)")
    
    if args and args.iran_ip and args.bridge_port and args.sync_port and args.password:
        iran_ip = args.iran_ip
        bridge_p = args.bridge_port
        sync_p = args.sync_port
        password = args.password
    else:
        iran_ip = input("[?] Iran IP: ")
        bridge_p = int(input("[?] Tunnel Bridge Port: "))
        sync_p = int(input("[?] Port Sync Port: "))
        password = input("[?] Secret Password (must match Iran): ")
    
    auth_key = get_auth_key(password)
    active_connections = 0

    def get_xray_ports():
        # Parsing /proc/net/tcp and /proc/net/tcp6 instead of running `ss` subprocess
        ports = set()
        for proc_file in ['/proc/net/tcp', '/proc/net/tcp6']:
            try:
                with open(proc_file, 'r') as f:
                    lines = f.readlines()[1:] # skip header
                    for line in lines:
                        parts = line.strip().split()
                        if len(parts) >= 4:
                            # state 0A is LISTEN
                            if parts[3] == '0A':
                                local_address = parts[1]
                                ip_hex, port_hex = local_address.split(':')
                                port_num = int(port_hex, 16)
                                # Exclude bridge and sync ports, keep > 100
                                if port_num > 100 and port_num != bridge_p and port_num != sync_p:
                                    ports.add(port_num)
            except FileNotFoundError:
                pass
            except Exception as e:
                pass
        return ports

    async def port_sync_task():
        while True:
            try:
                reader, writer = await asyncio.open_connection(iran_ip, sync_p)
                tune_socket(writer)
                # Send auth key first
                writer.write(auth_key)
                await writer.drain()
                
                current_ports = list(get_xray_ports())
                data = struct.pack('!B', len(current_ports))
                for p in current_ports:
                    data += obfuscate_port(p, auth_key)
                
                writer.write(data)
                await writer.drain()
                
                writer.close()
                await writer.wait_closed()
            except Exception as e:
                pass
            await asyncio.sleep(5)

    async def create_reverse_link():
        nonlocal active_connections
        try:
            reader, writer = await asyncio.open_connection(iran_ip, bridge_p)
            tune_socket(writer)
            
            # Send Auth Header
            writer.write(auth_key)
            await writer.drain()
            
            active_connections += 1
            
            # Read 2 obfuscated bytes for target port
            try:
                header = await reader.readexactly(2)
            except asyncio.IncompleteReadError:
                return # Connection dropped before telling us
                
            target_port = deobfuscate_port(header, auth_key)
            
            # Heartbeat check (0 = ping)
            if target_port == 0:
                return
                
            remote_reader, remote_writer = await asyncio.open_connection('127.0.0.1', target_port)
            tune_socket(remote_writer)
            
            # Pipe data
            await asyncio.gather(
                fast_pipe(reader, remote_writer),
                fast_pipe(remote_reader, writer),
                return_exceptions=True
            )
            
        except asyncio.CancelledError:
            pass
        except Exception as e:
            await asyncio.sleep(1)
        finally:
            active_connections = max(0, active_connections - 1)
            try:
                if 'writer' in locals() and not writer.is_closing():
                    writer.close()
                    await writer.wait_closed()
            except Exception:
                pass

    # Dynamic Connection Manager
    async def manage_pool():
        while True:
            if active_connections < MIN_CONNECTIONS:
                # Add connections up to MIN
                need = MIN_CONNECTIONS - active_connections
                for _ in range(need):
                    asyncio.create_task(create_reverse_link())
            elif active_connections < MAX_CONNECTIONS:
                # Slowly scale up if we are above MIN but let the natural drain happen
                asyncio.create_task(create_reverse_link())
            
            await asyncio.sleep(0.5)

    asyncio.create_task(port_sync_task())
    asyncio.create_task(manage_pool())
    
    print(f"✅ Running... Sync: {sync_p} | Bridge: {bridge_p} | Pool: Dynamic")
    try:
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        pass


async def start_iran(args=None):
    print_banner("IRAN (FLEX LISTENER)")
    
    if args and args.bridge_port and args.sync_port and args.password:
        bridge_p = args.bridge_port
        sync_p = args.sync_port
        password = args.password
        is_auto = args.auto_sync if args.auto_sync is not None else True
        manual_ports_str = args.manual_ports
    else:
        bridge_p = int(input("[?] Tunnel Bridge Port: "))
        sync_p = int(input("[?] Port Sync Port: "))
        password = input("[?] Secret Password (must match Europe): ")
        is_auto = input("[?] Do you want Auto-Sync Xray ports? (y/n): ").lower() == 'y'
        manual_ports_str = None
    
    auth_key = get_auth_key(password)
    
    connection_pool = asyncio.Queue()
    active_servers = {} 

    async def handle_europe_bridge(reader, writer):
        tune_socket(writer)
        
        # Authenticate Europe
        try:
            client_auth = await asyncio.wait_for(reader.readexactly(16), timeout=5.0)
            if client_auth != auth_key:
                writer.close()
                return
        except Exception:
            writer.close()
            return
            
        await connection_pool.put((reader, writer))

    async def get_valid_connection():
        # Retrieve a connection and ensure it's not a zombie
        while True:
            try:
                e_reader, e_writer = await connection_pool.get()
                if e_writer.is_closing():
                    continue
                return e_reader, e_writer
            except asyncio.QueueEmpty:
                await asyncio.sleep(0.1)

    async def handle_user_side(reader, writer, target_p):
        tune_socket(writer)
        try:
            # Getting a connection from Europe
            e_reader, e_writer = await get_valid_connection()
            
            # Send Obfuscated Port
            e_writer.write(obfuscate_port(target_p, auth_key))
            await e_writer.drain()
            
            await asyncio.gather(
                fast_pipe(reader, e_writer), 
                fast_pipe(e_reader, writer), 
                return_exceptions=True
            )
        except Exception as e:
            pass
        finally:
            if not writer.is_closing():
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

    async def open_new_port(p):
        if p not in active_servers:
            try:
                srv = await asyncio.start_server(lambda r, w, p=p: handle_user_side(r, w, p), '0.0.0.0', p, backlog=5000)
                active_servers[p] = srv
                print(f"✨ Port Active: {p}")
            except Exception as e:
                print(f"❌ Error opening port {p}: {e}")

    async def handle_sync_conn(reader, writer):
        try:
            # Authenticate Sync
            client_auth = await asyncio.wait_for(reader.readexactly(16), timeout=5.0)
            if client_auth != auth_key:
                writer.close()
                return
                
            header = await asyncio.wait_for(reader.readexactly(1), timeout=5.0)
            count = struct.unpack('!B', header)[0]
            for _ in range(count):
                p_data = await reader.readexactly(2)
                p = deobfuscate_port(p_data, auth_key)
                await open_new_port(p)
        except Exception as e:
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    await asyncio.start_server(handle_europe_bridge, '0.0.0.0', bridge_p, backlog=10000)

    if is_auto:
        await asyncio.start_server(handle_sync_conn, '0.0.0.0', sync_p, backlog=100)
        print(f"🔍 Auto-Sync Active on port {sync_p}")
    else:
        if not manual_ports_str:
            manual_ports_str = input("[?] Enter ports manually (e.g. 80,443,2083): ")
        manual_ports = manual_ports_str.split(',')
        for p_str in manual_ports:
            if p_str.strip().isdigit():
                await open_new_port(int(p_str.strip()))
        print("✅ Manual Ports Opened.")

    try:
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    optimize_system()
    
    parser = argparse.ArgumentParser(description="ATPlus - High Performance Reverse TCP Tunnel")
    parser.add_argument("--mode", choices=['europe', 'iran'], help="Server mode")
    parser.add_argument("--iran-ip", help="Iran Server IP (for Europe mode)")
    parser.add_argument("--bridge-port", type=int, help="Tunnel Bridge Port")
    parser.add_argument("--sync-port", type=int, help="Port Sync Port")
    parser.add_argument("--password", help="Secret Password")
    parser.add_argument("--auto-sync", type=bool, nargs='?', const=True, default=None, help="Enable Auto-Sync Xray ports")
    parser.add_argument("--manual-ports", help="Comma separated ports for manual entry")
    
    args, unknown = parser.parse_known_args()
    
    if args.mode == 'europe':
        asyncio.run(start_europe(args))
    elif args.mode == 'iran':
        asyncio.run(start_iran(args))
    else:
        print("1) Europe Server\n2) Iran Server")
        choice = input("Choice: ")
        if choice == '1': 
            asyncio.run(start_europe())
        else: 
            asyncio.run(start_iran())
EOF

chmod +x /usr/local/bin/ATPlus.py

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
    EXEC_CMD="/usr/bin/python3 /usr/local/bin/ATPlus.py --mode europe --iran-ip $IRAN_IP --bridge-port $BRIDGE_PORT --sync-port $SYNC_PORT --password \"$PASSWORD\""
elif [ "$SERVER_TYPE" == "2" ]; then
    MODE="iran"
    read -p "Do you want Auto-Sync Xray ports? (y/n): " AUTO_SYNC_INPUT
    if [[ "$AUTO_SYNC_INPUT" == "y" || "$AUTO_SYNC_INPUT" == "Y" ]]; then
        EXEC_CMD="/usr/bin/python3 /usr/local/bin/ATPlus.py --mode iran --bridge-port $BRIDGE_PORT --sync-port $SYNC_PORT --password \"$PASSWORD\" --auto-sync"
    else
        read -p "Enter ports manually (e.g. 80,443,2083): " MANUAL_PORTS
        EXEC_CMD="/usr/bin/python3 /usr/local/bin/ATPlus.py --mode iran --bridge-port $BRIDGE_PORT --sync-port $SYNC_PORT --password \"$PASSWORD\" --manual-ports $MANUAL_PORTS"
    fi
else
    echo "Invalid choice. Exiting."
    exit 1
fi

SERVICE_FILE="/etc/systemd/system/atplus.service"

cat > $SERVICE_FILE <<EOF
[Unit]
Description=ATPlus Reverse TCP Tunnel
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
echo "✅ ATPlus has been installed and started as a service!"
echo "To check the status, run: systemctl status atplus"
echo "To view live logs, run: journalctl -u atplus -f"
echo "To stop the Service run: systemctl stop atplus"
