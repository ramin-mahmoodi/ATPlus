import asyncio
import os
import socket
import struct
try:
    import resource
except ImportError:
    resource = None

def print_banner(mode_name):
    os.system('clear')
    CYAN, YELLOW, MAGENTA, BOLD, END = "\033[96m", "\033[93m", "\033[95m", "\033[1m", "\033[0m"
    banner = f"""
{MAGENTA}{BOLD}###########################################
#          🚀 AmirTunnel-Pro v2.0         #
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

async def start_europe():
    print_banner("EUROPE (XRAY CONNECTOR)")
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


async def start_iran():
    print_banner("IRAN (FLEX LISTENER)")
    bridge_p = int(input("[?] Tunnel Bridge Port: "))
    sync_p = int(input("[?] Port Sync Port: "))
    password = input("[?] Secret Password (must match Europe): ")
    
    auth_key = get_auth_key(password)
    
    is_auto = input("[?] Do you want Auto-Sync Xray ports? (y/n): ").lower() == 'y'
    
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
        manual_ports = input("[?] Enter ports manually (e.g. 80,443,2083): ").split(',')
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
    print("1) Europe Server\n2) Iran Server")
    choice = input("Choice: ")
    if choice == '1': 
        asyncio.run(start_europe())
    else: 
        asyncio.run(start_iran())
