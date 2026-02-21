#!/bin/bash

# ATPlus v4.0 (Anti-DPI) Installer Script
# This script installs Golang, compiles main.go, and configures ATPlus.

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (use sudo)"
  exit 1
fi

echo "###########################################"
echo "#     🚀 ATPlus v5.0 Stable Installer     #"
echo "###########################################"
echo ""

# =============================================
# LINUX KERNEL & NETWORK OPTIMIZATIONS
# =============================================
echo "[+] Applying Linux Kernel Optimizations..."

# --- BBR Congestion Control ---
modprobe tcp_bbr 2>/dev/null
if grep -q tcp_bbr /proc/modules 2>/dev/null; then
    sysctl -w net.core.default_qdisc=fq > /dev/null 2>&1
    sysctl -w net.ipv4.tcp_congestion_control=bbr > /dev/null 2>&1
    echo "  [✓] BBR Congestion Control enabled"
else
    echo "  [!] BBR not available on this kernel, skipping"
fi

# --- TCP Fast Open (client+server) ---
sysctl -w net.ipv4.tcp_fastopen=3 > /dev/null 2>&1
echo "  [✓] TCP Fast Open enabled"

# --- TCP Buffer Ceilings (only raise MAX, never touch defaults) ---
sysctl -w net.core.rmem_max=16777216 > /dev/null 2>&1
sysctl -w net.core.wmem_max=16777216 > /dev/null 2>&1
sysctl -w net.ipv4.tcp_rmem="4096 131072 16777216" > /dev/null 2>&1
sysctl -w net.ipv4.tcp_wmem="4096 65536 16777216" > /dev/null 2>&1
echo "  [✓] TCP buffer ceilings raised (defaults untouched)"

# --- TCP Keepalive (detect dead connections faster) ---
sysctl -w net.ipv4.tcp_keepalive_time=60 > /dev/null 2>&1
sysctl -w net.ipv4.tcp_keepalive_intvl=10 > /dev/null 2>&1
sysctl -w net.ipv4.tcp_keepalive_probes=6 > /dev/null 2>&1
echo "  [✓] TCP Keepalive intervals reduced"

# --- Connection Queue (handle bursts better) ---
sysctl -w net.core.somaxconn=65535 > /dev/null 2>&1
sysctl -w net.core.netdev_max_backlog=8192 > /dev/null 2>&1
sysctl -w net.ipv4.tcp_max_syn_backlog=8192 > /dev/null 2>&1
echo "  [✓] Connection queue limits raised"

# --- Disable IPv6 (if not used, reduces overhead) ---
sysctl -w net.ipv6.conf.all.disable_ipv6=1 > /dev/null 2>&1
sysctl -w net.ipv6.conf.default.disable_ipv6=1 > /dev/null 2>&1
echo "  [✓] IPv6 disabled"

# --- Reduce Swappiness ---
sysctl -w vm.swappiness=10 > /dev/null 2>&1
echo "  [✓] Swappiness reduced to 10"

# --- TCP Tweaks ---
sysctl -w net.ipv4.tcp_tw_reuse=1 > /dev/null 2>&1
sysctl -w net.ipv4.tcp_fin_timeout=15 > /dev/null 2>&1
sysctl -w net.ipv4.tcp_slow_start_after_idle=0 > /dev/null 2>&1
echo "  [✓] TIME_WAIT reuse + no slow start after idle"

# --- Disable Conntrack (reduce per-packet latency) ---
if lsmod | grep -q nf_conntrack 2>/dev/null; then
    rmmod nf_conntrack_netlink 2>/dev/null
    rmmod xt_conntrack 2>/dev/null
    # Only attempt if iptables is not actively using it
    if rmmod nf_conntrack 2>/dev/null; then
        echo "  [✓] Connection tracking disabled"
    else
        echo "  [!] Conntrack in use by iptables, increasing table size instead"
        sysctl -w net.netfilter.nf_conntrack_max=524288 > /dev/null 2>&1
    fi
else
    echo "  [✓] Connection tracking already disabled"
fi

# --- File Descriptor Limits ---
if ! grep -q "* soft nofile" /etc/security/limits.conf 2>/dev/null; then
    echo "* soft nofile 1000000" >> /etc/security/limits.conf
    echo "* hard nofile 1000000" >> /etc/security/limits.conf
    echo "  [✓] File descriptor limits raised to 1M"
else
    echo "  [✓] File descriptor limits already configured"
fi
ulimit -n 1000000 2>/dev/null

# --- Make sysctl persistent ---
cat > /etc/sysctl.d/99-atplus.conf << 'SYSEOF'
# ATPlus Network Optimizations
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_fastopen=3
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.tcp_rmem=4096 131072 16777216
net.ipv4.tcp_wmem=4096 65536 16777216
net.ipv4.tcp_keepalive_time=60
net.ipv4.tcp_keepalive_intvl=10
net.ipv4.tcp_keepalive_probes=6
net.core.somaxconn=65535
net.core.netdev_max_backlog=8192
net.ipv4.tcp_max_syn_backlog=8192
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
vm.swappiness=10
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_slow_start_after_idle=0
SYSEOF
echo "  [✓] All optimizations persisted to /etc/sysctl.d/99-atplus.conf"
echo ""

systemctl stop atplus 2>/dev/null

echo "[+] Checking for Golang compiler..."
if ! command -v go &> /dev/null; then
    echo "[-] Go is not installed. Installing Go..."
    
    # Attempt 1: Snap
    if command -v snap &> /dev/null; then
        echo "[+] Attempting to install via snap..."
        snap install go --classic
    fi

    # Attempt 2: Direct Tarball (If snap failed or doesn't exist)
    if ! command -v go &> /dev/null; then
        echo "[+] Snap failed or unavailable. Falling back to official Go binaries..."
        cd /tmp
        wget -q -O go.tar.gz https://go.dev/dl/go1.22.1.linux-amd64.tar.gz
        rm -rf /usr/local/go
        tar -C /usr/local -xzf go.tar.gz
        export PATH=$PATH:/usr/local/go/bin
        echo "export PATH=\$PATH:/usr/local/go/bin" >> ~/.profile
        echo "export PATH=\$PATH:/usr/local/go/bin" >> ~/.bashrc
    fi
fi

# Ensure go is in path for the current shell session
export PATH=$PATH:/usr/local/go/bin

echo "[+] Initializing Go Module..."
mkdir -p /usr/local/src/atplus
cd /usr/local/src/atplus
rm -f go.mod go.sum main.go
go mod init atplus

echo "[+] Bypassing DNS blocks for Go modules..."
export GOPROXY=direct,https://goproxy.io,https://goproxy.cn
go env -w GOPROXY=direct,https://goproxy.io,https://goproxy.cn

echo "[+] Downloading dependencies..."
go get github.com/xtaci/smux
go get github.com/refraction-networking/utls

echo "[+] Generating ATPlus Source Code..."
cat > /usr/local/src/atplus/main.go << 'EOF'
package main

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtaci/smux"
)

// ----------------------------------------------------
// LEVELED LOGGING (Feature 6)
// ----------------------------------------------------

func logInfo(format string, args ...interface{}) {
	fmt.Printf("[%s] [INFO]  %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, args...))
}

func logWarn(format string, args ...interface{}) {
	fmt.Printf("[%s] [WARN]  %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, args...))
}

func logError(format string, args ...interface{}) {
	fmt.Printf("[%s] [ERROR] %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, args...))
}

// ----------------------------------------------------
// GLOBALS
// ----------------------------------------------------

var (
	mode        string
	iranIP      string
	bridgePort  int
	syncPort    int
	password    string
	autoSync    bool
	manualPorts string
	antiDpi     bool

	authKey []byte
	cyan    = "\033[96m"
	yellow  = "\033[93m"
	magenta = "\033[95m"
	bold    = "\033[1m"
	reset   = "\033[0m"

	poolMu         sync.Mutex
	sessionPool    []*managedSession
	maxSmuxTunnels = 16

	bufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 32768)
		},
	}

	// Feature 3: Graceful Shutdown
	activeConns sync.WaitGroup
	globalCtx   context.Context
	globalStop  context.CancelFunc
)

// Feature 4: Connection Recycling — wraps smux.Session with creation timestamp
type managedSession struct {
	*smux.Session
	createdAt time.Time
}

const sessionTTL = 30 * time.Minute // Feature 4: max session lifetime

func init() {
	flag.StringVar(&mode, "mode", "", "europe or iran")
	flag.StringVar(&iranIP, "iran-ip", "", "Iran Server IP (for Europe mode)")
	flag.IntVar(&bridgePort, "bridge-port", 0, "Tunnel Bridge Port")
	flag.IntVar(&syncPort, "sync-port", 0, "Port Sync Port")
	flag.StringVar(&password, "password", "", "Secret Password")
	flag.BoolVar(&autoSync, "auto-sync", false, "Enable Auto-Sync Xray ports (Iran mode)")
	flag.StringVar(&manualPorts, "manual-ports", "", "Comma separated ports for manual entry")
	flag.BoolVar(&antiDpi, "anti-dpi", false, "Enable uTLS, Fragmentation & HTTP Decoy")
}

func printBanner(m string) {
	fmt.Print("\033[H\033[2J")
	banner := fmt.Sprintf(`%s%s###########################################
#          🚀 ATPlus v5.0 (Stable)        #
#      📢 Channel: @Telhost1             #
###########################################%s
%s      AMIR
     (____)              %s      .---.
     ( o o)              %s     /     \
  /--- \ / ---\          %s    (| o o |)
 /            \         %s     |  V  |
|   %sWELCOME%s    |   %s<--->%s   %s    /     \
 \            /          %s   / /   \ \
  \__________/           %s  (__|___|__)%s
    %sHorned Man%s             %s    Linux Tux%s
%s[+] Multiplexing (Smux) Engine Active
[+] Zero-Copy Memory Pools
[+] Health Check + Auto-Reconnect + Graceful Shutdown
[+] Session Recycling (TTL: 30m) + Failover
[+] Mode: %s%s
-------------------------------------------
`,
		magenta, bold, reset,
		cyan, yellow, yellow, yellow, yellow,
		magenta, yellow, bold, reset, yellow,
		yellow, yellow, reset,
		cyan, reset, yellow, reset,
		bold, m, reset)
	if antiDpi {
		banner += fmt.Sprintf("%s[+] ANTI-DPI MODE: uTLS + TLS Frag + HTTP Decoy ACTIVE%s\n", yellow, reset)
	} else {
		banner += fmt.Sprintf("%s[+] RAW MODE: Max Speed (No Anti-DPI)%s\n", cyan, reset)
	}
	fmt.Print(banner)
}

func getAuthKey(pass string) []byte {
	h := md5.Sum([]byte(pass))
	return h[:]
}

func obfuscatePort(port uint16, key []byte) []byte {
	pBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(pBytes, port)
	pBytes[0] ^= key[0]
	pBytes[1] ^= key[1]
	return pBytes
}

func deobfuscatePort(obfuscated []byte, key []byte) uint16 {
	pBytes := make([]byte, 2)
	pBytes[0] = obfuscated[0] ^ key[0]
	pBytes[1] = obfuscated[1] ^ key[1]
	return binary.BigEndian.Uint16(pBytes)
}

func tuneSocket(conn net.Conn) {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(15 * time.Second)
	}
}

func proxyConn(c1, c2 net.Conn) {
	activeConns.Add(1)
	defer activeConns.Done()

	var wg sync.WaitGroup
	wg.Add(2)

	pipe := func(dst, src net.Conn) {
		defer wg.Done()
		buf := bufferPool.Get().([]byte)
		io.CopyBuffer(dst, src, buf)
		bufferPool.Put(buf)

		if hw, ok := dst.(interface{ CloseWrite() error }); ok {
			hw.CloseWrite()
		}
		if hr, ok := src.(interface{ CloseRead() error }); ok {
			hr.CloseRead()
		}
	}

	go pipe(c1, c2)
	pipe(c2, c1)
	wg.Wait()
	c1.Close()
	c2.Close()
}

// ----------------------------------------------------
// ANTI-DPI UTILS
// ----------------------------------------------------

type fragConn struct {
	net.Conn
	written int
}

func (c *fragConn) Write(b []byte) (n int, err error) {
	if c.written < 1000 && len(b) > 50 {
		chunks := [][]byte{
			b[:10],
			b[10:30],
			b[30:50],
			b[50:],
		}
		for _, chunk := range chunks {
			nn, err := c.Conn.Write(chunk)
			n += nn
			c.written += nn
			if err != nil {
				return n, err
			}
			time.Sleep(2 * time.Millisecond)
		}
		return n, nil
	}
	nn, err := c.Conn.Write(b)
	c.written += nn
	return nn, err
}

func generateDummyCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Cloudflare, Inc."},
			CommonName:   "www.cloudflare.com",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, nil
}

// ----------------------------------------------------
// SMUX CONFIG FACTORY
// ----------------------------------------------------

func newSmuxConfig() *smux.Config {
	cfg := smux.DefaultConfig()
	cfg.MaxReceiveBuffer = 4194304 * 2
	cfg.MaxStreamBuffer = 4194304
	cfg.KeepAliveInterval = 10 * time.Second
	cfg.KeepAliveTimeout = 30 * time.Second
	return cfg
}

// ----------------------------------------------------
// MULTIPLEXER FACTORY
// ----------------------------------------------------

func createEuropeMultiplexer() (*managedSession, error) {
	rawConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", iranIP, bridgePort), 5*time.Second)
	if err != nil {
		return nil, err
	}
	tuneSocket(rawConn)

	var transportConn net.Conn = rawConn

	if antiDpi {
		fConn := &fragConn{Conn: rawConn}
		config := &utls.Config{ServerName: "www.google.com", InsecureSkipVerify: true}
		tlsConn := utls.UClient(fConn, config, utls.HelloChrome_120)

		if err := tlsConn.Handshake(); err != nil {
			rawConn.Close()
			return nil, err
		}

		// HTTP Decoy
		decoyReq := "GET / HTTP/1.1\r\nHost: www.google.com\r\nUser-Agent: Mozilla/5.0\r\nConnection: upgrade\r\n\r\n"
		if _, err := tlsConn.Write([]byte(decoyReq)); err != nil {
			rawConn.Close()
			return nil, err
		}

		transportConn = tlsConn
	}

	if _, err := transportConn.Write(authKey); err != nil {
		transportConn.Close()
		return nil, err
	}

	session, err := smux.Client(transportConn, newSmuxConfig())
	if err != nil {
		transportConn.Close()
		return nil, err
	}

	return &managedSession{Session: session, createdAt: time.Now()}, nil
}

// ----------------------------------------------------
// EUROPE
// ----------------------------------------------------

func getXrayPorts() []uint16 {
	portSet := make(map[uint16]bool)
	for _, file := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			parts := strings.Fields(line)
			if len(parts) >= 4 && parts[3] == "0A" {
				addrParts := strings.Split(parts[1], ":")
				if len(addrParts) == 2 {
					if port64, err := strconv.ParseUint(addrParts[1], 16, 16); err == nil {
						p := uint16(port64)
						if p > 100 && p != uint16(bridgePort) && p != uint16(syncPort) {
							portSet[p] = true
						}
					}
				}
			}
		}
	}
	var ports []uint16
	for p := range portSet {
		ports = append(ports, p)
	}
	return ports
}

func startEurope() {
	if iranIP == "" || bridgePort == 0 || syncPort == 0 || password == "" {
		logError("Missing arguments for Europe mode.")
		os.Exit(1)
	}
	printBanner("EUROPE (XRAY CONNECTOR)")
	authKey = getAuthKey(password)

	// Feature 1: Health Check — probes sessions every 15s
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-globalCtx.Done():
				return
			case <-ticker.C:
				poolMu.Lock()
				var dead []*managedSession
				for _, ms := range sessionPool {
					if ms.IsClosed() {
						dead = append(dead, ms)
						continue
					}
					// Quick probe: open a stream and immediately close it
					stream, err := ms.OpenStream()
					if err != nil {
						dead = append(dead, ms)
						continue
					}
					stream.Close()
				}
				for _, d := range dead {
					removeSessionLocked(d)
					logWarn("Health check: removed dead session (age: %s)", time.Since(d.createdAt).Round(time.Second))
					d.Close()
				}
				poolMu.Unlock()
			}
		}
	}()

	// Feature 4: Connection Recycling — retire sessions older than TTL
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-globalCtx.Done():
				return
			case <-ticker.C:
				poolMu.Lock()
				var expired []*managedSession
				for _, ms := range sessionPool {
					if time.Since(ms.createdAt) > sessionTTL {
						expired = append(expired, ms)
					}
				}
				for _, ms := range expired {
					removeSessionLocked(ms)
					logInfo("Recycled session (lived %s)", time.Since(ms.createdAt).Round(time.Second))
					ms.Close()
				}
				poolMu.Unlock()
			}
		}
	}()

	// Session builder with Feature 2: Exponential Backoff
	go func() {
		backoff := 500 * time.Millisecond
		const maxBackoff = 30 * time.Second

		for {
			select {
			case <-globalCtx.Done():
				return
			default:
			}

			poolMu.Lock()
			currentLinks := len(sessionPool)
			poolMu.Unlock()

			if currentLinks < maxSmuxTunnels {
				needed := maxSmuxTunnels - currentLinks
				successCount := int32(0)
				var wg sync.WaitGroup
				for i := 0; i < needed; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						ms, err := createEuropeMultiplexer()
						if err != nil {
							return
						}
						poolMu.Lock()
						if len(sessionPool) < maxSmuxTunnels {
							sessionPool = append(sessionPool, ms)
							atomic.AddInt32(&successCount, 1)
							go europeSessionWorker(ms)
						} else {
							ms.Close()
						}
						poolMu.Unlock()
					}()
				}
				wg.Wait()

				// Feature 2: Adjust backoff
				if atomic.LoadInt32(&successCount) > 0 {
					backoff = 500 * time.Millisecond // reset on success
				} else {
					backoff *= 2
					if backoff > maxBackoff {
						backoff = maxBackoff
					}
					logWarn("All reconnect attempts failed, backing off %s", backoff)
				}
			} else {
				backoff = 500 * time.Millisecond // pool full, reset
			}

			select {
			case <-globalCtx.Done():
				return
			case <-time.After(backoff):
			}
		}
	}()

	// Port sync goroutine
	go func() {
		for {
			select {
			case <-globalCtx.Done():
				return
			default:
			}

			if rawConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", iranIP, syncPort), 5*time.Second); err == nil {
				tuneSocket(rawConn)
				rawConn.Write(authKey)

				ports := getXrayPorts()
				count := len(ports)
				if count > 255 {
					count = 255
				}
				buf := make([]byte, 0, 1+count*2)
				buf = append(buf, byte(count))
				for i := 0; i < count; i++ {
					buf = append(buf, obfuscatePort(ports[i], authKey)...)
				}
				rawConn.Write(buf)
				rawConn.Close()
			}

			select {
			case <-globalCtx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}()

	logInfo("Running... Sync: %d | Bridge: %d | Tunnels: %d | Recycling: %s", syncPort, bridgePort, maxSmuxTunnels, sessionTTL)
	<-globalCtx.Done()
	logInfo("Shutdown signal received, waiting for active connections...")
	activeConns.Wait()
	logInfo("All connections drained. Goodbye!")
}

// europeSessionWorker accepts streams on a session and removes it from the pool when it dies.
func europeSessionWorker(ms *managedSession) {
	for {
		stream, err := ms.AcceptStream()
		if err != nil {
			break
		}
		go handleEuropeStream(stream)
	}
	poolMu.Lock()
	removeSessionLocked(ms)
	poolMu.Unlock()
}

func handleEuropeStream(stream *smux.Stream) {
	header := make([]byte, 2)
	stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(stream, header); err != nil {
		stream.Close()
		return
	}
	stream.SetReadDeadline(time.Time{})
	targetPort := deobfuscatePort(header, authKey)
	if targetPort == 0 {
		stream.Close()
		return
	}

	localConn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", targetPort), 5*time.Second)
	if err != nil {
		stream.Close()
		return
	}
	tuneSocket(localConn)

	proxyConn(stream, localConn)
}

// removeSessionLocked removes a managed session from the pool. Caller MUST hold poolMu.
func removeSessionLocked(target *managedSession) {
	for i, s := range sessionPool {
		if s == target {
			sessionPool = append(sessionPool[:i], sessionPool[i+1:]...)
			return
		}
	}
}

// ----------------------------------------------------
// IRAN
// ----------------------------------------------------

func startIran() {
	if bridgePort == 0 || syncPort == 0 || password == "" {
		logError("Missing arguments for Iran mode.")
		os.Exit(1)
	}
	printBanner("IRAN (FLEX LISTENER)")
	authKey = getAuthKey(password)

	activePorts := make(map[uint16]bool)
	var activePortsMu sync.Mutex
	var sessionRR uint64

	openNewPort := func(p uint16) {
		activePortsMu.Lock()
		if activePorts[p] {
			activePortsMu.Unlock()
			return
		}
		activePorts[p] = true
		activePortsMu.Unlock()

		listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", p))
		if err != nil {
			activePortsMu.Lock()
			activePorts[p] = false
			activePortsMu.Unlock()
			return
		}
		logInfo("Port Active: %d", p)

		go func() {
			for {
				clientConn, err := listener.Accept()
				if err != nil {
					select {
					case <-globalCtx.Done():
						return
					default:
						continue
					}
				}
				tuneSocket(clientConn)

				go func(c net.Conn) {
					// Feature 5: Session Failover — try up to 3 sessions
					var stream *smux.Stream
					maxRetries := 3

					for attempt := 0; attempt < maxRetries; attempt++ {
						poolMu.Lock()
						poolSize := uint64(len(sessionPool))
						if poolSize == 0 {
							poolMu.Unlock()
							if attempt == 0 {
								logWarn("No sessions available for port %d", p)
							}
							break
						}
						idx := atomic.AddUint64(&sessionRR, 1) % poolSize
						sess := sessionPool[idx]
						poolMu.Unlock()

						var err error
						stream, err = sess.OpenStream()
						if err == nil {
							break // success
						}
						logWarn("OpenStream failed on session %d (attempt %d/%d): %v", idx, attempt+1, maxRetries, err)
						stream = nil
					}

					if stream == nil {
						c.Close()
						return
					}

					if _, err := stream.Write(obfuscatePort(p, authKey)); err != nil {
						stream.Close()
						c.Close()
						return
					}

					proxyConn(c, stream)
				}(clientConn)
			}
		}()
	}

	// Port sync / manual ports
	go func() {
		if !autoSync {
			if manualPorts != "" {
				for _, pStr := range strings.Split(manualPorts, ",") {
					if p, err := strconv.Atoi(strings.TrimSpace(pStr)); err == nil {
						openNewPort(uint16(p))
					}
				}
				logInfo("Manual Ports Opened.")
			}
			return
		}

		listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", syncPort))
		if err != nil {
			return
		}
		logInfo("Auto-Sync Active on port %d", syncPort)

		for {
			rawConn, err := listener.Accept()
			if err != nil {
				select {
				case <-globalCtx.Done():
					return
				default:
					continue
				}
			}

			go func(c net.Conn) {
				authBuffer := make([]byte, 16)
				c.SetReadDeadline(time.Now().Add(5 * time.Second))
				if _, err := io.ReadFull(c, authBuffer); err != nil || string(authBuffer) != string(authKey) {
					c.Close()
					return
				}
				c.SetReadDeadline(time.Time{})

				countBuf := make([]byte, 1)
				if _, err := io.ReadFull(c, countBuf); err != nil {
					return
				}

				count := int(countBuf[0])
				if count > 0 {
					pBuf := make([]byte, count*2)
					if _, err := io.ReadFull(c, pBuf); err == nil {
						for i := 0; i < count; i++ {
							openNewPort(deobfuscatePort(pBuf[i*2:i*2+2], authKey))
						}
					}
				}
				c.Close()
			}(rawConn)
		}
	}()

	// Bridge listener
	bridgeListener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", bridgePort))
	if err != nil {
		logError("Bridge listener error: %v", err)
		os.Exit(1)
	}

	var globalCert tls.Certificate
	if antiDpi {
		globalCert, err = generateDummyCert()
		if err != nil {
			logError("Failed to generate dummy cert: %v", err)
			os.Exit(1)
		}
	}

	logInfo("Running... Bridge: %d | Sync: %d | Failover: 3 retries | Recycling: %s", bridgePort, syncPort, sessionTTL)

	for {
		rawConn, err := bridgeListener.Accept()
		if err != nil {
			select {
			case <-globalCtx.Done():
				logInfo("Shutdown signal received, waiting for active connections...")
				activeConns.Wait()
				logInfo("All connections drained. Goodbye!")
				return
			default:
				continue
			}
		}
		tuneSocket(rawConn)

		go func(c net.Conn) {

			var transportConn net.Conn = c

			if antiDpi {
				tlsConfig := &tls.Config{
					Certificates: []tls.Certificate{globalCert},
					MinVersion:   tls.VersionTLS12,
				}
				tlsSrv := tls.Server(c, tlsConfig)
				if err := tlsSrv.Handshake(); err != nil {
					c.Close()
					return
				}

				// Consume HTTP Decoy
				decoyBuf := make([]byte, 1024)
				tlsSrv.SetReadDeadline(time.Now().Add(5 * time.Second))
				n, err := tlsSrv.Read(decoyBuf)
				if err != nil || !strings.Contains(string(decoyBuf[:n]), "GET /") {
					c.Close()
					return
				}
				tlsSrv.SetReadDeadline(time.Time{})

				transportConn = tlsSrv
			}

			authBuffer := make([]byte, 16)
			transportConn.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.ReadFull(transportConn, authBuffer); err != nil || string(authBuffer) != string(authKey) {
				transportConn.Close()
				return
			}
			transportConn.SetReadDeadline(time.Time{})

			session, err := smux.Server(transportConn, newSmuxConfig())
			if err != nil {
				transportConn.Close()
				return
			}

			ms := &managedSession{Session: session, createdAt: time.Now()}
			poolMu.Lock()
			sessionPool = append(sessionPool, ms)
			poolMu.Unlock()
			logInfo("New bridge session established (total: %d)", len(sessionPool))

			go func() {
				<-session.CloseChan()
				poolMu.Lock()
				removeSessionLocked(ms)
				poolMu.Unlock()
				logWarn("Bridge session closed (remaining: %d)", len(sessionPool))
			}()
		}(rawConn)
	}
}

func main() {
	flag.Parse()

	// Feature 3: Graceful Shutdown
	globalCtx, globalStop = context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		logWarn("Received signal: %v — initiating graceful shutdown...", sig)
		globalStop()

		// Hard deadline: force exit after 10 seconds
		time.AfterFunc(10*time.Second, func() {
			logError("Graceful shutdown timed out, forcing exit!")
			os.Exit(1)
		})
	}()

	if mode == "europe" {
		startEurope()
	} else if mode == "iran" {
		startIran()
	} else {
		fmt.Println("Interactive Mode Setup")
		fmt.Println("1) Europe Server")
		fmt.Println("2) Iran Server")
		fmt.Print("Choice: ")
		var choice string
		fmt.Scanln(&choice)

		if choice == "1" {
			mode = "europe"
			fmt.Print("[?] Iran IP: ")
			fmt.Scanln(&iranIP)
			fmt.Print("[?] Tunnel Bridge Port: ")
			fmt.Scanln(&bridgePort)
			fmt.Print("[?] Port Sync Port: ")
			fmt.Scanln(&syncPort)
			fmt.Print("[?] Secret Password (must match Iran): ")
			fmt.Scanln(&password)
			startEurope()
		} else {
			mode = "iran"
			fmt.Print("[?] Tunnel Bridge Port: ")
			fmt.Scanln(&bridgePort)
			fmt.Print("[?] Port Sync Port: ")
			fmt.Scanln(&syncPort)
			fmt.Print("[?] Secret Password (must match Europe): ")
			fmt.Scanln(&password)
			var auto string
			fmt.Print("[?] Do you want Auto-Sync Xray ports? (y/n): ")
			fmt.Scanln(&auto)
			if strings.ToLower(auto) == "y" {
				autoSync = true
			} else {
				fmt.Print("[?] Enter ports manually (e.g. 80,443,2083): ")
				fmt.Scanln(&manualPorts)
			}
			startIran()
		}
	}
}
EOF

echo "[+] Compiling ATPlus..."
go build -o /usr/local/bin/atplus-core main.go

if [ ! -f "/usr/local/bin/atplus-core" ]; then
    echo "[-] Compilation failed! Check dependencies."
    exit 1
fi

chmod +x /usr/local/bin/atplus-core
echo "[+] Compilation successful!"
echo ""

echo "Select Server Type:"
echo "1) Europe Server (Exit)"
echo "2) Iran Server (Bridge)"
read -p "Choice [1/2]: " SERVER_TYPE

echo ""
echo "Select Connection Mode:"
echo "1) Maximum Speed (Raw TCP - No Obfuscation)"
echo "2) Maximum Security (Anti-DPI - uTLS + Fragmentation + Decoys)"
read -p "Choice [1/2]: " SECURITY_MODE

read -p "Enter Tunnel Bridge Port (e.g., 443): " BRIDGE_PORT
read -p "Enter Port Sync Port (e.g., 444): " SYNC_PORT
read -p "Enter Secret Password (must match on both servers): " PASSWORD

ANTI_DPI_FLAG=""
if [ "$SECURITY_MODE" == "2" ]; then
    ANTI_DPI_FLAG="--anti-dpi"
fi

if [ "$SERVER_TYPE" == "1" ]; then
    MODE="europe"
    read -p "Enter Iran Server IP: " IRAN_IP
    EXEC_CMD="/usr/local/bin/atplus-core --mode europe --iran-ip $IRAN_IP --bridge-port $BRIDGE_PORT --sync-port $SYNC_PORT --password \"$PASSWORD\" $ANTI_DPI_FLAG"
elif [ "$SERVER_TYPE" == "2" ]; then
    MODE="iran"
    read -p "Do you want Auto-Sync Xray ports? (y/n): " AUTO_SYNC_INPUT
    if [[ "$AUTO_SYNC_INPUT" == "y" || "$AUTO_SYNC_INPUT" == "Y" ]]; then
        EXEC_CMD="/usr/local/bin/atplus-core --mode iran --bridge-port $BRIDGE_PORT --sync-port $SYNC_PORT --password \"$PASSWORD\" --auto-sync $ANTI_DPI_FLAG"
    else
        read -p "Enter ports manually (e.g. 80,443,2083): " MANUAL_PORTS
        EXEC_CMD="/usr/local/bin/atplus-core --mode iran --bridge-port $BRIDGE_PORT --sync-port $SYNC_PORT --password \"$PASSWORD\" --manual-ports $MANUAL_PORTS $ANTI_DPI_FLAG"
    fi
else
    echo "Invalid choice. Exiting."
    exit 1
fi

echo "[+] Generating ATPlus Interactive CLI Menu..."
cat > /usr/local/bin/atplus << 'EOF'
#!/bin/bash
if [ "$1" != "" ]; then
    /usr/local/bin/atplus-core "$@"
    exit $?
fi

while true; do
	clear
	echo "###########################################"
	echo "#         🚀 ATPlus Manager Menu          #"
	echo "###########################################"
	echo "1) 📊 Show Service Status"
	echo "2) 📝 View Live Logs (journalctl)"
	echo "3) 🔄 Restart ATPlus Service"
	echo "4) 🛑 Stop ATPlus Service"
	echo "5) ▶️ Start ATPlus Service"
	echo "6) 🔄 Update / Reconfigure (Run Installer)"
	echo "7) 🗑️ Uninstall ATPlus Completely"
	echo "0) 🚪 Exit Menu"
	echo "-------------------------------------------"
	read -p "Choose an option [0-7]: " OPTION

	case $OPTION in
		1) clear; systemctl status atplus; read -n 1 -s -r -p "Press any key to continue..." ;;
		2) clear; echo "Press CTRL+C to stop viewing logs."; journalctl -u atplus -f ;;
		3) systemctl restart atplus; echo "Service Restarted."; read -n 1 -s -r -p "Press any key to continue..." ;;
		4) systemctl stop atplus; echo "Service Stopped."; read -n 1 -s -r -p "Press any key to continue..." ;;
		5) systemctl start atplus; echo "Service Started."; read -n 1 -s -r -p "Press any key to continue..." ;;
		6) 
		   clear
		   echo "Fetching Latest Installer from GitHub..."
		   curl -sL "https://raw.githubusercontent.com/ramin-mahmoodi/ATPlus/main/install.sh?v=$(date +%s)" -o /tmp/atplus_update.sh
		   bash /tmp/atplus_update.sh
		   exit 0
		   ;;
		7) 
		   clear
		   read -p "Are you sure you want to completely uninstall ATPlus? (y/n) " CONFIRM
		   if [[ "$CONFIRM" == "y" || "$CONFIRM" == "Y" ]]; then
			   echo "Uninstalling ATPlus..."
			   systemctl stop atplus
			   systemctl disable atplus
			   rm -f /etc/systemd/system/atplus.service
			   systemctl daemon-reload
			   rm -f /usr/local/bin/atplus*
			   rm -rf /usr/local/src/atplus
			   echo "ATPlus uninstalled successfully."
			   exit 0
		   fi
		   ;;
		0) clear; exit 0 ;;
		*) echo "Invalid option."; sleep 1 ;;
	esac
done
EOF
chmod +x /usr/local/bin/atplus

SERVICE_FILE="/etc/systemd/system/atplus.service"

cat > $SERVICE_FILE <<EOF
[Unit]
Description=ATPlus Reverse TCP Tunnel (Stable Edition)
After=network.target

[Service]
Type=simple
User=root
ExecStart=$EXEC_CMD
Restart=always
RestartSec=5
LimitNOFILE=1000000
Nice=-10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable atplus
systemctl restart atplus

echo ""
echo "✅ ATPlus V5.0 (Stable) has been installed and started as a service!"
echo "You can now manage ATPlus at any time by typing the following command:"
echo "👉  atplus"
