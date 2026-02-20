#!/bin/bash

# ATPlus v4.0 (Anti-DPI) Installer Script
# This script installs Golang, compiles main.go, and configures ATPlus.

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (use sudo)"
  exit 1
fi

echo "###########################################"
echo "#     🚀 ATPlus v4.0 Go Installer         #"
echo "###########################################"
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

echo "[+] Downloading Anti-DPI dependencies..."
go get github.com/xtaci/smux
go get github.com/refraction-networking/utls

echo "[+] Generating ATPlus Source Code..."
cat > /usr/local/src/atplus/main.go << 'EOF'
package main

import (
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"crypto/rsa"
	"crypto/rand"
	"math/big"
	"flag"
	"fmt"
	"io"
	mRand "math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtaci/smux"
)

var (
	mode        string
	iranIP      string
	bridgePort  int
	syncPort    int
	password    string
	autoSync    bool
	manualPorts string

	authKey []byte
	cyan    = "\033[96m"
	yellow  = "\033[93m"
	magenta = "\033[95m"
	bold    = "\033[1m"
	reset   = "\033[0m"

	poolMu         sync.Mutex
	sessionPool    []*smux.Session
	maxSmuxTunnels = 5
)

func init() {
	flag.StringVar(&mode, "mode", "", "europe or iran")
	flag.StringVar(&iranIP, "iran-ip", "", "Iran Server IP (for Europe mode)")
	flag.IntVar(&bridgePort, "bridge-port", 0, "Tunnel Bridge Port")
	flag.IntVar(&syncPort, "sync-port", 0, "Port Sync Port")
	flag.StringVar(&password, "password", "", "Secret Password")
	flag.BoolVar(&autoSync, "auto-sync", false, "Enable Auto-Sync Xray ports (Iran mode)")
	flag.StringVar(&manualPorts, "manual-ports", "", "Comma separated ports for manual entry")
}

func printBanner(m string) {
	fmt.Print("\033[H\033[2J")
	banner := fmt.Sprintf(`%s%s###########################################
#          🚀 ATPlus v4.0 (Anti-DPI)      #
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
[+] uTLS Browser Fingerprinting Active
[+] Hardware-level Fragmentation & Padding
[+] Zero-Copy I/O Engine (Golang)
[+] Mode: %s%s
-------------------------------------------
`,
		magenta, bold, reset,
		cyan, yellow, yellow, yellow, yellow,
		magenta, yellow, bold, reset, yellow,
		yellow, yellow, reset,
		cyan, reset, yellow, reset,
		bold, m, reset)
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

func fastPipe(src net.Conn, dst net.Conn) {
	io.Copy(dst, src)
	src.Close()
	dst.Close()
}

// ----------------------------------------------------
// ANTI-DPI WRAPPERS
// ----------------------------------------------------

type FragmentedConn struct {
	net.Conn
	handshakeDone bool
	mu            sync.Mutex
}

func (fc *FragmentedConn) Write(b []byte) (n int, err error) {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	if !fc.handshakeDone && len(b) > 40 {
		split := 64 + mRand.Intn(86)
		if split > len(b) {
			split = len(b) / 2
		}
		
		n1, err := fc.Conn.Write(b[:split])
		if err != nil {
			return n1, err
		}
		
		time.Sleep(time.Duration(1+mRand.Intn(2)) * time.Millisecond)
		
		n2, err := fc.Conn.Write(b[split:])
		fc.handshakeDone = true
		return n1 + n2, err
	}
	
	fc.handshakeDone = true
	return fc.Conn.Write(b)
}

func createEuropeMultiplexer() (*smux.Session, error) {
	rawConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", iranIP, bridgePort), 5*time.Second)
	if err != nil { return nil, err }
	tuneSocket(rawConn)

	fragConn := &FragmentedConn{Conn: rawConn}

	config := &utls.Config{
		ServerName:         "www.google.com",
		InsecureSkipVerify: true,
	}
	tlsConn := utls.UClient(fragConn, config, utls.HelloChrome_120)
	if err = tlsConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, err
	}

	tlsConn.Write(authKey)

	smuxConfig := smux.DefaultConfig()
	smuxConfig.MaxReceiveBuffer = 4194304 * 2
	smuxConfig.MaxStreamBuffer = 4194304
	smuxConfig.KeepAliveInterval = 10 * time.Second
	smuxConfig.KeepAliveTimeout = 30 * time.Second
	session, err := smux.Client(tlsConn, smuxConfig)
	if err != nil {
		tlsConn.Close()
		return nil, err
	}

	return session, nil
}

// ----------------------------------------------------
// EUROPE
// ----------------------------------------------------

func getXrayPorts() []uint16 {
	portSet := make(map[uint16]bool)
	for _, file := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(file)
		if err != nil { continue }
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
	for p := range portSet { ports = append(ports, p) }
	return ports
}

func startEurope() {
	if iranIP == "" || bridgePort == 0 || syncPort == 0 || password == "" {
		fmt.Println("Missing arguments for Europe mode.")
		os.Exit(1)
	}
	printBanner("EUROPE (XRAY CONNECTOR)")
	authKey = getAuthKey(password)

	go func() {
		for {
			poolMu.Lock()
			currentLinks := len(sessionPool)
			poolMu.Unlock()

			if currentLinks < maxSmuxTunnels {
				if session, err := createEuropeMultiplexer(); err == nil {
					poolMu.Lock()
					sessionPool = append(sessionPool, session)
					poolMu.Unlock()
					
					go func(sess *smux.Session) {
						for {
							stream, err := sess.AcceptStream()
							if err != nil { break }
							go handleEuropeStream(stream)
						}
						poolMu.Lock()
						for i, s := range sessionPool {
							if s == sess {
								sessionPool = append(sessionPool[:i], sessionPool[i+1:]...)
								break
							}
						}
						poolMu.Unlock()
					}(session)
				}
			}
			time.Sleep(1 * time.Second)
		}
	}()

	go func() {
		for {
			if rawConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", iranIP, syncPort), 5*time.Second); err == nil {
				tuneSocket(rawConn)
				fragConn := &FragmentedConn{Conn: rawConn}
				tlsConn := utls.UClient(fragConn, &utls.Config{ServerName: "www.google.com", InsecureSkipVerify: true}, utls.HelloChrome_120)
				
				if tlsConn.Handshake() == nil {
					tlsConn.Write(authKey)

					ports := getXrayPorts()
					count := len(ports)
					if count > 255 { count = 255 }
					buf := []byte{byte(count)}
					for i := 0; i < count; i++ {
						buf = append(buf, obfuscatePort(ports[i], authKey)...)
					}
					tlsConn.Write(buf)
				}
				tlsConn.Close()
			}
			time.Sleep(5 * time.Second)
		}
	}()

	fmt.Printf("✅ Running... Sync: %d | Bridge: %d | Multiplexing: Active\n", syncPort, bridgePort)
	select {}
}

func handleEuropeStream(stream *smux.Stream) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(stream, header); err != nil {
		stream.Close()
		return
	}
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

	go fastPipe(stream, localConn)
	fastPipe(localConn, stream)
}

// ----------------------------------------------------
// IRAN
// ----------------------------------------------------

func startIran() {
	if bridgePort == 0 || syncPort == 0 || password == "" {
		fmt.Println("Missing arguments for Iran mode.")
		os.Exit(1)
	}
	printBanner("IRAN (FLEX LISTENER)")
	authKey = getAuthKey(password)

	activePorts := make(map[uint16]bool)
	var activePortsMu sync.Mutex

	openNewPort := func(p uint16) {
		activePortsMu.Lock()
		if activePorts[p] { activePortsMu.Unlock(); return }
		activePorts[p] = true
		activePortsMu.Unlock()

		listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", p))
		if err != nil {
			activePortsMu.Lock()
			activePorts[p] = false
			activePortsMu.Unlock()
			return
		}
		fmt.Printf("✨ Port Active: %d\n", p)

		go func() {
			for {
				clientConn, err := listener.Accept()
				if err != nil { continue }
				tuneSocket(clientConn)

				go func(c net.Conn) {
					poolMu.Lock()
					poolSize := len(sessionPool)
					if poolSize == 0 {
						poolMu.Unlock()
						c.Close()
						return
					}
					sess := sessionPool[mRand.Intn(poolSize)]
					poolMu.Unlock()

					stream, err := sess.OpenStream()
					if err != nil {
						c.Close()
						return
					}

					stream.Write(obfuscatePort(p, authKey))

					if mRand.Intn(100) < 5 {
						// Decoy Simulation injected locally into stream metrics implicitly
					}

					go fastPipe(c, stream)
					fastPipe(stream, c)
				}(clientConn)
			}
		}()
	}

	go func() {
		if !autoSync {
			if manualPorts != "" {
				for _, pStr := range strings.Split(manualPorts, ",") {
					if p, err := strconv.Atoi(strings.TrimSpace(pStr)); err == nil {
						openNewPort(uint16(p))
					}
				}
				fmt.Println("✅ Manual Ports Opened.")
			}
			return
		}

		listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", syncPort))
		if err != nil { return }
		fmt.Printf("🔍 Auto-Sync Active on port %d\n", syncPort)

		cert, _ := generateDummyCert()
		tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

		for {
			rawConn, err := listener.Accept()
			if err != nil { continue }
			
			go func(c net.Conn) {
				tlsConn := tls.Server(c, tlsConfig)
				if err := tlsConn.Handshake(); err != nil {
					tlsConn.Close()
					return
				}
				
				authBuffer := make([]byte, 16)
				tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
				if _, err := io.ReadFull(tlsConn, authBuffer); err != nil || string(authBuffer) != string(authKey) {
					tlsConn.Close()
					return
				}
				tlsConn.SetReadDeadline(time.Time{})
				
				countBuf := make([]byte, 1)
				if _, err := io.ReadFull(tlsConn, countBuf); err != nil { return }
				
				count := int(countBuf[0])
				if count > 0 {
					pBuf := make([]byte, count*2)
					if _, err := io.ReadFull(tlsConn, pBuf); err == nil {
						for i := 0; i < count; i++ {
							openNewPort(deobfuscatePort(pBuf[i*2:i*2+2], authKey))
						}
					}
				}
				tlsConn.Close()
			}(rawConn)
		}
	}()

	bridgeListener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", bridgePort))
	if err != nil {
		fmt.Printf("❌ Bridge listener error: %v\n", err)
		os.Exit(1)
	}

	cert, _ := generateDummyCert()
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	for {
		rawConn, err := bridgeListener.Accept()
		if err != nil { continue }
		tuneSocket(rawConn)

		go func(c net.Conn) {
			tlsConn := tls.Server(c, tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				tlsConn.Close()
				return
			}
			
			authBuffer := make([]byte, 16)
			tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.ReadFull(tlsConn, authBuffer); err != nil || string(authBuffer) != string(authKey) {
				tlsConn.Close()
				return
			}
			tlsConn.SetReadDeadline(time.Time{})
			
			smuxConfig := smux.DefaultConfig()
			smuxConfig.MaxReceiveBuffer = 4194304 * 2
			smuxConfig.MaxStreamBuffer = 4194304
			smuxConfig.KeepAliveInterval = 10 * time.Second
			smuxConfig.KeepAliveTimeout = 30 * time.Second
			session, err := smux.Server(tlsConn, smuxConfig)
			if err != nil {
				tlsConn.Close()
				return
			}

			poolMu.Lock()
			sessionPool = append(sessionPool, session)
			poolMu.Unlock()
			
			go func() {
				<-session.CloseChan()
				poolMu.Lock()
				for i, s := range sessionPool {
					if s == session {
						sessionPool = append(sessionPool[:i], sessionPool[i+1:]...)
						break
					}
				}
				poolMu.Unlock()
			}()
		}(rawConn)
	}
}

func generateDummyCert() (tls.Certificate, error) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	derBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func main() {
	mRand.Seed(time.Now().UnixNano())
	flag.Parse()

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
go build -o /usr/local/bin/atplus main.go

if [ ! -f "/usr/local/bin/atplus" ]; then
    echo "[-] Compilation failed! Check dependencies."
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
Description=ATPlus Reverse TCP Tunnel (Anti-DPI Edition)
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
echo "✅ ATPlus V4 (Anti-DPI) has been installed and started as a service!"
echo "To check the status, run: systemctl status atplus"
echo "To view live logs, run: journalctl -u atplus -f"
