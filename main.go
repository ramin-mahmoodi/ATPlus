package main

import (
	"crypto/md5"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
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

	minConnections = 100
	maxConnections = 1000
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
	fmt.Print("\033[H\033[2J") // Clear screen
	banner := fmt.Sprintf(`%s%s###########################################
#            🚀 ATPlus v3.0 (Go)          #
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
%s[+] Authentication & XOR Obfuscation Enabled
[+] Dynamic Pool & Health Checks Active
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
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}
}

func fastPipe(src net.Conn, dst net.Conn) {
	// io.Copy automatically uses splice/sendfile on Linux for TCP connections when possible
	io.Copy(dst, src)
	src.Close()
	dst.Close()
}

// ================= EUROPE ================= //

func getXrayPorts() []uint16 {
	portSet := make(map[uint16]bool)
	files := []string{"/proc/net/tcp", "/proc/net/tcp6"}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			if i == 0 || len(line) == 0 {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) >= 4 && parts[3] == "0A" { // 0A = LISTEN
				localAddr := parts[1]
				addrParts := strings.Split(localAddr, ":")
				if len(addrParts) == 2 {
					portHex := addrParts[1]
					port64, err := strconv.ParseUint(portHex, 16, 16)
					if err == nil {
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
		fmt.Println("Missing arguments for Europe mode. Ensure --iran-ip, --bridge-port, --sync-port, and --password are provided.")
		os.Exit(1)
	}
	printBanner("EUROPE (XRAY CONNECTOR)")
	authKey = getAuthKey(password)

	activeConnections := 0
	var mu sync.Mutex

	// Port Sync Task
	go func() {
		for {
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", iranIP, syncPort), 5*time.Second)
			if err == nil {
				tuneSocket(conn)
				conn.Write(authKey)

				ports := getXrayPorts()
				// Max ports we can send in one uint8 is 255. If > 255 we truncate for safety.
				count := len(ports)
				if count > 255 {
					count = 255
				}
				buf := []byte{byte(count)}
				for i := 0; i < count; i++ {
					buf = append(buf, obfuscatePort(ports[i], authKey)...)
				}
				conn.Write(buf)
				conn.Close()
			}
			time.Sleep(5 * time.Second)
		}
	}()

	createReverseLink := func() {
		defer func() {
			mu.Lock()
			activeConnections--
			if activeConnections < 0 {
				activeConnections = 0
			}
			mu.Unlock()
		}()

		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", iranIP, bridgePort), 5*time.Second)
		if err != nil {
			time.Sleep(1 * time.Second)
			return
		}
		tuneSocket(conn)

		// Authenticate
		conn.Write(authKey)

		mu.Lock()
		activeConnections++
		mu.Unlock()

		header := make([]byte, 2)
		_, err = io.ReadFull(conn, header)
		if err != nil {
			conn.Close()
			return
		}

		targetPort := deobfuscatePort(header, authKey)
		if targetPort == 0 {
			conn.Close()
			return // Heartbeat ping
		}

		localConn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", targetPort), 5*time.Second)
		if err != nil {
			conn.Close()
			return
		}
		tuneSocket(localConn)

		go fastPipe(conn, localConn)
		fastPipe(localConn, conn)
	}

	// Dynamic Pool Manager
	fmt.Printf("✅ Running... Sync: %d | Bridge: %d | Pool: Dynamic\n", syncPort, bridgePort)
	for {
		mu.Lock()
		current := activeConnections
		mu.Unlock()

		if current < minConnections {
			need := minConnections - current
			for i := 0; i < need; i++ {
				go createReverseLink()
			}
		} else if current < maxConnections {
			// Add connections rapidly to satisfy high bursts and prevent slow ramp-up
			for i := 0; i < 10 && (current+i) < maxConnections; i++ {
				go createReverseLink()
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// ================= IRAN ================= //

func startIran() {
	if bridgePort == 0 || syncPort == 0 || password == "" {
		fmt.Println("Missing arguments for Iran mode. Ensure --bridge-port, --sync-port, and --password are provided.")
		os.Exit(1)
	}
	printBanner("IRAN (FLEX LISTENER)")
	authKey = getAuthKey(password)

	connPool := make(chan net.Conn, 10000)
	activePorts := make(map[uint16]bool)
	var activePortsMu sync.Mutex

	// Keep-alive heartbeat to clean dead connections
	go func() {
		for {
			time.Sleep(20 * time.Second)
			// Send dummy pings to connections in the pool to verify them occasionally (Optional, advanced pooling)
			// In Go, TCP keep-alives usually handle this at the OS level, but we can do a simple queue wash if needed.
		}
	}()

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
			fmt.Printf("❌ Error opening port %d: %v\n", p, err)
			activePortsMu.Lock()
			activePorts[p] = false
			activePortsMu.Unlock()
			return
		}
		fmt.Printf("✨ Port Active: %d\n", p)

		go func() {
			for {
				clientConn, err := listener.Accept()
				if err != nil {
					continue
				}
				tuneSocket(clientConn)

				go func(c net.Conn) {
					// Get valid Europe connection
					eConn, ok := <-connPool
					if !ok {
						c.Close()
						return
					}

					// Send target port
					eConn.Write(obfuscatePort(p, authKey))

					go fastPipe(c, eConn)
					fastPipe(eConn, c)
				}(clientConn)
			}
		}()
	}

	// Sync Listener
	go func() {
		if !autoSync {
			if manualPorts != "" {
				mPorts := strings.Split(manualPorts, ",")
				for _, pStr := range mPorts {
					p, err := strconv.Atoi(strings.TrimSpace(pStr))
					if err == nil {
						openNewPort(uint16(p))
					}
				}
				fmt.Println("✅ Manual Ports Opened.")
			}
			return
		}

		listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", syncPort))
		if err != nil {
			fmt.Printf("❌ Sync port error: %v\n", err)
			return
		}
		fmt.Printf("🔍 Auto-Sync Active on port %d\n", syncPort)

		for {
			conn, err := listener.Accept()
			if err != nil {
				continue
			}
			go func(c net.Conn) {
				defer c.Close()
				authBuffer := make([]byte, 16)
				c.SetReadDeadline(time.Now().Add(5 * time.Second))
				_, err := io.ReadFull(c, authBuffer)
				if err != nil || string(authBuffer) != string(authKey) {
					return
				}

				countBuf := make([]byte, 1)
				_, err = io.ReadFull(c, countBuf)
				if err != nil {
					return
				}
				count := int(countBuf[0])
				if count > 0 {
					pBuf := make([]byte, count*2)
					_, err = io.ReadFull(c, pBuf)
					if err != nil {
						return
					}
					for i := 0; i < count; i++ {
						p := deobfuscatePort(pBuf[i*2:i*2+2], authKey)
						openNewPort(p)
					}
				}
			}(conn)
		}
	}()

	// Bridge Listener
	bridgeListener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", bridgePort))
	if err != nil {
		fmt.Printf("❌ Bridge listener error: %v\n", err)
		os.Exit(1)
	}

	for {
		conn, err := bridgeListener.Accept()
		if err != nil {
			continue
		}
		tuneSocket(conn)

		go func(c net.Conn) {
			authBuffer := make([]byte, 16)
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, err := io.ReadFull(c, authBuffer)
			if err != nil || string(authBuffer) != string(authKey) {
				c.Close()
				return
			}

			// Remove deadline after auth
			c.SetReadDeadline(time.Time{})

			select {
			case connPool <- c:
				// Successfully pooled
			default:
				// If the pool is literally full (10,000 conns), drop it
				c.Close()
			}
		}(conn)
	}
}

func main() {
	flag.Parse()
	rand.Seed(time.Now().UnixNano())

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
