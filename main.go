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
	maxSmuxTunnels = 16

	bufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 32768)
		},
	}
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
#          🚀 ATPlus v4.1 (SMUX Raw)      #
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
[+] CPU-Optimized RAW Tunnel (No TLS Double-Encrypt)
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
	buf := bufferPool.Get().([]byte)
	io.CopyBuffer(dst, src, buf)
	bufferPool.Put(buf)
	src.Close()
	dst.Close()
}

// ----------------------------------------------------
// MULTIPLEXER FACTORY
// ----------------------------------------------------

func createEuropeMultiplexer() (*smux.Session, error) {
	rawConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", iranIP, bridgePort), 5*time.Second)
	if err != nil { return nil, err }
	tuneSocket(rawConn)

	rawConn.Write(authKey)

	smuxConfig := smux.DefaultConfig()
	smuxConfig.MaxReceiveBuffer = 4194304 * 2
	smuxConfig.MaxStreamBuffer = 4194304
	smuxConfig.KeepAliveInterval = 10 * time.Second
	smuxConfig.KeepAliveTimeout = 30 * time.Second
	session, err := smux.Client(rawConn, smuxConfig)
	if err != nil {
		rawConn.Close()
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
			time.Sleep(10 * time.Minute)
			poolMu.Lock()
			if len(sessionPool) > 0 {
				oldSession := sessionPool[0]
				sessionPool = sessionPool[1:]
				poolMu.Unlock()
				oldSession.Close()
			} else {
				poolMu.Unlock()
			}
		}
	}()

	go func() {
		for {
			poolMu.Lock()
			currentLinks := len(sessionPool)
			poolMu.Unlock()

			if currentLinks < maxSmuxTunnels {
				var wg sync.WaitGroup
				needed := maxSmuxTunnels - currentLinks
				for i := 0; i < needed; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						if session, err := createEuropeMultiplexer(); err == nil {
							poolMu.Lock()
							if len(sessionPool) < maxSmuxTunnels {
								sessionPool = append(sessionPool, session)
								go func(sess *smux.Session) {
									for {
										stream, err := sess.AcceptStream()
										if err != nil { break }
										go handleEuropeStream(stream)
									}
									poolMu.Lock()
									for k, s := range sessionPool {
										if s == sess {
											sessionPool = append(sessionPool[:k], sessionPool[k+1:]...)
											break
										}
									}
									poolMu.Unlock()
								}(session)
							} else {
								session.Close()
							}
							poolMu.Unlock()
						}
					}()
				}
				wg.Wait()
			}
			time.Sleep(200 * time.Millisecond)
		}
	}()

	go func() {
		for {
			if rawConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", iranIP, syncPort), 5*time.Second); err == nil {
				tuneSocket(rawConn)
				
				rawConn.Write(authKey)

				ports := getXrayPorts()
				count := len(ports)
				if count > 255 { count = 255 }
				buf := []byte{byte(count)}
				for i := 0; i < count; i++ {
					buf = append(buf, obfuscatePort(ports[i], authKey)...)
				}
				rawConn.Write(buf)
				rawConn.Close()
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
					if len(sessionPool) == 0 {
						poolMu.Unlock()
						c.Close()
						return
					}
					// Use round-robin instead of rand for better load balancing
					sess := sessionPool[0]
					sessionPool = append(sessionPool[1:], sess)
					poolMu.Unlock()

					stream, err := sess.OpenStream()
					if err != nil {
						c.Close()
						return
					}

					stream.Write(obfuscatePort(p, authKey))

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

		for {
			rawConn, err := listener.Accept()
			if err != nil { continue }
			
			go func(c net.Conn) {
				authBuffer := make([]byte, 16)
				c.SetReadDeadline(time.Now().Add(5 * time.Second))
				if _, err := io.ReadFull(c, authBuffer); err != nil || string(authBuffer) != string(authKey) {
					c.Close()
					return
				}
				c.SetReadDeadline(time.Time{})
				
				countBuf := make([]byte, 1)
				if _, err := io.ReadFull(c, countBuf); err != nil { return }
				
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

	bridgeListener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", bridgePort))
	if err != nil {
		fmt.Printf("❌ Bridge listener error: %v\n", err)
		os.Exit(1)
	}

	for {
		rawConn, err := bridgeListener.Accept()
		if err != nil { continue }
		tuneSocket(rawConn)

		go func(c net.Conn) {
			
			authBuffer := make([]byte, 16)
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.ReadFull(c, authBuffer); err != nil || string(authBuffer) != string(authKey) {
				c.Close()
				return
			}
			c.SetReadDeadline(time.Time{})
			
			smuxConfig := smux.DefaultConfig()
			smuxConfig.MaxReceiveBuffer = 4194304 * 2
			smuxConfig.MaxStreamBuffer = 4194304
			smuxConfig.KeepAliveInterval = 10 * time.Second
			smuxConfig.KeepAliveTimeout = 30 * time.Second
			session, err := smux.Server(c, smuxConfig)
			if err != nil {
				c.Close()
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

func main() {
	rand.Seed(time.Now().UnixNano())
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
