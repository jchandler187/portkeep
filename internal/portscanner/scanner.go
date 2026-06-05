// Package portscanner discovers open listening ports on the local host.
package portscanner

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// OpenPort describes a single listening port.
type OpenPort struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // "tcp" or "udp"
	Address  string `json:"address"`  // listening IP
	PID      int    `json:"pid,omitempty"`
	Process  string `json:"process,omitempty"`
}

// Scan returns all listening TCP (and UDP where detectable) ports on this host.
func Scan() ([]OpenPort, error) {
	if runtime.GOOS == "linux" {
		return scanLinux()
	}
	return scanNetstat()
}

// ─── Linux: parse /proc/net/tcp[6] ─────────────────────────────────────────

func scanLinux() ([]OpenPort, error) {
	var all []OpenPort

	tcp4, err := parseProcNetTCP("/proc/net/tcp", "tcp", false)
	if err == nil {
		all = append(all, tcp4...)
	}

	tcp6, err := parseProcNetTCP("/proc/net/tcp6", "tcp", true)
	if err == nil {
		all = append(all, tcp6...)
	}

	udp4, err := parseProcNetTCP("/proc/net/udp", "udp", false)
	if err == nil {
		all = append(all, udp4...)
	}

	// Deduplicate by port+proto (tcp6 often duplicates tcp4 when listening on ::)
	seen := make(map[string]bool)
	var deduped []OpenPort
	for _, p := range all {
		key := fmt.Sprintf("%d/%s", p.Port, p.Protocol)
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, p)
		}
	}

	// Resolve PIDs and process names via /proc inode matching
	resolveProcInfo(deduped, "tcp")
	resolveProcInfo(deduped, "udp")

	return deduped, nil
}

// parseProcNetTCP parses a /proc/net/tcp or /proc/net/tcp6 file.
// State 0A = TCP_LISTEN; for UDP state 07 = UNCONN (listening).
func parseProcNetTCP(path, proto string, ipv6 bool) ([]OpenPort, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var ports []OpenPort
	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header line

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		state := fields[3]
		// TCP: 0A=LISTEN; UDP: 07=UNCONN
		if proto == "tcp" && state != "0A" {
			continue
		}
		if proto == "udp" && state != "07" {
			continue
		}

		localAddr := fields[1]
		parts := strings.SplitN(localAddr, ":", 2)
		if len(parts) != 2 {
			continue
		}

		portNum, err := strconv.ParseInt(parts[1], 16, 32)
		if err != nil {
			continue
		}

		var ip string
		if ipv6 {
			ip = hexToIPv6(parts[0])
		} else {
			ip = hexToIPv4(parts[0])
		}

		ports = append(ports, OpenPort{
			Port:     int(portNum),
			Protocol: proto,
			Address:  ip,
		})
	}

	return ports, scanner.Err()
}

// hexToIPv4 converts a little-endian hex IPv4 string (e.g. "0100007F") to "127.0.0.1".
func hexToIPv4(h string) string {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 4 {
		return "0.0.0.0"
	}
	val := binary.LittleEndian.Uint32(b)
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, val)
	return ip.String()
}

// hexToIPv6 converts a /proc/net/tcp6 address (32 hex chars, little-endian groups) to an IP string.
func hexToIPv6(h string) string {
	if len(h) != 32 {
		return "::"
	}
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 16 {
		return "::"
	}
	// Each 4-byte group is little-endian; reverse each group.
	for i := 0; i < 16; i += 4 {
		b[i], b[i+3] = b[i+3], b[i]
		b[i+1], b[i+2] = b[i+2], b[i+1]
	}
	return net.IP(b).String()
}

// ─── Fallback: parse netstat output ────────────────────────────────────────

func scanNetstat() ([]OpenPort, error) {
	// Try "ss" first (modern Linux fallback), then "netstat"
	out, err := exec.Command("ss", "-tlnpH").Output()
	if err == nil {
		return parseSS(out), nil
	}

	out, err = exec.Command("netstat", "-an", "-p", "tcp").Output()
	if err != nil {
		return nil, fmt.Errorf("no port scan method available (tried ss, netstat): %w", err)
	}
	return parseNetstat(out, "tcp"), nil
}

// parseSS parses `ss -tlnpH` output.
// Columns: State, Recv-Q, Send-Q, Local Address:Port, Peer Address:Port, ...
func parseSS(data []byte) []OpenPort {
	var ports []OpenPort
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		localField := fields[3] // "0.0.0.0:22" or "[::]:22"
		port, addr := splitAddrPort(localField)
		if port > 0 {
			ports = append(ports, OpenPort{Port: port, Protocol: "tcp", Address: addr})
		}
	}
	return ports
}

// parseNetstat parses `netstat -an` output for a given protocol.
func parseNetstat(data []byte, proto string) []OpenPort {
	var ports []OpenPort
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		lower := strings.ToLower(line)
		if !strings.Contains(lower, "listen") {
			continue
		}
		fields := strings.Fields(line)
		// Typical: Proto Recv-Q Send-Q Local Foreign State
		if len(fields) < 4 {
			continue
		}
		// Find the Local Address field (index 3 on Linux, index 3 on macOS)
		localField := fields[3]
		port, addr := splitAddrPort(localField)
		if port > 0 {
			ports = append(ports, OpenPort{Port: port, Protocol: proto, Address: addr})
		}
	}
	return ports
}

// splitAddrPort parses "addr:port" or "[::]:port" returning port and addr.
func splitAddrPort(s string) (int, string) {
	// Handle IPv6 brackets: [::1]:22 → "::1", 22
	if strings.HasPrefix(s, "[") {
		end := strings.LastIndex(s, "]:")
		if end < 0 {
			return 0, ""
		}
		addr := s[1:end]
		portStr := s[end+2:]
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return 0, ""
		}
		return port, addr
	}
	// IPv4: "0.0.0.0:22" or "*:22"
	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return 0, ""
	}
	addr := s[:idx]
	portStr := s[idx+1:]
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, ""
	}
	return port, addr
}

// resolveProcInfo walks /proc to find which PID owns each listening socket inode.
func resolveProcInfo(ports []OpenPort, proto string) {
	portMap := make(map[int][]int)
	for i, p := range ports {
		if p.Protocol == proto {
			portMap[p.Port] = append(portMap[p.Port], i)
		}
	}
	if len(portMap) == 0 {
		return
	}

	// Pre-build inode→port map by reading /proc/net/{tcp,udp} ONCE
	inodeToPort := buildInodeMap(proto, portMap)

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		procName := processName(string(cmdline))

		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fdEntries, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		for _, fd := range fdEntries {
			link, err := os.Readlink(fmt.Sprintf("%s/%s", fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inodeStr := strings.TrimPrefix(link, "socket:[")
			inodeStr = strings.TrimRight(inodeStr, "]")
			inode, err := strconv.ParseUint(inodeStr, 10, 64)
			if err != nil {
				continue
			}

			if portNum, ok := inodeToPort[inode]; ok {
				if indices, ok2 := portMap[portNum]; ok2 {
					for _, idx := range indices {
						if ports[idx].PID == 0 {
							ports[idx].PID = pid
							ports[idx].Process = procName
						}
					}
				}
			}
		}
	}
}

// buildInodeMap reads /proc/net/{tcp,udp} ONCE and returns inode→port map.
func buildInodeMap(proto string, portMap map[int][]int) map[uint64]int {
	result := make(map[uint64]int)
	path := "/proc/net/" + proto
	f, err := os.Open(path)
	if err != nil {
		return result
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		localAddr := fields[1]
		parts := strings.SplitN(localAddr, ":", 2)
		if len(parts) != 2 {
			continue
		}
		portNum, err := strconv.ParseInt(parts[1], 16, 32)
		if err != nil {
			continue
		}
		if _, ok := portMap[int(portNum)]; !ok {
			continue
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			continue
		}
		result[inode] = int(portNum)
	}
	return result
}

// processName extracts the basename from a /proc/PID/cmdline string.
func processName(cmdline string) string {
	if cmdline == "" {
		return ""
	}
	parts := strings.SplitN(cmdline, "\x00", 2)
	exe := parts[0]
	idx := strings.LastIndex(exe, "/")
	if idx >= 0 {
		return exe[idx+1:]
	}
	return exe
}
