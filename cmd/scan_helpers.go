package cmd

import (
	"bufio"
	"strconv"
	"strings"

	"github.com/lowwattlabs/portkeep/internal/portscanner"
)

func parseSSOutput(output string) ([]portscanner.OpenPort, error) {
	var ports []portscanner.OpenPort
	scanner := bufio.NewScanner(strings.NewReader(output))

	headerDone := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Skip header lines
		if !headerDone {
			if strings.HasPrefix(line, "Netid") || strings.HasPrefix(line, "State") {
				continue
			}
			// First non-header line — start parsing
			if strings.HasPrefix(line, "tcp") || strings.HasPrefix(line, "udp") {
				headerDone = true
				// DON'T skip this line — fall through to parse it
			} else {
				continue
			}
		}

		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		proto := fields[0]
		if proto != "tcp" && proto != "udp" {
			continue
		}

		// Parse local address:port
		addrPort := strings.Split(fields[4], ":")
		if len(addrPort) != 2 {
			continue
		}
		portStr := addrPort[1]
		portNum, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}

		// Parse process info
		process := ""
		pid := 0
		if len(fields) > 6 {
			processInfo := strings.Join(fields[6:], " ")
			if strings.Contains(processInfo, "/") {
				parts := strings.SplitN(processInfo, "/", 2)
				pid, _ = strconv.Atoi(parts[0])
				process = parts[1]
			}
		}

		ports = append(ports, portscanner.OpenPort{
			Port:     portNum,
			Protocol: proto,
			Address:  addrPort[0],
			PID:      pid,
			Process:  process,
		})
	}

	return ports, nil
}