// Package threatintel provides 9-source live threat intelligence for port scoring.
//
// Sources requiring no authentication:
//   CISA-KEV         https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
//   EPSS             https://api.first.org/data/v1/epss (FIRST.org)
//   Feodo C2         https://feodotracker.abuse.ch/downloads/ipblocklist.json
//   Emerging Threats https://rules.emergingthreats.net/blockrules/compromised-ips.txt  (verify ET Pro license for commercial use)
//   Blocklist.de     https://lists.blocklist.de/lists/all.txt
//   DShield/SANS     https://feeds.dshield.org/block.txt  (CC BY-NC-SA 2.5 — non-commercial use only)
//
// Sources requiring a free abuse.ch Auth-Key (obtain at https://auth.abuse.ch):
//   ThreatFox        https://threatfox-api.abuse.ch/api/v1/
//   URLhaus          https://urlhaus-api.abuse.ch/v1/urls/recent/
//   MalwareBazaar    https://bazaar.abuse.ch/api/v1/
//     Note: MalwareBazaar provides malware hash metadata.
//     Direct port mapping is not available from this source;
//     data is cached for process-hash correlation planned in v0.2.
//
// Set ABUSE_CH_AUTH_KEY environment variable for the three abuse.ch sources.
// The other six sources sync without any key.
package threatintel

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	urlCISAKEV       = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	urlEPSS          = "https://api.first.org/data/v1/epss?limit=1000&order=!epss"
	urlFeodo         = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
	urlThreatFox     = "https://threatfox-api.abuse.ch/api/v1/"
	urlURLhaus       = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
	urlMalwareBazaar = "https://bazaar.abuse.ch/api/v1/"
	urlETCompromised = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
	urlBlocklistDE   = "https://lists.blocklist.de/lists/all.txt"
	urlDShield       = "https://feeds.dshield.org/block.txt"
)

// C2Port is a port (and optionally IP) known to be used as a command-and-control endpoint.
type C2Port struct {
	Port    int    `json:"port"`
	IP      string `json:"ip,omitempty"`
	Source  string `json:"source"`
	Malware string `json:"malware,omitempty"`
}

// BlockedIP is an IP or CIDR range flagged by a threat intelligence source.
// The IP field may contain a plain IPv4 address ("1.2.3.4") or CIDR notation ("1.2.3.0/24").
type BlockedIP struct {
	IP     string `json:"ip"`
	Source string `json:"source"`
	Note   string `json:"note,omitempty"`
}

// KEVEntry is one record from the CISA Known Exploited Vulnerabilities catalog.
type KEVEntry struct {
	CVEID   string `json:"cve_id"`
	Product string `json:"product"`
	Vendor  string `json:"vendor"`
	Added   string `json:"added"`
}

// SyncStatus records the outcome of syncing a single source.
type SyncStatus struct {
	Source   string `json:"source"`
	Status   string `json:"status"` // "ok", "skipped", "error"
	Detail   string `json:"detail,omitempty"`
	Count    int    `json:"count,omitempty"`
	SyncedAt string `json:"synced_at,omitempty"`
}

// DB is the aggregated threat intelligence database.
type DB struct {
	LastSync   string             `json:"last_sync"`
	C2Ports    []C2Port           `json:"c2_ports"`
	BlockedIPs []BlockedIP        `json:"blocked_ips"`
	KEVEntries []KEVEntry         `json:"kev_entries"`
	EPSSTop    map[string]float64 `json:"epss_top"` // cve_id -> probability score (top 1000 by score)
	Sources    []SyncStatus       `json:"sources"`
}

// EmptyDB returns an initialised but empty DB.
func EmptyDB() *DB {
	return &DB{EPSSTop: make(map[string]float64)}
}

// Load reads the on-disk cache. Returns EmptyDB on any error (e.g., not yet synced).
func Load(cacheDir string) *DB {
	data, err := os.ReadFile(filepath.Join(cacheDir, "db.json"))
	if err != nil {
		return EmptyDB()
	}
	db := &DB{EPSSTop: make(map[string]float64)}
	if err := json.Unmarshal(data, db); err != nil {
		return EmptyDB()
	}
	if db.EPSSTop == nil {
		db.EPSSTop = make(map[string]float64)
	}
	return db
}

// Save persists the DB to disk.
func (db *DB) Save(cacheDir string) error {
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}
	data, err := json.Marshal(db)
	if err != nil {
		return fmt.Errorf("marshal db: %w", err)
	}
	return os.WriteFile(filepath.Join(cacheDir, "db.json"), data, 0600)
}

// AgeString returns a human-readable description of how old the cached data is.
func (db *DB) AgeString() string {
	if db.LastSync == "" {
		return "not synced (run: portkeep sync)"
	}
	t, err := time.Parse(time.RFC3339, db.LastSync)
	if err != nil {
		return fmt.Sprintf("synced %s", db.LastSync)
	}
	age := time.Since(t)
	switch {
	case age < time.Hour:
		return fmt.Sprintf("synced %dm ago", int(age.Minutes()))
	case age < 24*time.Hour:
		return fmt.Sprintf("synced %dh ago", int(age.Hours()))
	default:
		return fmt.Sprintf("synced %dd ago (consider re-running portkeep sync)", int(age.Hours()/24))
	}
}

// C2Entries returns all C2Port records matching the given port number.
func (db *DB) C2Entries(port int) []C2Port {
	var out []C2Port
	for _, c := range db.C2Ports {
		if c.Port == port {
			out = append(out, c)
		}
	}
	return out
}

// IsBlockedIP reports whether the given IP appears in any threat intel blocklist.
// Supports both exact-match IPs and CIDR notation (e.g., from DShield /24 blocks).
func (db *DB) IsBlockedIP(ip string) (bool, string) {
	parsedIP := net.ParseIP(ip)
	for _, b := range db.BlockedIPs {
		if b.IP == ip {
			return true, b.Source
		}
		if parsedIP != nil && strings.Contains(b.IP, "/") {
			_, network, err := net.ParseCIDR(b.IP)
			if err == nil && network.Contains(parsedIP) {
				return true, b.Source
			}
		}
	}
	return false, ""
}

// KEVMatchesForService returns KEV entries whose product or vendor name contains
// the given hint string (case-insensitive substring match). Used to flag ports
// running software with known-exploited CVEs.
func (db *DB) KEVMatchesForService(hint string) []KEVEntry {
	if hint == "" {
		return nil
	}
	lower := strings.ToLower(hint)
	seen := make(map[string]bool)
	var out []KEVEntry
	for _, k := range db.KEVEntries {
		if seen[k.CVEID] {
			continue
		}
		if strings.Contains(strings.ToLower(k.Product), lower) ||
			strings.Contains(strings.ToLower(k.Vendor), lower) {
			out = append(out, k)
			seen[k.CVEID] = true
		}
	}
	return out
}

// EPSSScore returns the cached EPSS probability score for a CVE ID, or 0.0 if not cached.
func (db *DB) EPSSScore(cveID string) float64 {
	return db.EPSSTop[cveID]
}

// ─── SyncAll ─────────────────────────────────────────────────────────────────

// SyncAll fetches all 9 threat intel sources concurrently and saves the result.
//
//   abuseChKey  - Auth-Key for ThreatFox, URLhaus, MalwareBazaar.
//                 Pass "" to skip those 3 sources (the other 6 still sync).
//                 Obtain a free key at https://auth.abuse.ch
//   timeoutSec  - per-source HTTP timeout in seconds (0 → 30s)
func SyncAll(cacheDir string, abuseChKey string, timeoutSec int) ([]SyncStatus, error) {
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, fmt.Errorf("create cache dir: %w", err)
	}

	timeout := time.Duration(timeoutSec) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	newDB := EmptyDB()
	var mu sync.Mutex
	var wg sync.WaitGroup
	var statuses []SyncStatus

	addStatus := func(s SyncStatus) {
		mu.Lock()
		statuses = append(statuses, s)
		mu.Unlock()
	}

	appendC2 := func(c2 []C2Port) {
		mu.Lock()
		newDB.C2Ports = append(newDB.C2Ports, c2...)
		mu.Unlock()
	}

	appendBlocked := func(blocked []BlockedIP) {
		mu.Lock()
		newDB.BlockedIPs = append(newDB.BlockedIPs, blocked...)
		mu.Unlock()
	}

	// ── 1. CISA-KEV ────────────────────────────────────────────────────────
	wg.Add(1)
	go func() {
		defer wg.Done()
		entries, err := fetchCISAKEV(timeout)
		if err != nil {
			addStatus(SyncStatus{Source: "cisa-kev", Status: "error", Detail: err.Error()})
			return
		}
		mu.Lock()
		newDB.KEVEntries = entries
		mu.Unlock()
		addStatus(SyncStatus{
			Source: "cisa-kev", Status: "ok", Count: len(entries),
			SyncedAt: time.Now().UTC().Format(time.RFC3339),
		})
	}()

	// ── 2. EPSS (top 1000 CVEs by exploit probability) ─────────────────────
	wg.Add(1)
	go func() {
		defer wg.Done()
		scores, err := fetchEPSS(timeout)
		if err != nil {
			addStatus(SyncStatus{Source: "epss", Status: "error", Detail: err.Error()})
			return
		}
		mu.Lock()
		newDB.EPSSTop = scores
		mu.Unlock()
		addStatus(SyncStatus{
			Source: "epss", Status: "ok", Count: len(scores),
			SyncedAt: time.Now().UTC().Format(time.RFC3339),
		})
	}()

	// ── 3. Feodo C2 botnet tracker ──────────────────────────────────────────
	wg.Add(1)
	go func() {
		defer wg.Done()
		c2, err := fetchFeodo(timeout)
		if err != nil {
			addStatus(SyncStatus{Source: "feodo", Status: "error", Detail: err.Error()})
			return
		}
		appendC2(c2)
		addStatus(SyncStatus{
			Source: "feodo", Status: "ok", Count: len(c2),
			SyncedAt: time.Now().UTC().Format(time.RFC3339),
		})
	}()

	// ── 4. ThreatFox (abuse.ch Auth-Key required since 2025-06-30) ──────────
	wg.Add(1)
	go func() {
		defer wg.Done()
		if abuseChKey == "" {
			addStatus(SyncStatus{
				Source: "threatfox", Status: "skipped",
				Detail: "ABUSE_CH_AUTH_KEY not set — free key at https://auth.abuse.ch",
			})
			return
		}
		c2, blocked, err := fetchThreatFox(abuseChKey, timeout)
		if err != nil {
			addStatus(SyncStatus{Source: "threatfox", Status: "error", Detail: err.Error()})
			return
		}
		appendC2(c2)
		appendBlocked(blocked)
		addStatus(SyncStatus{
			Source: "threatfox", Status: "ok", Count: len(c2) + len(blocked),
			SyncedAt: time.Now().UTC().Format(time.RFC3339),
		})
	}()

	// ── 5. URLhaus (abuse.ch Auth-Key required since 2025-06-30) ────────────
	wg.Add(1)
	go func() {
		defer wg.Done()
		if abuseChKey == "" {
			addStatus(SyncStatus{
				Source: "urlhaus", Status: "skipped",
				Detail: "ABUSE_CH_AUTH_KEY not set — free key at https://auth.abuse.ch",
			})
			return
		}
		blocked, err := fetchURLhaus(abuseChKey, timeout)
		if err != nil {
			addStatus(SyncStatus{Source: "urlhaus", Status: "error", Detail: err.Error()})
			return
		}
		appendBlocked(blocked)
		addStatus(SyncStatus{
			Source: "urlhaus", Status: "ok", Count: len(blocked),
			SyncedAt: time.Now().UTC().Format(time.RFC3339),
		})
	}()

	// ── 6. MalwareBazaar (abuse.ch Auth-Key required since 2025-06-30) ──────
	// Provides malware hash/family metadata. No direct port data.
	// Cached for process-hash correlation (planned v0.2).
	wg.Add(1)
	go func() {
		defer wg.Done()
		if abuseChKey == "" {
			addStatus(SyncStatus{
				Source: "malwarebazaar", Status: "skipped",
				Detail: "ABUSE_CH_AUTH_KEY not set — free key at https://auth.abuse.ch",
			})
			return
		}
		count, err := fetchMalwareBazaar(abuseChKey, timeout, cacheDir)
		if err != nil {
			addStatus(SyncStatus{Source: "malwarebazaar", Status: "error", Detail: err.Error()})
			return
		}
		addStatus(SyncStatus{
			Source: "malwarebazaar", Status: "ok", Count: count,
			Detail:   "hash metadata cached (no direct port data — process correlation planned for v0.2)",
			SyncedAt: time.Now().UTC().Format(time.RFC3339),
		})
	}()

	// ── 7. Emerging Threats compromised hosts ────────────────────────────────
	wg.Add(1)
	go func() {
		defer wg.Done()
		blocked, err := fetchPlainIPList(urlETCompromised, "emerging-threats", timeout)
		if err != nil {
			addStatus(SyncStatus{Source: "emerging-threats", Status: "error", Detail: err.Error()})
			return
		}
		appendBlocked(blocked)
		addStatus(SyncStatus{
			Source: "emerging-threats", Status: "ok", Count: len(blocked),
			SyncedAt: time.Now().UTC().Format(time.RFC3339),
		})
	}()

	// ── 8. Blocklist.de attack list ──────────────────────────────────────────
	wg.Add(1)
	go func() {
		defer wg.Done()
		blocked, err := fetchPlainIPList(urlBlocklistDE, "blocklist.de", timeout)
		if err != nil {
			addStatus(SyncStatus{Source: "blocklist.de", Status: "error", Detail: err.Error()})
			return
		}
		appendBlocked(blocked)
		addStatus(SyncStatus{
			Source: "blocklist.de", Status: "ok", Count: len(blocked),
			SyncedAt: time.Now().UTC().Format(time.RFC3339),
		})
	}()

	// ── 9. DShield/SANS top attacking netblocks ──────────────────────────────
	wg.Add(1)
	go func() {
		defer wg.Done()
		blocked, err := fetchDShield(timeout)
		if err != nil {
			addStatus(SyncStatus{Source: "dshield-sans", Status: "error", Detail: err.Error()})
			return
		}
		appendBlocked(blocked)
		addStatus(SyncStatus{
			Source: "dshield-sans", Status: "ok", Count: len(blocked),
			SyncedAt: time.Now().UTC().Format(time.RFC3339),
		})
	}()

	wg.Wait()

	newDB.LastSync = time.Now().UTC().Format(time.RFC3339)
	newDB.Sources = statuses

	// Deduplicate BlockedIPs by IP field
	seen := make(map[string]bool)
	deduped := make([]BlockedIP, 0, len(newDB.BlockedIPs))
	for _, b := range newDB.BlockedIPs {
		if !seen[b.IP] {
			seen[b.IP] = true
			deduped = append(deduped, b)
		}
	}
	newDB.BlockedIPs = deduped

	if err := newDB.Save(cacheDir); err != nil {
		return statuses, fmt.Errorf("save cache: %w", err)
	}

	return statuses, nil
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

func doGet(url, authKey string, timeout time.Duration) ([]byte, error) {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if authKey != "" {
		req.Header.Set("Auth-Key", authKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20)) // cap at 64 MB
}

func doPost(url, authKey, body string, timeout time.Duration) ([]byte, error) {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest("POST", url, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if authKey != "" {
		req.Header.Set("Auth-Key", authKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 16<<20)) // cap at 16 MB
}

// ─── Source fetchers ──────────────────────────────────────────────────────────

func fetchCISAKEV(timeout time.Duration) ([]KEVEntry, error) {
	data, err := doGet(urlCISAKEV, "", timeout)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Vulnerabilities []struct {
			CveID         string `json:"cveID"`
			VendorProject string `json:"vendorProject"`
			Product       string `json:"product"`
			DateAdded     string `json:"dateAdded"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse CISA-KEV JSON: %w", err)
	}
	entries := make([]KEVEntry, 0, len(resp.Vulnerabilities))
	for _, v := range resp.Vulnerabilities {
		entries = append(entries, KEVEntry{
			CVEID:   v.CveID,
			Product: v.Product,
			Vendor:  v.VendorProject,
			Added:   v.DateAdded,
		})
	}
	return entries, nil
}

// fetchEPSS fetches the top-1000 CVEs by EPSS score from the FIRST.org API.
// EPSS tracks ~240,000+ CVEs; we cache the top 1000 by probability score.
func fetchEPSS(timeout time.Duration) (map[string]float64, error) {
	data, err := doGet(urlEPSS, "", timeout)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Data []struct {
			CVE  string `json:"cve"`
			EPSS string `json:"epss"` // returned as quoted decimal string by the API
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse EPSS JSON: %w", err)
	}
	scores := make(map[string]float64, len(resp.Data))
	for _, d := range resp.Data {
		if score, err := strconv.ParseFloat(d.EPSS, 64); err == nil {
			scores[d.CVE] = score
		}
	}
	return scores, nil
}

// fetchFeodo fetches the Feodo C2 botnet IP/port blocklist.
// Note: Feodo tracker lists active and recently offline C2 infrastructure. Entries may be offline status; these are retained for drift detection.
func fetchFeodo(timeout time.Duration) ([]C2Port, error) {
	data, err := doGet(urlFeodo, "", timeout)
	if err != nil {
		return nil, err
	}
	var entries []struct {
		IP      string `json:"ip_address"`
		Port    int    `json:"port"`
		Malware string `json:"malware"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parse Feodo JSON: %w", err)
	}
	var c2 []C2Port
	for _, e := range entries {
		if e.Port > 0 {
			c2 = append(c2, C2Port{
				Port:    e.Port,
				IP:      e.IP,
				Source:  "feodo",
				Malware: e.Malware,
			})
		}
	}
	return c2, nil
}

// fetchThreatFox queries the ThreatFox IOC API for recent IOCs (last 7 days).
// Requires a free Auth-Key from https://auth.abuse.ch (mandatory since 2025-06-30).
func fetchThreatFox(authKey string, timeout time.Duration) ([]C2Port, []BlockedIP, error) {
	data, err := doPost(urlThreatFox, authKey, `{"query":"get_iocs","days":7}`, timeout)
	if err != nil {
		return nil, nil, err
	}
	var resp struct {
		QueryStatus string `json:"query_status"`
		Data        []struct {
			IOCType  string `json:"ioc_type"`
			IOCValue string `json:"ioc_value"`
			Malware  string `json:"malware"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, nil, fmt.Errorf("parse ThreatFox JSON: %w", err)
	}
	if resp.QueryStatus == "no_results" {
		return nil, nil, nil
	}

	var c2 []C2Port
	var blocked []BlockedIP
	for _, d := range resp.Data {
		switch d.IOCType {
		case "ip:port":
			// format: "1.2.3.4:4444"
			if idx := strings.LastIndex(d.IOCValue, ":"); idx > 0 {
				ipPart := d.IOCValue[:idx]
				portPart := d.IOCValue[idx+1:]
				if port, err := strconv.Atoi(portPart); err == nil && port > 0 {
					c2 = append(c2, C2Port{
						Port:    port,
						IP:      ipPart,
						Source:  "threatfox",
						Malware: d.Malware,
					})
				}
			}
		case "ip":
			if isValidIPv4(d.IOCValue) {
				blocked = append(blocked, BlockedIP{
					IP:     d.IOCValue,
					Source: "threatfox",
					Note:   d.Malware,
				})
			}
		}
	}
	return c2, blocked, nil
}

// fetchURLhaus fetches recent malicious URLs from URLhaus.
// Only plain IPv4 hosts are extracted for the IP blocklist.
// Requires a free Auth-Key from https://auth.abuse.ch (mandatory since 2025-06-30).
func fetchURLhaus(authKey string, timeout time.Duration) ([]BlockedIP, error) {
	data, err := doGet(urlURLhaus, authKey, timeout)
	if err != nil {
		return nil, err
	}
	var resp struct {
		QueryStatus string `json:"query_status"`
		URLs        []struct {
			Host string `json:"host"`
		} `json:"urls"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse URLhaus JSON: %w", err)
	}

	seen := make(map[string]bool)
	var blocked []BlockedIP
	for _, u := range resp.URLs {
		if u.Host == "" || seen[u.Host] {
			continue
		}
		if isValidIPv4(u.Host) {
			seen[u.Host] = true
			blocked = append(blocked, BlockedIP{IP: u.Host, Source: "urlhaus"})
		}
	}
	return blocked, nil
}

// fetchMalwareBazaar fetches recent malware sample metadata.
// MalwareBazaar is a file-hash database; it does not provide port-level data.
// The response is stored in the cache for future process-hash correlation (v0.2).
// Requires a free Auth-Key from https://auth.abuse.ch (mandatory since 2025-06-30).
func fetchMalwareBazaar(authKey string, timeout time.Duration, cacheDir string) (int, error) {
	data, err := doPost(urlMalwareBazaar, authKey, `{"query":"get_recent","selector":"time"}`, timeout)
	if err != nil {
		return 0, err
	}
	var resp struct {
		QueryStatus string `json:"query_status"`
		Data        []json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return 0, fmt.Errorf("parse MalwareBazaar JSON: %w", err)
	}
	// Store raw sample metadata for future use; ignore write errors.
	hashPath := filepath.Join(cacheDir, "malwarebazaar_recent.json")
	_ = os.WriteFile(hashPath, data, 0600)
	return len(resp.Data), nil
}

// fetchPlainIPList fetches a newline-separated list of IPv4 addresses.
// Lines starting with '#' and blank lines are skipped.
func fetchPlainIPList(url, source string, timeout time.Duration) ([]BlockedIP, error) {
	data, err := doGet(url, "", timeout)
	if err != nil {
		return nil, err
	}
	var blocked []BlockedIP
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Some lists have "ip # comment" — take only the first token
		ip := strings.Fields(line)[0]
		if isValidIPv4(ip) {
			blocked = append(blocked, BlockedIP{IP: ip, Source: source})
		}
	}
	return blocked, sc.Err()
}

// fetchDShield fetches the SANS Internet Storm Center recommended block list.
// Format: tab-separated; columns include Start IP, End IP, Prefix, Attacks, ...
// Entries are stored as /24 CIDR ranges for use in subnet-match queries.
func fetchDShield(timeout time.Duration) ([]BlockedIP, error) {
	data, err := doGet(urlDShield, "", timeout)
	if err != nil {
		return nil, err
	}
	var blocked []BlockedIP
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "Start") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		startIP := fields[0]
		prefix := fields[2] // CIDR prefix length, e.g. "24"
		if !isValidIPv4(startIP) {
			continue
		}
		// Convert to CIDR notation: "1.2.3.0/24"
		cidr := fmt.Sprintf("%s/%s", startIP, prefix)
		if _, _, err := net.ParseCIDR(cidr); err == nil {
			blocked = append(blocked, BlockedIP{IP: cidr, Source: "dshield-sans"})
		}
	}
	return blocked, sc.Err()
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// isValidIPv4 reports whether s looks like a dotted-decimal IPv4 address.
func isValidIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}
