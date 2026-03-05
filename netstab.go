package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// ── constants ────────────────────────────────────────────────────────────────

const (
	pingTarget   = "1.1.1.1"
	pingCount    = 20
	pingDeadline = 3 * time.Second
	pingInterval = 50 * time.Millisecond
	bufferSize   = 1500
	cfBase       = "https://speed.cloudflare.com"
	httpTimeout  = 30 * time.Second

	// systemPATH is a fixed search path used when resolving external tool
	// binaries. It replaces the inherited $PATH to prevent CWE-426 (Untrusted
	// Search Path / PATH hijacking): a compromised environment could place a
	// malicious `iw` or `ethtool` earlier in $PATH, which would otherwise
	// execute with the elevated privileges this binary requires.
	systemPATH = "/usr/sbin:/usr/bin:/sbin:/bin"
)

// lookupTool resolves the absolute path of an external binary using only the
// fixed systemPATH, then verifies the result is an absolute path. It returns
// the name unchanged (falling back to Go's standard PATH search) if the binary
// is not found in systemPATH, so the caller can still surface a meaningful
// "command not found" error.
func lookupTool(name string) string {
	orig := os.Getenv("PATH")
	os.Setenv("PATH", systemPATH) //nolint:errcheck — no error path on Linux
	resolved, err := exec.LookPath(name)
	os.Setenv("PATH", orig) //nolint:errcheck
	if err != nil || !strings.HasPrefix(resolved, "/") {
		return name
	}
	return resolved
}

// ── speed test config ─────────────────────────────────────────────────────────

// speedConfig controls how many samples are collected and at what payload size.
// The lowest sample is always trimmed before the median is taken to reduce
// TCP slow-start bias.
type speedConfig struct {
	dlSamples int
	ulSamples int
	dlBytes   int
	ulBytes   int
}

var (
	// speedDefault is the standard ~10 s preset.
	speedDefault = speedConfig{dlSamples: 5, ulSamples: 5, dlBytes: 10_000_000, ulBytes: 10_000_000}
	// speedThorough is the ~20 s preset for fast connections.
	speedThorough = speedConfig{dlSamples: 8, ulSamples: 6, dlBytes: 25_000_000, ulBytes: 25_000_000}
)

// ── result types ─────────────────────────────────────────────────────────────

type statusResult struct {
	online    bool
	localIP   net.IP
	iface     string
	ifaceType string // "wifi" | "ethernet" | "unknown"
	publicIP  string
}

type strengthResult struct {
	signalDBm  int    // WiFi only; valid only when signalOK is true
	signalOK   bool   // true if a dBm reading was successfully obtained
	linkMbps   int    // ethernet negotiated speed; 0 means not available
	signalDesc string // human-readable quality label
}

type speedResult struct {
	downloadMbps float64
	uploadMbps   float64
}

type stabilityResult struct {
	sent       int
	received   int
	packetLoss float64
	minMs      float64
	avgMs      float64
	maxMs      float64
	jitterMs   float64
}

// ── 1. Connection status ──────────────────────────────────────────────────────

func checkStatus() statusResult {
	r := statusResult{}

	// Discover the outbound interface and local IP via a UDP "dial" (no packet sent).
	conn, err := net.Dial("udp", "1.1.1.1:80")
	if err != nil {
		return r
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	r.localIP = localAddr.IP
	r.online = true

	// Match the local IP to a named interface.
	ifaces, err := net.Interfaces()
	if err != nil {
		return r
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.Equal(localAddr.IP) {
				r.iface = iface.Name
				r.ifaceType = ifaceType(iface.Name)
			}
		}
	}

	// Fetch public IP from Cloudflare's trace endpoint (plain text, tiny).
	r.publicIP = fetchPublicIP()
	return r
}

// ifaceType classifies an interface name heuristically.
func ifaceType(name string) string {
	name = strings.ToLower(name)
	switch {
	case strings.HasPrefix(name, "wl") || strings.HasPrefix(name, "wlan") || strings.HasPrefix(name, "wifi"):
		return "wifi"
	case strings.HasPrefix(name, "eth") || strings.HasPrefix(name, "en") || strings.HasPrefix(name, "eno") || strings.HasPrefix(name, "enp") || strings.HasPrefix(name, "ens"):
		return "ethernet"
	default:
		return "unknown"
	}
}

// fetchPublicIP retrieves the public IP from Cloudflare's trace endpoint.
func fetchPublicIP() string {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://1.1.1.1/cdn-cgi/trace")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "ip=") {
			return strings.TrimPrefix(line, "ip=")
		}
	}
	return ""
}

// ── 2. Connection strength ────────────────────────────────────────────────────

func checkStrength(iface, ifaceType string) strengthResult {
	r := strengthResult{}
	if iface == "" {
		return r
	}
	switch ifaceType {
	case "wifi":
		r.signalDBm, r.signalOK, r.signalDesc = wifiSignal(iface)
	case "ethernet":
		r.linkMbps = ethernetSpeed(iface)
	}
	return r
}

// wifiSignal reads signal strength via `iw dev <iface> link`.
// Returns signal level in dBm and a quality description.
// /proc/net/wireless is not used because it is absent on modern kernels
// using cfg80211/mac80211 drivers.
func wifiSignal(iface string) (int, bool, string) {
	out, err := exec.Command(lookupTool("iw"), "dev", iface, "link").Output()
	if err != nil {
		return 0, false, "unavailable"
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "signal:") {
			continue
		}
		// e.g. "signal: -54 dBm"
		val := strings.TrimPrefix(line, "signal:")
		val = strings.TrimSpace(val)
		val = strings.TrimSuffix(val, " dBm")
		dbm, err := strconv.Atoi(strings.TrimSpace(val))
		if err != nil {
			continue
		}
		return dbm, true, signalQuality(dbm)
	}
	return 0, false, "unavailable"
}

// signalQuality converts a dBm value to a human-readable label.
func signalQuality(dbm int) string {
	switch {
	case dbm >= -50:
		return "Excellent"
	case dbm >= -60:
		return "Good"
	case dbm >= -70:
		return "Fair"
	case dbm >= -80:
		return "Poor"
	default:
		return "Very Poor"
	}
}

// ethernetSpeed reads the negotiated link speed via ethtool.
func ethernetSpeed(iface string) int {
	out, err := exec.Command(lookupTool("ethtool"), iface).Output()
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Speed:") {
			// e.g. "Speed: 1000Mb/s" or "Speed: 10000Mb/s"
			val := strings.TrimPrefix(line, "Speed:")
			val = strings.TrimSpace(val)
			val = strings.TrimSuffix(val, "Mb/s")
			mbps, err := strconv.Atoi(strings.TrimSpace(val))
			if err != nil {
				return 0
			}
			return mbps
		}
	}
	return 0
}

// ── 3. Speed test ─────────────────────────────────────────────────────────────

// speedMeasurement holds a single sample's bytes and duration.
type speedMeasurement struct {
	bytes    int64
	duration time.Duration
}

func (m speedMeasurement) mbps() float64 {
	if m.duration == 0 {
		return 0
	}
	return float64(m.bytes) * 8 / m.duration.Seconds() / 1e6
}

func runSpeedTest(cfg speedConfig) speedResult {
	fmt.Print("  Measuring download")
	dlMbps := measureDownload(cfg)
	fmt.Println()

	fmt.Print("  Measuring upload")
	ulMbps := measureUpload(cfg)
	fmt.Println()

	return speedResult{
		downloadMbps: dlMbps,
		uploadMbps:   ulMbps,
	}
}

// measureDownload benchmarks download speed using Cloudflare's __down endpoint.
// It collects cfg.dlSamples measurements at cfg.dlBytes each, trims the lowest
// (TCP slow-start bias), and returns the median of the remainder.
func measureDownload(cfg speedConfig) float64 {
	client := &http.Client{Timeout: httpTimeout}
	var samples []float64

	for i := 0; i < cfg.dlSamples; i++ {
		url := fmt.Sprintf("%s/__down?bytes=%d", cfBase, cfg.dlBytes)
		start := time.Now()
		resp, err := client.Get(url)
		if err != nil {
			fmt.Print(".")
			continue
		}
		n, err := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		elapsed := time.Since(start)
		if err != nil || n == 0 {
			fmt.Print(".")
			continue
		}
		m := speedMeasurement{bytes: n, duration: elapsed}
		samples = append(samples, m.mbps())
		fmt.Print(".")
	}

	return medianFloat(trimLowest(samples))
}

// measureUpload benchmarks upload speed using Cloudflare's __up endpoint.
// It collects cfg.ulSamples measurements at cfg.ulBytes each, trims the lowest,
// and returns the median of the remainder.
func measureUpload(cfg speedConfig) float64 {
	client := &http.Client{Timeout: httpTimeout}
	var samples []float64

	for i := 0; i < cfg.ulSamples; i++ {
		payload := make([]byte, cfg.ulBytes)
		url := fmt.Sprintf("%s/__up", cfBase)
		start := time.Now()
		resp, err := client.Post(url, "application/octet-stream", bytes.NewReader(payload))
		if err != nil {
			fmt.Print(".")
			continue
		}
		io.Copy(io.Discard, resp.Body) //nolint:errcheck — response body is irrelevant
		resp.Body.Close()
		elapsed := time.Since(start)
		m := speedMeasurement{bytes: int64(cfg.ulBytes), duration: elapsed}
		samples = append(samples, m.mbps())
		fmt.Print(".")
	}

	return medianFloat(trimLowest(samples))
}

// trimLowest returns a copy of vals with the single lowest value removed.
// If the slice has fewer than 2 elements it is returned unchanged.
func trimLowest(vals []float64) []float64 {
	if len(vals) < 2 {
		return vals
	}
	minIdx := 0
	for i, v := range vals {
		if v < vals[minIdx] {
			minIdx = i
		}
	}
	out := make([]float64, 0, len(vals)-1)
	for i, v := range vals {
		if i != minIdx {
			out = append(out, v)
		}
	}
	return out
}

// medianFloat returns the median of a float64 slice, or 0 if empty.
func medianFloat(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sorted := make([]float64, len(vals))
	copy(sorted, vals)
	sort.Float64s(sorted)
	mid := len(sorted) / 2
	if len(sorted)%2 == 0 {
		return (sorted[mid-1] + sorted[mid]) / 2
	}
	return sorted[mid]
}

// ── 4. Stability (ping, jitter, packet loss) ──────────────────────────────────

func checkStability() stabilityResult {
	r := stabilityResult{sent: pingCount}

	ip, err := net.ResolveIPAddr("ip4", pingTarget)
	if err != nil {
		fmt.Printf("    Error resolving %s: %v\n", pingTarget, err)
		return r
	}

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		fmt.Printf("    Error opening ICMP socket: %v\n", err)
		return r
	}
	defer conn.Close()

	pid := os.Getpid() & 0xffff
	var rtts []float64

	for i := 0; i < pingCount; i++ {
		msg := icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &icmp.Echo{
				ID:   pid,
				Seq:  i,
				Data: []byte("netstab"),
			},
		}
		msgBytes, err := msg.Marshal(nil)
		if err != nil {
			fmt.Printf("    Error marshaling ICMP: %v\n", err)
			continue
		}

		start := time.Now()
		_, err = conn.WriteTo(msgBytes, &net.IPAddr{IP: ip.IP})
		if err != nil {
			continue
		}

		reply := make([]byte, bufferSize)
		err = conn.SetReadDeadline(time.Now().Add(pingDeadline))
		if err != nil {
			continue
		}
		_, _, err = conn.ReadFrom(reply)
		if err != nil {
			// Timeout counts as lost packet.
			continue
		}

		rtt := float64(time.Since(start).Microseconds()) / 1000.0
		rtts = append(rtts, rtt)
		time.Sleep(pingInterval)
	}

	r.received = len(rtts)
	r.packetLoss = float64(r.sent-r.received) / float64(r.sent) * 100

	if len(rtts) == 0 {
		return r
	}

	// Latency stats.
	var sum float64
	r.minMs = rtts[0]
	r.maxMs = rtts[0]
	for _, rtt := range rtts {
		sum += rtt
		if rtt < r.minMs {
			r.minMs = rtt
		}
		if rtt > r.maxMs {
			r.maxMs = rtt
		}
	}
	r.avgMs = sum / float64(len(rtts))

	// Jitter: mean absolute deviation of consecutive RTT differences.
	if len(rtts) > 1 {
		var jitterSum float64
		for i := 1; i < len(rtts); i++ {
			jitterSum += math.Abs(rtts[i] - rtts[i-1])
		}
		r.jitterMs = jitterSum / float64(len(rtts)-1)
	}

	return r
}

// ── 5. Formatting helpers ─────────────────────────────────────────────────────

const (
	colorReset  = "\033[0m"
	colorBold   = "\033[1m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorRed    = "\033[31m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
)

func header(title string) {
	fmt.Printf("\n%s%s── %s %s──%s\n", colorBold, colorCyan, title, colorGray, colorReset)
}

func field(label, value string) {
	fmt.Printf("  %-22s %s\n", label, value)
}

// formatSpeed formats a Mbps value as Mbps or Gbps.
func formatSpeed(mbps float64) string {
	if mbps <= 0 {
		return colorRed + "unavailable" + colorReset
	}
	if mbps >= 1000 {
		return fmt.Sprintf("%s%.2f Gbps%s", colorGreen, mbps/1000, colorReset)
	}
	col := colorGreen
	if mbps < 10 {
		col = colorRed
	} else if mbps < 50 {
		col = colorYellow
	}
	return fmt.Sprintf("%s%.1f Mbps%s", col, mbps, colorReset)
}

// formatLatency colors a latency value.
func formatLatency(ms float64) string {
	col := colorGreen
	if ms > 100 {
		col = colorRed
	} else if ms > 40 {
		col = colorYellow
	}
	return fmt.Sprintf("%s%.2f ms%s", col, ms, colorReset)
}

// formatJitter colors a jitter value.
func formatJitter(ms float64) string {
	col := colorGreen
	if ms > 20 {
		col = colorRed
	} else if ms > 8 {
		col = colorYellow
	}
	return fmt.Sprintf("%s%.2f ms%s", col, ms, colorReset)
}

// formatLoss colors a packet loss percentage.
func formatLoss(pct float64) string {
	col := colorGreen
	if pct > 5 {
		col = colorRed
	} else if pct > 1 {
		col = colorYellow
	}
	return fmt.Sprintf("%s%.1f%%%s", col, pct, colorReset)
}

// ── main ──────────────────────────────────────────────────────────────────────

func main() {
	thorough := flag.Bool("thorough", false, "run a longer, more accurate speed test (~20s instead of ~10s)")
	flag.Parse()

	cfg := speedDefault
	if *thorough {
		cfg = speedThorough
	}

	fmt.Printf("%s%snetstab — network analyzer%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s\n", colorGray, strings.Repeat("─", 40)+colorReset)

	// ── 1. Status ──
	header("1. Connection Status")
	status := checkStatus()
	if !status.online {
		field("Status:", colorRed+"OFFLINE"+colorReset)
		fmt.Println()
		os.Exit(1)
	}
	field("Status:", colorGreen+"Online"+colorReset)
	if status.iface != "" {
		typeLabel := status.ifaceType
		field("Interface:", fmt.Sprintf("%s (%s)", status.iface, typeLabel))
	}
	if status.localIP != nil {
		field("Local IP:", status.localIP.String())
	}
	if status.publicIP != "" {
		field("Public IP:", status.publicIP)
	}

	// ── 2. Signal strength ──
	header("2. Connection Strength")
	strength := checkStrength(status.iface, status.ifaceType)
	switch status.ifaceType {
	case "wifi":
		if strength.signalOK {
			col := colorGreen
			if strength.signalDBm < -70 {
				col = colorRed
			} else if strength.signalDBm < -60 {
				col = colorYellow
			}
			field("Signal:", fmt.Sprintf("%s%d dBm%s (%s)", col, strength.signalDBm, colorReset, strength.signalDesc))
		} else {
			field("Signal:", colorGray+"unavailable (try running as root)"+colorReset)
		}
	case "ethernet":
		if strength.linkMbps > 0 {
			field("Link speed:", formatSpeed(float64(strength.linkMbps)))
		} else {
			field("Link speed:", colorGray+"unavailable (ethtool not found or no permission)"+colorReset)
		}
	default:
		field("Strength:", colorGray+"unavailable"+colorReset)
	}

	// ── 3. Speed ──
	header("3. Speed Test")
	fmt.Printf("  %sUsing speed.cloudflare.com%s\n", colorGray, colorReset)
	speed := runSpeedTest(cfg)
	field("Download:", formatSpeed(speed.downloadMbps))
	field("Upload:", formatSpeed(speed.uploadMbps))

	// ── 4. Stability ──
	header("4. Stability")
	fmt.Printf("  %sPinging %s × %d%s\n", colorGray, pingTarget, pingCount, colorReset)
	stability := checkStability()
	field("Packets sent/recv:", fmt.Sprintf("%d / %d", stability.sent, stability.received))
	field("Packet loss:", formatLoss(stability.packetLoss))
	if stability.received > 0 {
		field("Latency (min):", formatLatency(stability.minMs))
		field("Latency (avg):", formatLatency(stability.avgMs))
		field("Latency (max):", formatLatency(stability.maxMs))
		field("Jitter:", formatJitter(stability.jitterMs))
	}

	fmt.Printf("\n%s%s\n\n", colorGray, strings.Repeat("─", 40)+colorReset)
}
