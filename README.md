# netstab

A CLI tool for diagnosing the real state of your network connection. Rather than
just checking whether you are online, netstab runs four sequential stages that
together give a complete picture: what interface you are on, how strong the
signal is, how fast the connection is, and how stable it is over time.

---

## Why netstab?

Most network tools answer one question in isolation. `ping` tells you latency.
`speedtest-cli` tells you throughput. Nothing tells you all four things together
in a single, fast run with no account, no browser, and no telemetry.

netstab is a single self-contained binary with no runtime dependencies beyond
the Go standard library and `golang.org/x/net`. It is designed to be run
directly on the machine you are diagnosing, including headless servers and
embedded Linux systems.

---

## How it works

### 1. Connection status

netstab opens a UDP socket aimed at `1.1.1.1:80`. No packet is sent — the
kernel's routing table resolves the outbound interface as a side effect of the
dial. This gives the local IP and the interface name without any network
round-trip.

The interface name is then matched against known prefixes (`wl*`, `eth*`, `en*`)
to classify the connection as WiFi, Ethernet, or unknown.

The public IP is fetched from Cloudflare's plain-text trace endpoint
(`https://1.1.1.1/cdn-cgi/trace`), which returns a small key-value body
containing the `ip=` field. This is faster and more reliable than using a
dedicated IP-lookup API.

### 2. Connection strength

**WiFi — dBm**

Signal strength is reported in dBm (decibel-milliwatts), which is the standard
unit used by 802.11 hardware drivers. It is a logarithmic scale: `-30 dBm` is
near-perfect, `-90 dBm` is the edge of usability. dBm is preferred over
arbitrary percentage scales because it maps directly to what the hardware
measures and makes comparisons between readings meaningful.

Signal is read via `iw dev <iface> link`, which works on all modern Linux
systems using `cfg80211`/`mac80211` drivers. The older `/proc/net/wireless`
interface is not used as it is absent on any kernel with a modern WiFi driver.

| dBm range      | Quality    |
|----------------|------------|
| ≥ −50          | Excellent  |
| −50 to −60     | Good       |
| −60 to −70     | Fair       |
| −70 to −80     | Poor       |
| < −80          | Very Poor  |

**Ethernet — link speed**

For wired connections, the negotiated link speed is read via `ethtool`. This
reflects the physical layer speed (e.g. 1000 Mb/s, 10000 Mb/s) rather than
actual throughput.

### 3. Speed test

netstab measures throughput against Cloudflare's dedicated speed test
infrastructure (`speed.cloudflare.com`). Cloudflare is chosen because:

- Their edge nodes are globally distributed and geographically close to most
  users, minimising the effect of long-haul routing on results.
- The `/__down` and `/__up` endpoints serve and consume raw bytes with no
  protocol overhead, making byte-counting accurate.
- The service is free, requires no authentication, and has no rate limits for
  reasonable use.

**Why not fast.com or speedtest.net?**  
Both require a browser or a separate CLI client. Cloudflare's endpoints are
plain HTTP and can be hit with a standard `net/http` client.

**Variance reduction**

A naive single-request speed test is unreliable because TCP slow-start means
the connection ramps up gradually — short transfers never reach full throughput.
netstab addresses this in two ways:

1. **Fixed large payloads only.** Small payloads (< 10 MB) are excluded because
   they complete before the TCP congestion window fully opens, consistently
   under-reporting real throughput.
2. **Multiple samples with lowest trimmed.** The first request of any run still
   suffers from slow-start. netstab discards the single lowest sample before
   computing the median, removing this systematic bias.

| Mode | Samples | Payload | Typical duration |
|---|---|---|---|
| Default | 5 DL + 5 UL | 10 MB each | ~10 s |
| `--thorough` | 8 DL + 6 UL | 25 MB each | ~20 s |

Use `--thorough` on fast connections (>100 Mbps) where 10 MB transfers complete
quickly enough that slow-start still has a measurable effect.

### 4. Stability

20 ICMP echo packets are sent to `1.1.1.1` at 50 ms intervals. From the
round-trip times netstab computes:

- **Packet loss** — the percentage of probes that received no reply within 3 s.
- **Min / avg / max latency** — the spread of round-trip times in milliseconds.
- **Jitter** — mean absolute deviation of consecutive RTT differences. Jitter
  is a better measure of connection consistency than the raw latency range
  because it captures how much the delay varies from packet to packet, which
  directly affects the quality of real-time traffic like video calls and gaming.

Raw ICMP sockets require elevated privileges. Run as root.

---

## Build

```sh
# Dependencies are committed — no init step needed
go build -o netstab

# Statically linked (recommended for distribution or servers)
CGO_ENABLED=0 go build -o netstab
```

## Run

```sh
sudo ./netstab             # standard run (~10 s speed test)
sudo ./netstab --thorough  # longer speed test (~20 s, better for fast connections)
```

---

## Requirements

- Linux (ICMP and `/proc` interfaces are Linux-specific)
- Go 1.21 or later
- Root / sudo (for raw ICMP sockets)
- `iw` installed for WiFi signal reading (`apt install iw` / `pacman -S iw`)
- `ethtool` installed for Ethernet link speed (`apt install ethtool`)
