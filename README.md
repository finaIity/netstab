# netstab

A CLI tool for diagnosing the real state of your network connection. 
Netstab runs four sequential stages that give a complete picture:
What interface you are on, how strong the signal is, how fast the connection
is, and how stable it is over time.

---


## Requirements

- Linux (ICMP and `/proc` interfaces are Linux-specific)
- Go 1.21 or later
- Root / sudo (for raw ICMP sockets)
- `iw` installed for WiFi signal reading (`apt install iw` / `pacman -S iw`)
- `ethtool` installed for Ethernet link speed (`apt install ethtool`)

## Build

```sh
# Dependencies are committed so no init step needed
go build -o netstab

# Statically linked (recommended for distribution or servers)
CGO_ENABLED=0 go build -o netstab
```

## Run

```sh
sudo ./netstab             # standard run (~10 s speed test)
sudo ./netstab --thorough  # longer speed test (~20 s, better for fast connections)
```
Note: use `--thorough` on fast connections (>500 Mbps) where 10 MB transfers complete
quickly enough that slow-start still has a measurable effect.
