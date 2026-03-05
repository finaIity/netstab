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
# Recommended: grant only the required capability, then run without sudo
sudo setcap cap_net_raw+ep ./netstab
./netstab
./netstab --thorough   # longer speed test (~20s, better for fast connections)

# Alternative: run as root
sudo ./netstab
sudo ./netstab --thorough
```
Note: use `--thorough` on fast connections (>500 Mbps) where 10 MB transfers complete
quickly enough that slow-start still has a measurable effect

---

## Requirements

- Linux (ICMP and `/proc` interfaces are Linux-specific)
- Go 1.21 or later
- `iw` installed for WiFi signal reading (`apt install iw` / `pacman -S iw`)
- `ethtool` installed for Ethernet link speed (`apt install ethtool`)

---

## Privileges

netstab requires `CAP_NET_RAW` to open a raw ICMP socket. Running the full
binary as root works but is broader than necessary. The preferred approach is
to grant only the required capability to the binary:

```sh
sudo setcap cap_net_raw+ep ./netstab
./netstab          # no sudo needed after this
```

With `setcap`, all other code paths (HTTP requests, subprocess calls, file
reads) run without elevated privileges, reducing the blast radius of any
hypothetical vulnerability to `CAP_NET_RAW` in a single process rather than
a full root shell.

`setcap` must be re-applied after each rebuild.
