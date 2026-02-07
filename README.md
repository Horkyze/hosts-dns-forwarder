# hosts-dns-forwarder

Tiny UDP DNS server in Rust:

- Answer from `/etc/hosts` first (A / AAAA / ANY)
- Otherwise forward the raw DNS packet to the first upstream in `/etc/resolv.conf`

This is intentionally minimal: no TCP, no caching, no DNSSEC.

## Build

```bash
cargo build --release
```

## Run (non-privileged port)

Default listen is `127.0.0.1:5300` (chosen to avoid clashing with mDNS on 5353):

```bash
./target/release/hosts-dns-forwarder
```

Or explicitly:

```bash
./target/release/hosts-dns-forwarder --listen 127.0.0.1:5300
```

## Test

```bash
dig @127.0.0.1 -p 5300 core A +short
dig @127.0.0.1 -p 5300 google.com A +short
```

## Run on port 53

Binding to port 53 requires privileges. Two common approaches:

```bash
sudo ./target/release/hosts-dns-forwarder --listen 127.0.0.1:53
```

Or grant the binary permission to bind low ports:

```bash
sudo setcap 'cap_net_bind_service=+ep' ./target/release/hosts-dns-forwarder
./target/release/hosts-dns-forwarder --listen 127.0.0.1:53
```

If you point your machine at this as its resolver, make sure forwarding doesn't loop.
For systemd-resolved systems, a common upstream is the local stub:

```bash
./target/release/hosts-dns-forwarder --listen 127.0.0.1:53 --upstream 127.0.0.53
```

## Debian/Ubuntu package

Build a local `.deb` (requires `dpkg-deb`):

```bash
bash packaging/debian/build-deb.sh
```

Install it:

```bash
bash packaging/debian/install.sh
```

The package installs:

- binary: `/usr/bin/hosts-dns-forwarder`
- wrapper: `/usr/lib/hosts-dns-forwarder/hosts-dns-forwarder-run`
- config: `/etc/hosts-dns-forwarder/hosts-dns-forwarder.env`
- unit: `/lib/systemd/system/hosts-dns-forwarder.service`


## “Without an additional application?”

- For *your own machine*, you already get `/etc/hosts` before DNS via NSS
  (see `/etc/nsswitch.conf`, the `hosts:` line).
- For a *DNS server* that other machines can query, you need something listening on UDP/TCP 53
  (e.g. dnsmasq/unbound/CoreDNS, or this program).
