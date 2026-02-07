use anyhow::{anyhow, bail, Context, Result};
use trust_dns_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use trust_dns_proto::rr::rdata::{A, AAAA};
use trust_dns_proto::rr::{Name, RData, Record, RecordType};
use std::collections::HashMap;
use std::env;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

// Avoid clashing with mDNS (UDP/5353).
const DEFAULT_LISTEN: &str = "127.0.0.1:5300";
const DEFAULT_HOSTS: &str = "/etc/hosts";
const DEFAULT_RESOLV: &str = "/etc/resolv.conf";
const DEFAULT_TIMEOUT_MS: u64 = 1500;
const DEFAULT_TTL_SECS: u32 = 60;
const MAX_DNS_PACKET: usize = 4096;

#[derive(Debug, Clone)]
struct Config {
    listen: SocketAddr,
    hosts_path: PathBuf,
    resolv_conf: PathBuf,
    upstreams: Vec<SocketAddr>,
    forward_timeout: Duration,
    ttl_secs: u32,
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut cfg = Config::from_args().await?;
    cfg.drop_recursive_upstreams();
    if cfg.upstreams.is_empty() {
        bail!(
            "no upstream nameservers configured (try --upstream 1.1.1.1 or check {})",
            cfg.resolv_conf.display()
        );
    }

    eprintln!(
        "listening on {} (UDP); hosts={}, resolv={}, upstreams={:?}",
        cfg.listen,
        cfg.hosts_path.display(),
        cfg.resolv_conf.display(),
        cfg.upstreams
    );

    let sock = UdpSocket::bind(cfg.listen)
        .await
        .with_context(|| format!("bind UDP socket on {}", cfg.listen))?;

    let cfg = std::sync::Arc::new(cfg);
    let sock = std::sync::Arc::new(sock);
    let mut buf = vec![0u8; MAX_DNS_PACKET];

    loop {
        let (n, peer) = sock
            .recv_from(&mut buf)
            .await
            .context("recv UDP packet")?;
        let packet = buf[..n].to_vec();

        let sock = std::sync::Arc::clone(&sock);
        let cfg = std::sync::Arc::clone(&cfg);
        tokio::spawn(async move {
            if let Err(err) = handle_packet(&sock, &cfg, peer, packet).await {
                eprintln!("error handling {}: {:#}", peer, err);
            }
        });
    }
}

impl Config {
    async fn from_args() -> Result<Self> {
        let mut listen: SocketAddr = DEFAULT_LISTEN
            .parse()
            .expect("DEFAULT_LISTEN must be a valid SocketAddr");
        let mut hosts_path = PathBuf::from(DEFAULT_HOSTS);
        let mut resolv_conf = PathBuf::from(DEFAULT_RESOLV);
        let mut upstreams: Vec<SocketAddr> = Vec::new();
        let mut forward_timeout = Duration::from_millis(DEFAULT_TIMEOUT_MS);
        let mut ttl_secs = DEFAULT_TTL_SECS;

        let mut args = env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                "-l" | "--listen" => {
                    let v = args.next().ok_or_else(|| anyhow!("--listen needs a value"))?;
                    listen = v.parse().with_context(|| format!("parse --listen {v}"))?;
                }
                "--hosts" => {
                    let v = args.next().ok_or_else(|| anyhow!("--hosts needs a value"))?;
                    hosts_path = PathBuf::from(v);
                }
                "--resolv" => {
                    let v = args.next().ok_or_else(|| anyhow!("--resolv needs a value"))?;
                    resolv_conf = PathBuf::from(v);
                }
                "-u" | "--upstream" => {
                    let v = args.next().ok_or_else(|| anyhow!("--upstream needs a value"))?;
                    upstreams.push(parse_upstream(&v)?);
                }
                "--timeout-ms" => {
                    let v = args
                        .next()
                        .ok_or_else(|| anyhow!("--timeout-ms needs a value"))?;
                    let ms: u64 = v.parse().with_context(|| format!("parse --timeout-ms {v}"))?;
                    forward_timeout = Duration::from_millis(ms);
                }
                "--ttl" => {
                    let v = args.next().ok_or_else(|| anyhow!("--ttl needs a value"))?;
                    ttl_secs = v.parse().with_context(|| format!("parse --ttl {v}"))?;
                }
                other => bail!("unknown argument: {other}"),
            }
        }

        if upstreams.is_empty() {
            upstreams = read_upstreams_from_resolv_conf(&resolv_conf).await?;
        }

        Ok(Self {
            listen,
            hosts_path,
            resolv_conf,
            upstreams,
            forward_timeout,
            ttl_secs,
        })
    }

    fn drop_recursive_upstreams(&mut self) {
        let listen = self.listen;
        let mut removed = Vec::new();
        self.upstreams.retain(|u| {
            if would_recurse(listen, *u) {
                removed.push(*u);
                false
            } else {
                true
            }
        });

        if !removed.is_empty() {
            eprintln!(
                "warning: removed upstream(s) that would recurse into this server (listen={}): {:?}",
                listen, removed
            );
        }
    }
}

fn would_recurse(listen: SocketAddr, upstream: SocketAddr) -> bool {
    if upstream == listen {
        return true;
    }
    if listen.port() != upstream.port() {
        return false;
    }

    // If we listen on a wildcard address (0.0.0.0 / ::), forwarding to loopback on the same
    // port will hit this process.
    match (listen.ip(), upstream.ip()) {
        (IpAddr::V4(l), IpAddr::V4(u)) if l.is_unspecified() => u.is_loopback() || u.is_unspecified(),
        (IpAddr::V6(l), IpAddr::V6(u)) if l.is_unspecified() => u.is_loopback() || u.is_unspecified(),
        _ => false,
    }
}

fn print_usage() {
    eprintln!(
        "hosts-dns-forwarder\n\nUSAGE:\n  hosts-dns-forwarder [options]\n\nOPTIONS:\n  -l, --listen <ip:port>     Listen address (default: {DEFAULT_LISTEN})\n      --hosts <path>          Hosts file path (default: {DEFAULT_HOSTS})\n      --resolv <path>         resolv.conf path (default: {DEFAULT_RESOLV})\n  -u, --upstream <ip[:port]>  Upstream DNS server (repeatable; default: parsed from resolv.conf)\n      --timeout-ms <ms>       Upstream UDP timeout (default: {DEFAULT_TIMEOUT_MS})\n      --ttl <secs>            TTL for hosts answers (default: {DEFAULT_TTL_SECS})\n  -h, --help                  Show this help\n\nNOTES:\n  - Answers from /etc/hosts are authoritative (AA=1).\n  - If a name exists in /etc/hosts but the query type doesn't match, the server returns NOERROR with an empty answer section (NODATA).\n  - This is UDP-only and does not implement TCP fallback.\n"
    );
}

fn parse_upstream(s: &str) -> Result<SocketAddr> {
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Ok(sa);
    }
    let ip: IpAddr = s.parse().with_context(|| format!("parse upstream IP {s}"))?;
    Ok(SocketAddr::new(ip, 53))
}

async fn read_upstreams_from_resolv_conf(path: &Path) -> Result<Vec<SocketAddr>> {
    let contents = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("read resolv.conf: {}", path.display()))?;

    let mut out = Vec::new();
    for line in contents.lines() {
        let line = line.split('#').next().unwrap_or("");
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let key = parts.next().unwrap_or("");
        if key != "nameserver" {
            continue;
        }
        let Some(addr) = parts.next() else { continue };
        if let Ok(ip) = addr.parse::<IpAddr>() {
            out.push(SocketAddr::new(ip, 53));
        }
    }

    Ok(out)
}

async fn handle_packet(
    sock: &UdpSocket,
    cfg: &Config,
    peer: SocketAddr,
    packet: Vec<u8>,
) -> Result<()> {
    let req = match Message::from_vec(&packet) {
        Ok(m) => m,
        Err(_) => return Ok(()),
    };

    if req.message_type() != MessageType::Query {
        return Ok(());
    }
    if req.op_code() != OpCode::Query {
        let mut err = Message::error_msg(req.id(), req.op_code(), ResponseCode::NotImp);
        err.set_recursion_available(true);
        err.set_recursion_desired(req.recursion_desired());
        err.add_queries(req.queries().iter().cloned());
        if let Some(edns) = req.extensions().as_ref() {
            err.set_edns(edns.clone());
        }
        let out = err.to_vec()?;
        sock.send_to(&out, peer).await?;
        return Ok(());
    }

    if req.queries().len() != 1 {
        // Keep it stupid: forward anything non-standard.
        return forward_and_reply(sock, cfg, peer, &packet, &req).await;
    }

    let q = req.queries()[0].clone();
    let qname = normalize_query_name(q.name());
    let qtype = q.query_type();

    // Note: /etc/hosts only really defines A/AAAA-ish data, but we treat the presence
    // of a name as authoritative and return NODATA for other types.
    let hosts = load_hosts_map(&cfg.hosts_path).await.unwrap_or_default();
    if let Some(ips) = hosts.get(&qname) {
        let out = build_hosts_response(cfg, &req, q, ips, qtype)?;
        sock.send_to(&out, peer).await?;
        return Ok(());
    }

    forward_and_reply(sock, cfg, peer, &packet, &req).await
}

async fn forward_and_reply(
    sock: &UdpSocket,
    cfg: &Config,
    peer: SocketAddr,
    packet: &[u8],
    req: &Message,
) -> Result<()> {
    match forward_udp(cfg, packet).await {
        Ok(resp) => {
            sock.send_to(&resp, peer).await?;
            Ok(())
        }
        Err(err) => {
            eprintln!("forward failed: {:#}", err);
            let mut msg = Message::error_msg(req.id(), req.op_code(), ResponseCode::ServFail);
            msg.set_recursion_available(true);
            msg.set_recursion_desired(req.recursion_desired());
            msg.add_queries(req.queries().iter().cloned());
            if let Some(edns) = req.extensions().as_ref() {
                msg.set_edns(edns.clone());
            }
            let out = msg.to_vec()?;
            sock.send_to(&out, peer).await?;
            Ok(())
        }
    }
}

async fn forward_udp(cfg: &Config, packet: &[u8]) -> Result<Vec<u8>> {
    let mut last_err: Option<anyhow::Error> = None;
    for upstream in &cfg.upstreams {
        match forward_udp_once(*upstream, packet, cfg.forward_timeout).await {
            Ok(resp) => return Ok(resp),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("no upstreams configured")))
}

async fn forward_udp_once(upstream: SocketAddr, packet: &[u8], to: Duration) -> Result<Vec<u8>> {
    let bind_addr: SocketAddr = match upstream.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };

    let sock = UdpSocket::bind(bind_addr)
        .await
        .with_context(|| format!("bind ephemeral UDP socket on {bind_addr}"))?;

    sock.send_to(packet, upstream)
        .await
        .with_context(|| format!("send UDP query to upstream {upstream}"))?;

    let mut buf = vec![0u8; MAX_DNS_PACKET];
    let (n, _from) = timeout(to, sock.recv_from(&mut buf))
        .await
        .with_context(|| format!("timeout waiting for upstream {upstream}"))??;
    buf.truncate(n);
    Ok(buf)
}

fn build_hosts_response(cfg: &Config, req: &Message, q: Query, ips: &[IpAddr], qtype: RecordType) -> Result<Vec<u8>> {
    let mut resp = Message::new();
    resp.set_id(req.id());
    resp.set_message_type(MessageType::Response);
    resp.set_op_code(req.op_code());
    resp.set_authoritative(true);
    resp.set_recursion_desired(req.recursion_desired());
    resp.set_recursion_available(true);
    resp.set_checking_disabled(req.checking_disabled());
    resp.set_response_code(ResponseCode::NoError);
    resp.add_query(q.clone());

    if let Some(edns) = req.extensions().as_ref() {
        resp.set_edns(edns.clone());
    }

    let name = q.name().clone();
    let ttl = cfg.ttl_secs;

    match qtype {
        RecordType::A => {
            for ip in ips.iter().copied().filter_map(|ip| match ip {
                IpAddr::V4(v4) => Some(v4),
                IpAddr::V6(_) => None,
            }) {
                resp.add_answer(Record::from_rdata(name.clone(), ttl, RData::A(A(ip))));
            }
        }
        RecordType::AAAA => {
            for ip in ips.iter().copied().filter_map(|ip| match ip {
                IpAddr::V6(v6) => Some(v6),
                IpAddr::V4(_) => None,
            }) {
                resp.add_answer(Record::from_rdata(name.clone(), ttl, RData::AAAA(AAAA(ip))));
            }
        }
        RecordType::ANY => {
            for ip in ips {
                match ip {
                    IpAddr::V4(v4) => {
                        resp.add_answer(Record::from_rdata(name.clone(), ttl, RData::A(A(*v4))));
                    }
                    IpAddr::V6(v6) => {
                        resp.add_answer(Record::from_rdata(
                            name.clone(),
                            ttl,
                            RData::AAAA(AAAA(*v6)),
                        ));
                    }
                }
            }
        }
        _ => {
            // NODATA, no answers.
        }
    }

    Ok(resp.to_vec()?)
}

fn normalize_query_name(name: &Name) -> String {
    let mut s = name.to_ascii().to_lowercase();
    if s != "." {
        while s.ends_with('.') {
            s.pop();
        }
    }
    s
}

async fn load_hosts_map(path: &Path) -> Result<HashMap<String, Vec<IpAddr>>> {
    let contents = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("read hosts file: {}", path.display()))?;

    let mut out: HashMap<String, Vec<IpAddr>> = HashMap::new();
    for line in contents.lines() {
        let line = line.split('#').next().unwrap_or("");
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let mut parts = line.split_whitespace();
        let Some(ip_s) = parts.next() else { continue };
        let Ok(ip) = ip_s.parse::<IpAddr>() else { continue };

        for name in parts {
            let name = name.trim();
            if name.is_empty() {
                continue;
            }
            let mut key = name.to_ascii_lowercase();
            while key.ends_with('.') {
                key.pop();
            }
            let entry = out.entry(key).or_default();
            if !entry.contains(&ip) {
                entry.push(ip);
            }
        }
    }

    Ok(out)
}
