/**
 * Runtime-ledger parser tests.
 *
 * The pcap and strace parsers are pure functions over bytes/text, so
 * they are exercised here against hand-built fixtures — no sandbox, no
 * network. A real end-to-end capture is verified separately against a
 * live podman sandbox; these lock the parsing logic.
 */
import { describe, expect, it } from "vitest";
import {
  parsePcap,
  parseStrace,
  parseSni,
  buildLedger,
  analyzeLedger,
  extractDocHosts,
  type RawCapture,
} from "../src/behavioral/ledger";

// ---------------------------------------------------------------------
// pcap fixture builders (classic little-endian format, LINKTYPE_RAW_IP)
// ---------------------------------------------------------------------

function u16(n: number): number[] {
  return [n & 0xff, (n >> 8) & 0xff];
}
function u16be(n: number): number[] {
  return [(n >> 8) & 0xff, n & 0xff];
}
function u32le(n: number): number[] {
  return [n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff];
}

const LINKTYPE_RAW_IP = 101;
const LINKTYPE_LINUX_SLL2 = 276;

/**
 * Linux "cooked v2" frame — the link type `tcpdump -i any` actually
 * produces, which is what the sandbox capture uses. 20-byte header:
 * protocol(2) reserved(2) ifindex(4) arphrd(2) pkttype(1) addrlen(1)
 * addr(8), then the IP packet.
 */
function sll2(ethertype: number, ipPacket: number[]): number[] {
  return [...u16be(ethertype), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ...ipPacket];
}

function pcapGlobalHeader(linktype: number): number[] {
  return [
    ...u32le(0xa1b2c3d4), // magic (LE)
    ...u16(2),
    ...u16(4), // version
    ...u32le(0), // thiszone
    ...u32le(0), // sigfigs
    ...u32le(65535), // snaplen
    ...u32le(linktype),
  ];
}

function pcapRecord(packet: number[]): number[] {
  return [...u32le(0), ...u32le(0), ...u32le(packet.length), ...u32le(packet.length), ...packet];
}

/** Minimal IPv4 header (20 bytes) with the given protocol + dst IP. */
function ipv4(proto: number, dst: [number, number, number, number], payload: number[]): number[] {
  const total = 20 + payload.length;
  return [
    0x45,
    0x00,
    ...u16be(total),
    ...u16be(0),
    ...u16be(0),
    64,
    proto,
    ...u16be(0), // checksum (ignored by parser)
    10,
    0,
    0,
    2, // src 10.0.0.2
    ...dst,
    ...payload,
  ];
}

/** Minimal IPv6 header (40 bytes, no extension headers) with dst + next-header. */
function ipv6(nextHeader: number, dst: number[], payload: number[]): number[] {
  const src = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
  return [
    0x60,
    0,
    0,
    0, // version 6, tclass/flow 0
    ...u16be(payload.length),
    nextHeader,
    64, // hop limit
    ...src,
    ...dst,
    ...payload,
  ];
}

/** TCP header with flags; dataOffset = 5 words (20 bytes), no options. */
function tcp(dstPort: number, flags: number, payload: number[] = []): number[] {
  return [
    ...u16be(40000), // src port
    ...u16be(dstPort),
    ...u32le(0), // seq
    ...u32le(0), // ack
    0x50, // data offset 5<<4
    flags,
    ...u16be(65535),
    ...u16be(0),
    ...u16be(0),
    ...payload,
  ];
}

function udp(srcPort: number, dstPort: number, payload: number[]): number[] {
  return [
    ...u16be(srcPort),
    ...u16be(dstPort),
    ...u16be(8 + payload.length),
    ...u16be(0),
    ...payload,
  ];
}

/** A DNS query packet body for a single A-record question. */
function dnsQuery(name: string): number[] {
  const labels: number[] = [];
  for (const part of name.split(".")) {
    labels.push(part.length, ...[...part].map((c) => c.charCodeAt(0)));
  }
  labels.push(0);
  return [
    ...u16be(0x1234), // id
    ...u16be(0x0100), // flags: recursion desired
    ...u16be(1), // qdcount
    ...u16be(0),
    ...u16be(0),
    ...u16be(0),
    ...labels,
    ...u16be(1), // qtype A
    ...u16be(1), // qclass IN
  ];
}

/** A DNS response mapping name -> ip (single A answer, compression pointer). */
function dnsAnswer(name: string, ip: [number, number, number, number]): number[] {
  const labels: number[] = [];
  for (const part of name.split(".")) {
    labels.push(part.length, ...[...part].map((c) => c.charCodeAt(0)));
  }
  labels.push(0);
  const header = [
    ...u16be(0x1234),
    ...u16be(0x8180), // response
    ...u16be(1), // qd
    ...u16be(1), // an
    ...u16be(0),
    ...u16be(0),
  ];
  const question = [...labels, ...u16be(1), ...u16be(1)];
  const nameOffset = header.length + 0; // question name starts right after header
  const answer = [
    ...u16be(0xc000 | nameOffset), // pointer to question name
    ...u16be(1), // type A
    ...u16be(1), // class IN
    ...u32le(300), // ttl
    ...u16be(4), // rdlength
    ...ip,
  ];
  return [...header, ...question, ...answer];
}

/** A TLS ClientHello record carrying an SNI server_name extension. */
function tlsClientHello(serverName: string): number[] {
  const name = [...serverName].map((c) => c.charCodeAt(0));
  const sni = [
    0x00,
    0x00, // extension type = server_name
    ...u16be(name.length + 5),
    ...u16be(name.length + 3), // server_name_list length
    0x00, // name type = host_name
    ...u16be(name.length),
    ...name,
  ];
  const extensions = [...u16be(sni.length), ...sni];
  const body = [
    0x03,
    0x03, // client_version TLS1.2
    ...new Array(32).fill(0), // random
    0x00, // session id len
    ...u16be(2),
    0x13,
    0x01, // cipher suites
    0x01,
    0x00, // compression methods
    ...extensions,
  ];
  const handshake = [0x01, ...u16be(body.length >> 8 === 0 ? body.length : body.length), 0x00];
  // handshake length is 3 bytes
  const hs = [
    0x01,
    (body.length >> 16) & 0xff,
    (body.length >> 8) & 0xff,
    body.length & 0xff,
    ...body,
  ];
  void handshake;
  const record = [0x16, 0x03, 0x03, ...u16be(hs.length), ...hs];
  return record;
}

function bytes(...parts: number[][]): Uint8Array {
  return Uint8Array.from(parts.flat());
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

describe("parsePcap", () => {
  it("records an outbound TCP SYN as a connection", () => {
    const pcap = bytes(
      pcapGlobalHeader(LINKTYPE_RAW_IP),
      pcapRecord(ipv4(6, [93, 184, 216, 34], tcp(443, 0x02))),
    );
    const obs = parsePcap(pcap);
    expect(obs.syns).toEqual([{ ip: "93.184.216.34", port: 443 }]);
  });

  it("parses a Linux SLL2 frame — the link type `-i any` captures actually use", () => {
    // Regression: real sandbox captures are SLL2 (276), not RAW_IP. The
    // capture path filters to SYN/DNS/TLS and writes SLL2; if the parser
    // ever stopped reading this link type, every runtime ledger would go
    // silently empty (a connection to api.github.com would vanish).
    const pcap = bytes(
      pcapGlobalHeader(LINKTYPE_LINUX_SLL2),
      pcapRecord(sll2(0x0800, ipv4(6, [140, 82, 116, 6], tcp(443, 0x02)))),
    );
    expect(parsePcap(pcap).syns).toEqual([{ ip: "140.82.116.6", port: 443 }]);
  });

  it("records an outbound IPv6 TCP SYN with a compressed address", () => {
    // 2606:4700:4700::1111 (Cloudflare DNS over IPv6).
    const dst = [0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11];
    const pcap = bytes(pcapGlobalHeader(LINKTYPE_RAW_IP), pcapRecord(ipv6(6, dst, tcp(443, 0x02))));
    // IPv6-only egress used to be invisible; the ledger's whole value is
    // seeing where an artifact phones, so this must be caught.
    expect(parsePcap(pcap).syns).toEqual([{ ip: "2606:4700:4700::1111", port: 443 }]);
  });

  it("parses a DNS query carried over IPv6 UDP", () => {
    const dst = [0x20, 0x01, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88];
    const pcap = bytes(
      pcapGlobalHeader(LINKTYPE_RAW_IP),
      pcapRecord(ipv6(17, dst, udp(40000, 53, dnsQuery("api.telegram.org")))),
    );
    expect(parsePcap(pcap).dnsQueries).toEqual(["api.telegram.org"]);
  });

  it("notes IPv6 packets with extension headers instead of dropping them silently", () => {
    // next-header 0 = Hop-by-Hop options (an extension header).
    const dst = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    const notes: string[] = [];
    const pcap = bytes(pcapGlobalHeader(LINKTYPE_RAW_IP), pcapRecord(ipv6(0, dst, tcp(443, 0x02))));
    parsePcap(pcap, notes);
    expect(notes.some((n) => /extension headers/.test(n))).toBe(true);
  });

  it("ignores SYN-ACK (inbound handshake completion), only initiations", () => {
    const pcap = bytes(
      pcapGlobalHeader(LINKTYPE_RAW_IP),
      pcapRecord(ipv4(6, [1, 1, 1, 1], tcp(443, 0x12))), // SYN+ACK
    );
    expect(parsePcap(pcap).syns).toEqual([]);
  });

  it("extracts a DNS query name", () => {
    const pcap = bytes(
      pcapGlobalHeader(LINKTYPE_RAW_IP),
      pcapRecord(ipv4(17, [8, 8, 8, 8], udp(40000, 53, dnsQuery("api.telegram.org")))),
    );
    expect(parsePcap(pcap).dnsQueries).toEqual(["api.telegram.org"]);
  });

  it("maps an IP to a hostname from a DNS answer", () => {
    const pcap = bytes(
      pcapGlobalHeader(LINKTYPE_RAW_IP),
      pcapRecord(
        ipv4(17, [10, 0, 0, 2], udp(53, 40000, dnsAnswer("evil.example.com", [1, 2, 3, 4]))),
      ),
    );
    const obs = parsePcap(pcap);
    expect(obs.dnsAnswers.get("1.2.3.4")).toBe("evil.example.com");
  });

  it("reads SNI from a TLS ClientHello", () => {
    const hello = tlsClientHello("api.openai.com");
    expect(parseSni(Uint8Array.from(hello), 0, hello.length)).toBe("api.openai.com");
  });

  it("returns nothing on a non-pcap blob without throwing", () => {
    const obs = parsePcap(Uint8Array.from([1, 2, 3, 4, 5]));
    expect(obs.syns).toEqual([]);
  });
});

describe("parseStrace", () => {
  it("parses a connect() into ip:port", () => {
    const log = `1234 connect(7<socket:[123]>, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("140.82.112.3")}, 16) = 0`;
    expect(parseStrace(log).connects).toEqual([{ ip: "140.82.112.3", port: 443 }]);
  });

  it("parses execve argv", () => {
    const log = `1234 execve("/bin/sh", ["/bin/sh", "-c", "curl evil.test"], 0x7ff /* 20 vars */) = 0`;
    expect(parseStrace(log).commands).toEqual([["/bin/sh", "-c", "curl evil.test"]]);
  });

  it("classifies open flags into read vs write and records unlink as delete", () => {
    const log = [
      `openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3`,
      `openat(AT_FDCWD, "/tmp/out.txt", O_WRONLY|O_CREAT, 0644) = 4`,
      `unlinkat(AT_FDCWD, "/tmp/gone", 0) = 0`,
    ].join("\n");
    const s = parseStrace(log);
    expect(s.files.get("/etc/passwd")).toEqual({ read: true, write: false, delete: false });
    expect(s.files.get("/tmp/out.txt")).toEqual({ read: false, write: true, delete: false });
    expect(s.files.get("/tmp/gone")).toEqual({ read: false, write: false, delete: true });
  });
});

describe("buildLedger", () => {
  it("names connection IPs from DNS answers and drops workspace-internal files", () => {
    const pcap = bytes(
      pcapGlobalHeader(LINKTYPE_RAW_IP),
      pcapRecord(
        ipv4(17, [10, 0, 0, 2], udp(53, 40000, dnsAnswer("api.telegram.org", [5, 6, 7, 8]))),
      ),
      pcapRecord(ipv4(6, [5, 6, 7, 8], tcp(443, 0x02))),
    );
    const strace = [
      `openat(AT_FDCWD, "/workspace/index.js", O_RDONLY) = 3`, // internal → dropped
      `openat(AT_FDCWD, "/root/.ssh/id_rsa", O_RDONLY) = -1 ENOENT`, // sensitive → kept
    ].join("\n");
    const raw: RawCapture = {
      pcap,
      straceLogs: [strace],
      networkCaptured: true,
      syscallsCaptured: true,
      notes: [],
    };
    const ledger = buildLedger(raw, "/workspace");
    expect(ledger.connections).toContainEqual({
      ip: "5.6.7.8",
      port: 443,
      protocol: "tcp",
      host: "api.telegram.org",
    });
    expect(ledger.files.map((f) => f.path)).toEqual(["/root/.ssh/id_rsa"]);
  });

  it("reports captured=false honestly when capture did not run", () => {
    const ledger = buildLedger(
      { networkCaptured: false, syscallsCaptured: false, notes: ["tcpdump: not present"] },
      "/workspace",
    );
    expect(ledger.captured).toEqual({ network: false, syscalls: false });
    expect(ledger.connections).toEqual([]);
    expect(ledger.notes).toContain("tcpdump: not present");
  });
});

describe("analyzeLedger", () => {
  const ledgerWith = (hosts: { host?: string; ip: string; port: number }[]) => ({
    captured: { network: true, syscalls: true },
    notes: [],
    connections: hosts.map((h) => ({ ...h, protocol: "tcp" as const })),
    dns: [],
    files: [],
    commands: [],
  });

  it("flags a host that is neither declared, documented, nor infra", () => {
    const a = analyzeLedger(ledgerWith([{ host: "evil.example.com", ip: "1.2.3.4", port: 443 }]), {
      declaredHosts: ["api.telegram.org"],
      docText: "This server talks to api.telegram.org.",
    });
    expect(a.undeclaredHosts).toEqual(["evil.example.com"]);
  });

  it("credits a declared host and its subdomains", () => {
    const a = analyzeLedger(
      ledgerWith([
        { host: "api.telegram.org", ip: "5.6.7.8", port: 443 },
        { host: "cdn.telegram.org", ip: "5.6.7.9", port: 443 },
      ]),
      { declaredHosts: ["telegram.org"] },
    );
    expect(a.undeclaredHosts).toEqual([]);
    expect(a.declaredContacted).toContain("api.telegram.org");
  });

  it("credits a host named only in the docs", () => {
    const a = analyzeLedger(ledgerWith([{ host: "api.openai.com", ip: "1.1.1.1", port: 443 }]), {
      docText: "Sends completions to api.openai.com for summaries.",
    });
    expect(a.undeclaredHosts).toEqual([]);
  });

  it("never charges package-registry infra as undeclared", () => {
    const a = analyzeLedger(
      ledgerWith([{ host: "registry.npmjs.org", ip: "1.1.1.1", port: 443 }]),
      {},
    );
    expect(a.undeclaredHosts).toEqual([]);
  });

  it("raises an SSRF flag for the cloud metadata endpoint", () => {
    const a = analyzeLedger(ledgerWith([{ ip: "169.254.169.254", port: 80 }]), {});
    expect(a.flags.some((f) => f.includes("metadata"))).toBe(true);
  });

  it("does not flag private/loopback IPs as undeclared", () => {
    const a = analyzeLedger(ledgerWith([{ ip: "127.0.0.1", port: 8080 }]), {});
    expect(a.undeclaredHosts).toEqual([]);
    expect(a.flags).toEqual([]);
  });
});

describe("extractDocHosts", () => {
  it("finds hostnames and rejects filenames", () => {
    const hosts = extractDocHosts("Talks to api.example.com. See index.js and setup.py.");
    expect(hosts.has("api.example.com")).toBe(true);
    expect(hosts.has("index.js")).toBe(false);
    expect(hosts.has("setup.py")).toBe(false);
  });
});
