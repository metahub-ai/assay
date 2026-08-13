/**
 * Runtime behavior ledger — what the artifact ACTUALLY did at runtime,
 * assembled from ground-truth capture rather than transcript strings.
 *
 * Two sources, both captured inside the sandbox while the harness runs:
 *
 *   - a packet capture (`tcpdump -i any`), parsed here for outbound TCP
 *     connections, DNS queries + answers, and TLS SNI — which together
 *     name every host the artifact contacted;
 *   - an strace log of the artifact's process tree, parsed for
 *     `connect()`, file opens/writes/deletes, and `execve()` — file and
 *     process activity the transcript cannot see.
 *
 * The parsers are pure functions over bytes/text with zero dependencies,
 * in keeping with the package's no-runtime-deps rule, and are exercised
 * against synthetic fixtures in tests. Everything degrades honestly: a
 * capture that could not run yields `captured.network=false` plus a
 * note, never a fabricated "no traffic observed".
 *
 * The prior art is OpenSSF package-analysis, which records the same
 * four ledgers (sockets / DNS / files / commands) for npm and PyPI
 * packages. The addition here is the DIFF: observed hosts are compared
 * against what the artifact declared, which is the question a consumer
 * actually has — "it works" is table stakes, "it phones exactly where
 * it says it phones" is trust.
 */

// ---------------------------------------------------------------------
// Ledger types
// ---------------------------------------------------------------------

export interface LedgerConnection {
  ip: string;
  port: number;
  protocol: "tcp" | "udp";
  /** Hostname, when DNS answers or TLS SNI let us name the IP. */
  host?: string;
}

export interface LedgerDnsQuery {
  name: string;
}

export interface LedgerFileAccess {
  path: string;
  read: boolean;
  write: boolean;
  delete: boolean;
}

export interface LedgerCommand {
  argv: string[];
}

export interface RuntimeLedger {
  captured: { network: boolean; syscalls: boolean };
  /** Why parts of the capture are missing or degraded. */
  notes: string[];
  connections: LedgerConnection[];
  dns: LedgerDnsQuery[];
  /** File access OUTSIDE the workspace (workspace-internal is routine). */
  files: LedgerFileAccess[];
  commands: LedgerCommand[];
}

// ---------------------------------------------------------------------
// pcap parsing
// ---------------------------------------------------------------------

interface PcapObservations {
  /** Outbound TCP SYNs (initiations), deduped by ip:port. */
  syns: { ip: string; port: number }[];
  /** UDP destinations other than DNS, deduped. */
  udp: { ip: string; port: number }[];
  dnsQueries: string[];
  /** ip -> hostname learned from DNS A/AAAA answers. */
  dnsAnswers: Map<string, string>;
  /** ip:port -> SNI hostname from TLS ClientHellos. */
  sni: Map<string, string>;
}

const LINKTYPE_ETHERNET = 1;
const LINKTYPE_RAW_IP = 101;
const LINKTYPE_LINUX_SLL = 113;
const LINKTYPE_LINUX_SLL2 = 276;

/**
 * Parse a classic-format pcap (what `tcpdump -w` writes) for the
 * observations above. Unknown link types, IPv6, and truncated packets
 * are skipped rather than fatal — partial sight beats no sight, and the
 * ledger's `notes` say when something was skipped.
 */
export function parsePcap(bytes: Uint8Array, notes: string[] = []): PcapObservations {
  const out: PcapObservations = {
    syns: [],
    udp: [],
    dnsQueries: [],
    dnsAnswers: new Map(),
    sni: new Map(),
  };
  if (bytes.length < 24) {
    notes.push("pcap: file too short for a global header");
    return out;
  }
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const magicBE = dv.getUint32(0, false);
  let le: boolean;
  if (magicBE === 0xa1b2c3d4 || magicBE === 0xa1b23c4d) le = false;
  else if (magicBE === 0xd4c3b2a1 || magicBE === 0x4d3cb2a1) le = true;
  else {
    notes.push("pcap: unrecognized magic — not a classic pcap file");
    return out;
  }
  const linktype = dv.getUint32(20, le);

  const seenSyn = new Set<string>();
  const seenUdp = new Set<string>();
  const seenQuery = new Set<string>();
  let sawIp6Ext = false;

  let off = 24;
  while (off + 16 <= bytes.length) {
    const inclLen = dv.getUint32(off + 8, le);
    const frame = off + 16;
    if (frame + inclLen > bytes.length) break;

    // Link layer → find the start of the IP header. Both IPv4 (0x0800)
    // and IPv6 (0x86dd) are accepted; the version nibble decides how the
    // header is parsed. RAW_IP carries no ethertype, so the nibble is the
    // only signal there.
    let ipStart = -1;
    const IP4 = 0x0800;
    const IP6 = 0x86dd;
    if (linktype === LINKTYPE_ETHERNET && inclLen >= 14) {
      const ethertype = dv.getUint16(frame + 12, false);
      if (ethertype === IP4 || ethertype === IP6) ipStart = frame + 14;
    } else if (linktype === LINKTYPE_LINUX_SLL && inclLen >= 16) {
      const proto = dv.getUint16(frame + 14, false);
      if (proto === IP4 || proto === IP6) ipStart = frame + 16;
    } else if (linktype === LINKTYPE_LINUX_SLL2 && inclLen >= 20) {
      const proto = dv.getUint16(frame + 0, false);
      if (proto === IP4 || proto === IP6) ipStart = frame + 20;
    } else if (linktype === LINKTYPE_RAW_IP) {
      ipStart = frame;
    }

    const frameEnd = frame + inclLen;
    if (ipStart >= 0 && ipStart + 1 <= frameEnd) {
      const version = bytes[ipStart]! >> 4;
      // Resolve (dstIp, l4 protocol, l4 offset) for whichever IP version
      // this is; the TCP/UDP handling below is identical for both.
      let dstIp: string | null = null;
      let proto = -1;
      let l4 = -1;
      if (version === 4 && ipStart + 20 <= frameEnd) {
        const ihl = (bytes[ipStart]! & 0x0f) * 4;
        proto = bytes[ipStart + 9]!;
        dstIp = ipv4At(bytes, ipStart + 16);
        l4 = ipStart + ihl;
      } else if (version === 6 && ipStart + 40 <= frameEnd) {
        // Fixed 40-byte header. Next-header at +6; destination address at
        // +24 (16 bytes). Extension headers (Hop-by-Hop, Routing, …) chain
        // via next-header and would need walking — rare inside the
        // sandbox, so the common no-extension case is handled and anything
        // else is noted rather than silently dropped.
        const nextHdr = bytes[ipStart + 6]!;
        if (nextHdr === 6 || nextHdr === 17) {
          proto = nextHdr;
          dstIp = ipv6At(bytes, ipStart + 24);
          l4 = ipStart + 40;
        } else {
          sawIp6Ext = true;
        }
      }

      if (dstIp !== null && l4 >= 0) {
        if (proto === 6 && l4 + 20 <= frameEnd) {
          // TCP
          const dstPort = dv.getUint16(l4 + 2, false);
          const dataOffset = (bytes[l4 + 12]! >> 4) * 4;
          const flags = bytes[l4 + 13]!;
          const syn = (flags & 0x02) !== 0;
          const ack = (flags & 0x10) !== 0;
          if (syn && !ack) {
            const key = `${dstIp}:${dstPort}`;
            if (!seenSyn.has(key)) {
              seenSyn.add(key);
              out.syns.push({ ip: dstIp, port: dstPort });
            }
          }
          const payload = l4 + dataOffset;
          if (payload < frameEnd) {
            const host = parseSni(bytes, payload, frameEnd);
            if (host) out.sni.set(`${dstIp}:${dstPort}`, host);
          }
        } else if (proto === 17 && l4 + 8 <= frameEnd) {
          // UDP
          const srcPort = dv.getUint16(l4, false);
          const dstPort = dv.getUint16(l4 + 2, false);
          const payload = l4 + 8;
          if (dstPort === 53 && payload < frameEnd) {
            for (const q of parseDnsNames(bytes, payload, frameEnd, "query")) {
              if (!seenQuery.has(q)) {
                seenQuery.add(q);
                out.dnsQueries.push(q);
              }
            }
          } else if (srcPort === 53 && payload < frameEnd) {
            for (const [ip, name] of parseDnsAnswers(bytes, payload, frameEnd)) {
              out.dnsAnswers.set(ip, name);
            }
          } else {
            const key = `${dstIp}:${dstPort}`;
            if (!seenUdp.has(key)) {
              seenUdp.add(key);
              out.udp.push({ ip: dstIp, port: dstPort });
            }
          }
        }
      }
    }
    off = frame + inclLen;
  }
  if (sawIp6Ext) {
    notes.push("pcap: some IPv6 packets carried extension headers and were not parsed");
  }
  return out;
}

function ipv4At(b: Uint8Array, o: number): string {
  return `${b[o]}.${b[o + 1]}.${b[o + 2]}.${b[o + 3]}`;
}

/**
 * Format the 16 bytes at `o` as an IPv6 address, with the longest run of
 * zero groups collapsed to `::` (RFC 5952-ish). Enough for a ledger
 * label a human reads and a diff keys on — not a canonicalizer.
 */
function ipv6At(b: Uint8Array, o: number): string {
  const groups: number[] = [];
  for (let i = 0; i < 16; i += 2) groups.push((b[o + i]! << 8) | b[o + i + 1]!);
  // Find the longest run of consecutive zero groups (length ≥ 2).
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (groups[i] === 0) {
      if (curStart === -1) curStart = i;
      curLen++;
      if (curLen > bestLen) {
        bestLen = curLen;
        bestStart = curStart;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestLen < 2) return hex.join(":");
  const head = hex.slice(0, bestStart).join(":");
  const tail = hex.slice(bestStart + bestLen).join(":");
  return `${head}::${tail}`;
}

/** Read a DNS name (with compression pointers) starting at `off`. */
function readDnsName(
  b: Uint8Array,
  dnsStart: number,
  off: number,
  end: number,
): { name: string; next: number } | null {
  const labels: string[] = [];
  let o = off;
  let next = -1;
  let hops = 0;
  while (o < end) {
    const len = b[o]!;
    if (len === 0) {
      if (next === -1) next = o + 1;
      break;
    }
    if ((len & 0xc0) === 0xc0) {
      if (o + 1 >= end) return null;
      if (next === -1) next = o + 2;
      const ptr = ((len & 0x3f) << 8) | b[o + 1]!;
      o = dnsStart + ptr;
      if (++hops > 8) return null; // compression loop guard
      continue;
    }
    if (o + 1 + len > end) return null;
    labels.push(new TextDecoder().decode(b.subarray(o + 1, o + 1 + len)));
    o += 1 + len;
  }
  if (labels.length === 0) return null;
  return { name: labels.join(".").toLowerCase(), next };
}

function parseDnsNames(b: Uint8Array, start: number, end: number, which: "query"): string[] {
  void which;
  if (start + 12 > end) return [];
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const qd = dv.getUint16(start + 4, false);
  const names: string[] = [];
  let o = start + 12;
  for (let i = 0; i < qd && o < end; i++) {
    const q = readDnsName(b, start, o, end);
    if (!q) break;
    names.push(q.name);
    o = q.next + 4; // qtype + qclass
  }
  return names;
}

/**
 * Parse A answers → [ip, hostname] pairs, labeling each IP with the
 * QUESTION name rather than the A record's owner.
 *
 * A response to "deb.debian.org?" is usually a CNAME chain
 * (deb.debian.org → debian.map.fastlydns.net → A 146.x). Labeling the
 * IP with the owner of the A record gives the CDN name nobody declared;
 * labeling it with the question name gives "deb.debian.org", which is
 * what docs, allowlists, and install-infra matching actually reference.
 * A DNS response answers exactly one question for our purposes, so every
 * A record in it resolves that question.
 */
function parseDnsAnswers(b: Uint8Array, start: number, end: number): [string, string][] {
  if (start + 12 > end) return [];
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const qd = dv.getUint16(start + 4, false);
  const an = dv.getUint16(start + 6, false);
  const out: [string, string][] = [];
  let o = start + 12;
  let questionName: string | null = null;
  for (let i = 0; i < qd && o < end; i++) {
    const q = readDnsName(b, start, o, end);
    if (!q) return out;
    if (i === 0) questionName = q.name;
    o = q.next + 4;
  }
  for (let i = 0; i < an && o < end; i++) {
    const nm = readDnsName(b, start, o, end);
    if (!nm) return out;
    o = nm.next;
    if (o + 10 > end) return out;
    const type = dv.getUint16(o, false);
    const rdlen = dv.getUint16(o + 8, false);
    const rdata = o + 10;
    if (rdata + rdlen > end) return out;
    if (type === 1 && rdlen === 4) {
      // Label by the question name (head of any CNAME chain); fall back
      // to the record owner if the question was unreadable.
      out.push([ipv4At(b, rdata), questionName ?? nm.name]);
    }
    // AAAA (28) answers exist but v1 skips IPv6 sockets, so labeling
    // IPv6 addresses would label nothing.
    o = rdata + rdlen;
  }
  return out;
}

/** Extract the SNI hostname from a TLS ClientHello, if this payload is one. */
export function parseSni(b: Uint8Array, start: number, end: number): string | null {
  // TLS record: type(1)=0x16 version(2) length(2); handshake type(1)=0x01
  if (end - start < 6 || b[start] !== 0x16) return null;
  if (b[start + 5] !== 0x01) return null;
  let o = start + 5 + 4; // record header + handshake type/length
  o += 2 + 32; // client_version + random
  if (o >= end) return null;
  const sidLen = b[o]!;
  o += 1 + sidLen;
  if (o + 2 > end) return null;
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const csLen = dv.getUint16(o, false);
  o += 2 + csLen;
  if (o + 1 > end) return null;
  const compLen = b[o]!;
  o += 1 + compLen;
  if (o + 2 > end) return null;
  const extTotal = dv.getUint16(o, false);
  o += 2;
  const extEnd = Math.min(o + extTotal, end);
  while (o + 4 <= extEnd) {
    const extType = dv.getUint16(o, false);
    const extLen = dv.getUint16(o + 2, false);
    const extData = o + 4;
    if (extType === 0x0000 && extData + 5 <= extEnd) {
      // server_name list: listLen(2) nameType(1) nameLen(2) name
      const nameLen = dv.getUint16(extData + 3, false);
      const nameStart = extData + 5;
      if (nameStart + nameLen <= extEnd) {
        return new TextDecoder().decode(b.subarray(nameStart, nameStart + nameLen)).toLowerCase();
      }
    }
    o = extData + extLen;
  }
  return null;
}

// ---------------------------------------------------------------------
// strace parsing
// ---------------------------------------------------------------------

interface StraceObservations {
  connects: { ip: string; port: number }[];
  files: Map<string, { read: boolean; write: boolean; delete: boolean }>;
  commands: string[][];
}

const RE_CONNECT_INET =
  /connect\(\d+[^,]*,\s*\{sa_family=AF_INET,\s*sin_port=htons\((\d+)\),\s*sin_addr=inet_addr\("([\d.]+)"\)/;
const RE_OPEN =
  /\b(?:openat|open|creat)\((?:AT_FDCWD(?:<[^>]*>)?,\s*)?"([^"]+)"(?:,\s*([A-Z_|]+))?/;
const RE_UNLINK = /\bunlink(?:at)?\((?:AT_FDCWD(?:<[^>]*>)?,\s*)?"([^"]+)"/;
const RE_RENAME =
  /\brenameat?2?\((?:AT_FDCWD(?:<[^>]*>)?,\s*)?"([^"]+)",\s*(?:AT_FDCWD(?:<[^>]*>)?,\s*)?"([^"]+)"/;
const RE_EXECVE = /\bexecve\("([^"]+)",\s*\[(.*?)\](?:,|\s*\/)/;

/**
 * Parse an strace log produced with
 * `-f -qq -yy -s 256 -e trace=connect,openat,unlinkat,rename,execve,...`.
 * Line-oriented; unfinished/resumed pairs are matched only when the
 * complete form appears on one line (strace with -o merges most).
 */
export function parseStrace(text: string): StraceObservations {
  const out: StraceObservations = { connects: [], files: new Map(), commands: [] };
  const seenConnect = new Set<string>();
  for (const line of text.split("\n")) {
    let m = RE_CONNECT_INET.exec(line);
    if (m) {
      const port = Number(m[1]);
      // Skip port-0 connects: a real outbound TCP connection always has a
      // nonzero destination port. Port 0 shows up for AF_INET probes and
      // pre-connect socket setup, and is noise in the ledger.
      if (port > 0) {
        const key = `${m[2]}:${port}`;
        if (!seenConnect.has(key)) {
          seenConnect.add(key);
          out.connects.push({ ip: m[2]!, port });
        }
      }
      continue;
    }
    m = RE_EXECVE.exec(line);
    if (m) {
      const argv = [...m[2]!.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((x) => x[1]!);
      if (argv.length > 0) out.commands.push(argv);
      continue;
    }
    m = RE_UNLINK.exec(line);
    if (m) {
      entry(out.files, m[1]!).delete = true;
      continue;
    }
    m = RE_RENAME.exec(line);
    if (m) {
      entry(out.files, m[1]!).write = true;
      entry(out.files, m[2]!).write = true;
      continue;
    }
    m = RE_OPEN.exec(line);
    if (m) {
      // A failed open (= -1 ENOENT) is still an ATTEMPT worth recording
      // for sensitive paths, so no exit-status filter here.
      const flags = m[2] ?? "O_RDONLY";
      const e = entry(out.files, m[1]!);
      if (/O_WRONLY|O_RDWR|O_CREAT|O_APPEND|O_TRUNC/.test(flags)) e.write = true;
      else e.read = true;
    }
  }
  return out;
}

function entry(
  map: Map<string, { read: boolean; write: boolean; delete: boolean }>,
  path: string,
): { read: boolean; write: boolean; delete: boolean } {
  let e = map.get(path);
  if (!e) {
    e = { read: false, write: false, delete: false };
    map.set(path, e);
  }
  return e;
}

// ---------------------------------------------------------------------
// Ledger assembly + policy diff
// ---------------------------------------------------------------------

/**
 * System paths whose access is routine process startup, not artifact
 * behavior. Reads under these prefixes are dropped from the ledger;
 * WRITES and DELETES are never dropped.
 */
const ROUTINE_READ_PREFIXES = [
  "/proc/",
  "/sys/",
  "/dev/",
  "/lib",
  "/usr/",
  "/opt/",
  "/etc/ld.so",
  "/etc/ssl",
  "/etc/nsswitch",
  "/etc/resolv.conf",
  "/etc/hosts",
  "/etc/host.conf",
  "/etc/hostname",
  "/etc/netsvc.conf",
  "/etc/svc.conf",
  "/etc/protocols",
  "/etc/services",
  "/etc/passwd",
  "/etc/group",
  "/etc/localtime",
  "/etc/gai.conf",
  "/etc/os-release",
  "/etc/node",
  "/etc/pki",
  "/etc/ca-certificates",
];

/**
 * Benign device/std files whose access is never signal, even on write
 * (`/dev/null` is written constantly). Filtered regardless of op.
 */
const ROUTINE_DEVICES = new Set([
  "/dev/null",
  "/dev/zero",
  "/dev/full",
  "/dev/urandom",
  "/dev/random",
  "/dev/tty",
  "/dev/stdin",
  "/dev/stdout",
  "/dev/stderr",
]);

/**
 * Sensitive paths that are ledger-worthy wherever they live. Deliberately
 * excludes `.npmrc`/`.pypirc` (package managers read them on every
 * install — routine, not signal) and workspace-relative `.env` (dotenv
 * probing its own directory is idiomatic; see SENSITIVE_OUTSIDE).
 */
const SENSITIVE_ANYWHERE = /\/\.(ssh|aws|netrc|gnupg)\b|\/etc\/shadow/;

/** Sensitive only when reached OUTSIDE the workspace. */
const SENSITIVE_OUTSIDE = /credentials\.json|(^|\/)\.env(\.|$)/;

function isSensitive(path: string, inWorkspace: boolean): boolean {
  if (SENSITIVE_ANYWHERE.test(path)) return true;
  return !inWorkspace && SENSITIVE_OUTSIDE.test(path);
}

export interface RawCapture {
  pcap?: Uint8Array;
  straceLogs?: string[];
  networkCaptured: boolean;
  syscallsCaptured: boolean;
  notes: string[];
}

/** Assemble the normalized ledger from raw capture output. */
export function buildLedger(raw: RawCapture, workspace: string): RuntimeLedger {
  const notes = [...raw.notes];
  const connections = new Map<string, LedgerConnection>();
  const dns: string[] = [];
  let dnsAnswers = new Map<string, string>();
  let sni = new Map<string, string>();

  if (raw.pcap && raw.networkCaptured) {
    const p = parsePcap(raw.pcap, notes);
    dns.push(...p.dnsQueries);
    dnsAnswers = p.dnsAnswers;
    sni = p.sni;
    for (const s of p.syns) {
      connections.set(`tcp:${s.ip}:${s.port}`, { ip: s.ip, port: s.port, protocol: "tcp" });
    }
    for (const u of p.udp) {
      connections.set(`udp:${u.ip}:${u.port}`, { ip: u.ip, port: u.port, protocol: "udp" });
    }
  }

  const files = new Map<string, LedgerFileAccess>();
  const commands: LedgerCommand[] = [];
  if (raw.syscallsCaptured && raw.straceLogs) {
    for (const log of raw.straceLogs) {
      const s = parseStrace(log);
      for (const c of s.connects) {
        const key = `tcp:${c.ip}:${c.port}`;
        if (!connections.has(key)) {
          connections.set(key, { ip: c.ip, port: c.port, protocol: "tcp" });
        }
      }
      for (const [path, ops] of s.files) {
        const inWorkspace = path.startsWith(workspace);
        const sensitive = isSensitive(path, inWorkspace);
        const routineRead =
          !ops.write && !ops.delete && ROUTINE_READ_PREFIXES.some((p) => path.startsWith(p));
        const routineDevice = ROUTINE_DEVICES.has(path);
        if ((inWorkspace || routineRead || routineDevice) && !sensitive) continue;
        const existing = files.get(path);
        if (existing) {
          existing.read ||= ops.read;
          existing.write ||= ops.write;
          existing.delete ||= ops.delete;
        } else {
          files.set(path, { path, ...ops });
        }
      }
      for (const argv of s.commands) commands.push({ argv });
    }
  }

  // Name the connection IPs from DNS answers and SNI.
  for (const conn of connections.values()) {
    const viaSni = sni.get(`${conn.ip}:${conn.port}`);
    const viaDns = dnsAnswers.get(conn.ip);
    const host = viaSni ?? viaDns;
    if (host) conn.host = host;
  }

  // Collapse by (host-or-ip, port): DNS round-robin resolves one host to
  // several IPs, and pcap+strace can both see the same flow. A reader
  // wants "contacted api.ipify.org:443", once, not one row per IP.
  const byLabel = new Map<string, LedgerConnection>();
  for (const conn of connections.values()) {
    const key = `${conn.protocol}:${conn.host ?? conn.ip}:${conn.port}`;
    if (!byLabel.has(key)) byLabel.set(key, conn);
  }

  return {
    captured: { network: raw.networkCaptured, syscalls: raw.syscallsCaptured },
    notes,
    connections: [...byLabel.values()],
    dns: [...new Set(dns)].map((name) => ({ name })),
    files: [...files.values()],
    commands,
  };
}

/**
 * Hosts that are evaluation infrastructure, not artifact behavior:
 * package registries and OS mirrors the install step legitimately hits.
 * Suffix-matched (".npmjs.org" covers registry + subdomains).
 */
export const INFRA_HOST_SUFFIXES = [
  "npmjs.org",
  "npmjs.com",
  "github.com",
  "githubusercontent.com",
  "githubassets.com",
  "pypi.org",
  "pythonhosted.org",
  "debian.org",
  "ubuntu.com",
  "alpinelinux.org",
  "nodejs.org",
  "yarnpkg.com",
];

/**
 * Non-routable ranges: recorded, never "undeclared". Covers RFC 1918
 * private, loopback, and link-local, plus the RFC 5737 TEST-NET
 * documentation ranges. The latter can never reach a real host, so a
 * connection to one is sandbox plumbing, not artifact behavior — E2B's
 * microVM routes some internal traffic through `192.0.2.1` (TEST-NET-1),
 * which otherwise showed up as an undeclared host on every E2B run.
 */
function isPrivateIp(ip: string): boolean {
  return (
    ip.startsWith("127.") ||
    ip.startsWith("10.") ||
    ip.startsWith("192.168.") ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    ip.startsWith("169.254.") ||
    ip.startsWith("192.0.2.") || // TEST-NET-1
    ip.startsWith("198.51.100.") || // TEST-NET-2
    ip.startsWith("203.0.113.") || // TEST-NET-3
    ip === "0.0.0.0"
  );
}

/** The cloud metadata endpoint: private, but NEVER routine for an artifact. */
const METADATA_IP = "169.254.169.254";

export interface LedgerAnalysis {
  /** Hosts contacted that match neither declarations, docs, nor infra. */
  undeclaredHosts: string[];
  /** Deterministic red flags: metadata endpoint, sensitive file access. */
  flags: string[];
  /** Hosts contacted and accounted for (declared / docs / infra). */
  declaredContacted: string[];
}

/**
 * Diff the observed ledger against what the artifact declared.
 *
 * `declaredHosts` comes from `allowedHosts` (manifest/config/CLI);
 * `docText` is scanned for hostnames so an artifact whose README says
 * "talks to api.telegram.org" gets credit for saying so. Deliberately
 * WARN-grade, not fail-grade: most working artifacts legitimately call
 * their own API and today nobody declares anything — the ledger's job
 * is to make the undeclared visible, and the flags' job is to catch
 * the handful of patterns that are never legitimate.
 */
export function analyzeLedger(
  ledger: RuntimeLedger,
  policy: { declaredHosts?: string[]; docText?: string; sandbox?: string },
): LedgerAnalysis {
  const declared = new Set((policy.declaredHosts ?? []).map((h) => h.toLowerCase()));
  const docHosts = extractDocHosts(policy.docText ?? "");

  const accounted = (host: string): boolean => {
    const h = host.toLowerCase();
    if (declared.has(h)) return true;
    if (docHosts.has(h)) return true;
    for (const suffix of INFRA_HOST_SUFFIXES) {
      if (h === suffix || h.endsWith(`.${suffix}`)) return true;
    }
    // A declared parent domain covers its subdomains.
    for (const d of declared) {
      if (h.endsWith(`.${d}`)) return true;
    }
    return false;
  };

  const undeclaredHosts = new Set<string>();
  const declaredContacted = new Set<string>();
  const flags: string[] = [];

  // E2B's own microVM contacts the metadata endpoint as part of its
  // operation, so on E2B this fires on every eval and says nothing about
  // the artifact. Suppress it there; the check stays live on every other
  // sandbox (podman, docker, …) where a metadata hit really is the code.
  const metadataIsInfra = policy.sandbox === "e2b";

  for (const conn of ledger.connections) {
    if (conn.ip === METADATA_IP) {
      if (!metadataIsInfra) {
        flags.push(`contacted the cloud metadata endpoint ${METADATA_IP} (SSRF pattern)`);
      }
      continue;
    }
    if (conn.port === 53) continue; // DNS itself, reported via `dns`
    const label = conn.host ?? conn.ip;
    if (conn.host === undefined && isPrivateIp(conn.ip)) continue;
    if (accounted(label)) declaredContacted.add(label);
    else undeclaredHosts.add(label);
  }

  for (const f of ledger.files) {
    // Everything in `ledger.files` already survived the workspace/
    // routine filter; flag only the sensitive subset here.
    if (SENSITIVE_ANYWHERE.test(f.path) || SENSITIVE_OUTSIDE.test(f.path)) {
      const ops = [f.read && "read", f.write && "write", f.delete && "delete"]
        .filter(Boolean)
        .join("/");
      flags.push(`${ops || "accessed"} sensitive path: ${f.path}`);
    }
  }

  return {
    undeclaredHosts: [...undeclaredHosts].sort(),
    declaredContacted: [...declaredContacted].sort(),
    flags,
  };
}

/** Pull hostname-shaped tokens out of documentation text. */
export function extractDocHosts(doc: string): Set<string> {
  const hosts = new Set<string>();
  const re = /\b((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:[a-z]{2,}))\b/gi;
  for (const m of doc.matchAll(re)) {
    const h = m[1]!.toLowerCase();
    // Filenames masquerade as hostnames ("index.js", "setup.py");
    // require a plausible TLD-ish last label.
    if (/\.(js|ts|mjs|cjs|py|json|md|txt|yml|yaml|toml|lock|map|css|html|png|svg|jpg)$/.test(h)) {
      continue;
    }
    hosts.add(h);
  }
  return hosts;
}
