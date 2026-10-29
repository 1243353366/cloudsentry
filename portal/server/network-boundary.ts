import { isIP } from "node:net";

const MAX_NETWORKS = 128;
const MAX_INDICATORS = 256;
type JsonRecord = Record<string, unknown>;
type Range = { index: number; family: 4 | 6; bits: number; prefix: number; address: bigint; first: bigint; last: bigint };
type Indicator = { code: string; refs: number[]; assessment: "review_only"; detail: string };

function ipv4Value(host: string): bigint {
  return host.split(".").reduce((value, part) => (value << 8n) + BigInt(Number(part)), 0n);
}

function ipv6Value(host: string): bigint | null {
  let normalized = host;
  if (normalized.includes(".")) {
    const position = normalized.lastIndexOf(":");
    const tail = normalized.slice(position + 1);
    if (isIP(tail) !== 4) return null;
    const value = ipv4Value(tail);
    normalized = `${normalized.slice(0, position + 1)}${(value >> 16n).toString(16)}:${(value & 65535n).toString(16)}`;
  }
  const halves = normalized.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) return null;
  const groups = [...left, ...Array(halves.length === 2 ? missing : 0).fill("0"), ...right];
  if (groups.length !== 8 || groups.some(group => !/^[0-9a-f]{1,4}$/i.test(group))) return null;
  return groups.reduce((value, part) => (value << 16n) + BigInt(parseInt(part, 16)), 0n);
}

function parseRange(value: unknown, index: number): Range | null {
  if (typeof value !== "string" || value.length > 128 || /[\s%]/.test(value)) return null;
  const parts = value.split("/");
  if (parts.length !== 2 || !/^\d{1,3}$/.test(parts[1]!)) return null;
  const family = isIP(parts[0]!);
  if (family !== 4 && family !== 6) return null;
  const bits = family === 4 ? 32 : 128;
  const prefix = Number(parts[1]);
  if (prefix < 0 || prefix > bits) return null;
  const address = family === 4 ? ipv4Value(parts[0]!) : ipv6Value(parts[0]!);
  if (address === null) return null;
  const suffix = (1n << BigInt(bits - prefix)) - 1n;
  const first = address & ~suffix;
  return { index, family, bits, prefix, address, first, last: first + suffix };
}

function object(value: unknown): JsonRecord | null {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as JsonRecord : null;
}

/** Purely examines selected JSON. No socket, command, host inventory or discovery. */
export function reviewNetworkBoundaries(report: JsonRecord) {
  const configuration = object(report.network_configuration) ?? report;
  const supplied = configuration.networks;
  const indicators: Indicator[] = [];
  let indicatorsTruncated = false;
  const add = (indicator: Indicator) => {
    if (indicators.length < MAX_INDICATORS) indicators.push(indicator);
    else indicatorsTruncated = true;
  };
  const ranges: Range[] = [];
  const entries = Array.isArray(supplied) ? supplied.slice(0, MAX_NETWORKS) : [];
  for (let index = 0; index < entries.length; index++) {
    const entry = entries[index];
    const raw = typeof entry === "string" ? entry : object(entry)?.cidr;
    const range = parseRange(raw, index);
    if (!range) {
      add({ code: "invalid_or_unsupported_cidr", refs: [index], assessment: "review_only", detail: "Selected network definition is not a supported IPv4/IPv6 CIDR." });
      continue;
    }
    ranges.push(range);
    if (range.address !== range.first) {
      add({ code: "network_definition_has_host_bits", refs: [index], assessment: "review_only", detail: "A network definition contains host bits. This may be an interface address; verify its intended meaning." });
    }
    if ((range.family === 4 && range.prefix < 24) || (range.family === 6 && range.prefix < 64)) {
      add({ code: "broad_prefix_review", refs: [index], assessment: "review_only", detail: "Prefix is broader than this review's IPv4 /24 or IPv6 /64 reference. Legitimate aggregates are common; this is not a vulnerability finding." });
    }
  }
  for (let left = 0; left < ranges.length; left++) {
    for (let right = left + 1; right < ranges.length; right++) {
      const a = ranges[left]!;
      const b = ranges[right]!;
      if (a.family === b.family && a.first <= b.last && b.first <= a.last) {
        add({ code: "overlapping_network_definitions", refs: [a.index, b.index], assessment: "review_only", detail: "Supplied address ranges overlap. Intentional nesting is possible; compare routes and security policy before changing anything." });
      }
    }
  }
  const routes = Array.isArray(configuration.routes) ? configuration.routes.slice(0, MAX_NETWORKS) : [];
  for (let index = 0; index < routes.length; index++) {
    const route = object(routes[index]);
    const range = parseRange(route?.destination ?? route?.cidr, index);
    if (!range) {
      add({ code: "invalid_or_unsupported_route_cidr", refs: [index], assessment: "review_only", detail: "Selected route destination is not a supported CIDR. Route references are indexed within routes, not networks." });
    } else if (typeof route?.gateway === "string") {
      const family = isIP(route.gateway);
      if (family !== range.family) {
        add({ code: "route_gateway_family_review", refs: [index], assessment: "review_only", detail: "Route gateway and destination address families differ or the gateway is not an IP literal. Device-specific configuration may explain this." });
      }
    }
  }
  const inputTruncated = (Array.isArray(supplied) && supplied.length > MAX_NETWORKS) || (Array.isArray(configuration.routes) && configuration.routes.length > MAX_NETWORKS);
  return {
    status: Array.isArray(supplied) || routes.length ? "customer_supplied_configuration_review" : "not_assessed_no_configuration_supplied",
    provenance: "Unverified customer-selected JSON; not a measurement of the portal host or a visitor's machine.",
    coverage: { networks_reviewed: entries.length, routes_reviewed: routes.length, input_truncated: inputTruncated, indicators_truncated: indicatorsTruncated },
    reference_policy: { ipv4_broad_prefix_below: 24, ipv6_broad_prefix_below: 64, interpretation: "Review thresholds, not access-control or vulnerability thresholds." },
    indicators,
    not_assessed: ["ARP changes or spoofing", "DHCP server authorization", "Actual firewall enforcement", "Reachability or lateral movement", "Device identity or visitor authorization"],
    boundary_notice: "IP addresses and subnet masks are not identity, integrity or authorization evidence. No network probe or remediation was performed. No indicators does not establish safe segmentation.",
  };
}
