/**
 * V2ray/Trojan/SS URI to Clash Proxy Converter
 * Supports: vmess://, vless://, trojan://, ss://
 */

import type { AnyJson } from "./type";

export type ProxyProtocol = "vmess" | "vless" | "trojan" | "ss";

export interface ParsedProxy {
  name: string;
  protocol: ProxyProtocol;
  server: string;
  port: number;
  [key: string]: unknown;
}

/**
 * Decode base64 to string, handling URL-safe base64
 */
function base64Decode(str: string): string {
  // URL-safe base64 → standard base64
  const standardBase64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const padding = standardBase64.length % 4;
  const padded = padding > 0 ? standardBase64 + "=".repeat(4 - padding) : standardBase64;
  try {
    return decodeURIComponent(
      atob(padded)
        .split("")
        .map((c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
        .join(""),
    );
  } catch {
    return atob(padded);
  }
}

/**
 * Parse vmess:// URI
 * Format: vmess://(base64 JSON)
 */
function parseVmess(uri: string): ParsedProxy | null {
  const payload = uri.slice(8); // remove "vmess://"
  let jsonStr: string;
  try {
    jsonStr = base64Decode(payload);
  } catch {
    return null;
  }

  let json: AnyJson;
  try {
    json = JSON.parse(jsonStr);
  } catch {
    return null;
  }

  const proxy: ParsedProxy = {
    name: String(json.ps || json.remark || "vmess"),
    protocol: "vmess",
    server: String(json.add || json.address || json.host),
    port: Number(json.port || json.port),
  };

  // vmess specific fields
  const net = String(json.net || "tcp").toLowerCase();
  const type = String(json.type || "none").toLowerCase();
  const tls = String(json.tls || "none").toLowerCase();

  proxy.type = "vmess";
  proxy.uuid = String(json.id || json.uuid || "");
  proxy.alterId = Number(json.aid || json.alterId || 0);
  proxy.network = net;
  proxy["client-fingerprint"] = "chrome"; // default

  if (net === "tcp") {
    if (type !== "none") {
      proxy["tcp-type"] = type;
    }
  } else if (net === "ws") {
    proxy["ws-opts"] = {
      path: String(json.path || "/"),
      headers: {
        Host: String(json.host || json.headers?.Host || ""),
      },
    };
  } else if (net === "grpc") {
    proxy["grpc-opts"] = {
      "grpc-service-name": String(json.path || "").replace(/^\//, ""),
    };
  } else if (net === "h2") {
    proxy["h2-opts"] = {
      path: String(json.path || "/"),
      host: String(json.host || ""),
    };
  }

  if (tls === "tls" || tls === "reality") {
    proxy.tls = true;
    if (json.sni) {
      proxy.sni = String(json.sni);
    }
    if (tls === "reality") {
      proxy.reality = true;
      proxy["public-key"] = String(json.pbk || "");
      proxy["short-id"] = String(json.sid || json.shortId || "");
    }
  }

  return proxy;
}

/**
 * Parse vless:// URI
 * Format: vless://uuid@server:port?params#name
 */
function parseVless(uri: string): ParsedProxy | null {
  // vless://f81f5afc-7a77-3a82-b500-69f62ae1b69e@103.86.888.88:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx&sid=xxxxxxxx&type=tcp&headerType=none&network=tcp#US-01
  const match = uri.match(/^vless:\/\/([^@]+)@([^:]+):(\d+)(\?[^#]*)?(#.*)?$/i);
  if (!match) return null;

  const [, uuid, server, port, queryStr = "", hash = ""] = match;
  const params = new URLSearchParams(queryStr.slice(1));

  const name = decodeURIComponent(hash.slice(1)) || "vless";

  const network = params.get("network") || "tcp";
  const type = params.get("type") || "none";
  const security = params.get("security") || "";
  const proxy: ParsedProxy = {
    name,
    protocol: "vless",
    type: "vless",
    server,
    port: Number(port),
    uuid,
    "client-fingerprint": params.get("fp") || "chrome",
  };

  if (security === "tls" || security === "reality") {
    proxy.tls = true;
    if (params.get("sni")) {
      proxy.sni = params.get("sni")!;
    }
    if (params.get("alpn")) {
      proxy.alpn = params.get("alpn")!.split(",");
    }
  }

  if (security === "reality") {
    proxy.reality = true;
    proxy["public-key"] = params.get("pbk") || "";
    proxy["short-id"] = params.get("sid") || "";
  }

  if (network === "tcp") {
    if (type !== "none") {
      proxy["tcp-type"] = type;
    }
  } else if (network === "ws") {
    proxy.network = "ws";
    proxy["ws-opts"] = {
      path: params.get("path") || "/",
      headers: {
        Host: params.get("host") || "",
      },
    };
  } else if (network === "grpc") {
    proxy.network = "grpc";
    proxy["grpc-opts"] = {
      "grpc-service-name": (params.get("serviceName") || params.get("path") || "").replace(/^\//, ""),
    };
  }

  return proxy;
}

/**
 * Parse trojan:// URI
 * Format: trojan://password@server:port?params#name
 */
function parseTrojan(uri: string): ParsedProxy | null {
  // trojan://password@server:port?secureNaming=true&sni=example.com#Name
  const match = uri.match(/^trojan:\/\/([^@]+)@([^:]+):(\d+)(\?[^#]*)?(#.*)?$/i);
  if (!match) return null;

  const [, password, server, port, queryStr = "", hash = ""] = match;
  const params = new URLSearchParams(queryStr.slice(1));

  const name = decodeURIComponent(hash.slice(1)) || "trojan";

  const proxy: ParsedProxy = {
    name,
    protocol: "trojan",
    type: "trojan",
    server,
    port: Number(port),
    password,
    "client-fingerprint": params.get("fp") || "chrome",
  };

  if (params.get("sni")) {
    proxy.sni = params.get("sni")!;
  }
  if (params.get("alpn")) {
    proxy.alpn = params.get("alpn")!.split(",");
  }
  if (params.get("type") === "trojan") {
    // naiveprotocol fallback-free
  }

  const network = params.get("network") || "tcp";

  if (network === "ws") {
    proxy.network = "ws";
    proxy["ws-opts"] = {
      path: params.get("path") || "/",
      headers: {
        Host: params.get("host") || "",
      },
    };
  } else if (network === "grpc") {
    proxy.network = "grpc";
    proxy["grpc-opts"] = {
      "grpc-service-name": (params.get("serviceName") || "").replace(/^\//, ""),
    };
  }

  return proxy;
}

/**
 * Parse ss:// URI
 * Format: ss://(base64 userinfo)@server:port#name
 * Or: ss://(base64 method:password)@server:port?plugin=name;params#name
 */
function parseSs(uri: string): ParsedProxy | null {
  // ss://_BASE64_@server:port?plugin=obfs-local%3Bobfs%3Dhttp%3Bhost%3Dgoogle.com#Name
  const withoutScheme = uri.slice(5); // remove "ss://"
  const hashIdx = withoutScheme.indexOf("#");
  const name = hashIdx >= 0 ? decodeURIComponent(withoutScheme.slice(hashIdx + 1)) : "ss";
  const rest = hashIdx >= 0 ? withoutScheme.slice(0, hashIdx) : withoutScheme;

  const atIdx = rest.lastIndexOf("@");
  if (atIdx < 0) return null;

  const userinfo = rest.slice(0, atIdx);
  const hostPart = rest.slice(atIdx + 1);
  const colonIdx = hostPart.lastIndexOf(":");
  if (colonIdx < 0) return null;

  const server = hostPart.slice(0, colonIdx);
  const port = Number(hostPart.slice(colonIdx + 1));

  // Decode userinfo
  let method = "aes-256-gcm";
  let password = "";
  try {
    const decoded = base64Decode(userinfo);
    const colonIdx2 = decoded.indexOf(":");
    if (colonIdx2 >= 0) {
      method = decoded.slice(0, colonIdx2);
      password = decoded.slice(colonIdx2 + 1);
    } else {
      password = decoded;
    }
  } catch {
    return null;
  }

  const proxy: ParsedProxy = {
    name,
    protocol: "ss",
    type: "ss",
    server,
    port,
    cipher: method,
    password,
  };

  // Parse plugin (SIP002 style)
  // ss://BASE64@host:port?plugin=obfs-local%3Bobfs%3Dhttp%3Bhost%3Dgoogle.com
  const pluginStr = new URLSearchParams(rest).get("plugin");
  if (pluginStr) {
    const pluginParams = new URLSearchParams("?" + pluginStr.replace(/;/g, "&"));
    const pluginName = pluginParams.get("plugin") || pluginStr.split(";")[0];
    if (pluginName === "obfs-local" || pluginName === "simple-obfs") {
      const obfs = pluginParams.get("obfs") || pluginParams.get("obfs-local") || "http";
      proxy.plugin = "obfs";
      proxy["plugin-opts"] = {
        mode: obfs === "http" ? "http" : "tls",
        host: pluginParams.get("host") || "",
      };
    } else if (pluginName === "v2ray-plugin") {
      proxy.plugin = "v2ray-plugin";
      proxy["plugin-opts"] = {
        mode: pluginParams.get("mode") || "websocket",
        path: pluginParams.get("path") || "/",
        host: pluginParams.get("host") || "",
        tls: pluginParams.get("tls") === "true",
      };
    }
  }

  return proxy;
}

/**
 * Check if a line is a URI
 */
function isUri(line: string): ProxyProtocol | null {
  const trimmed = line.trim();
  if (trimmed.startsWith("vmess://")) return "vmess";
  if (trimmed.startsWith("vless://")) return "vless";
  if (trimmed.startsWith("trojan://")) return "trojan";
  if (trimmed.startsWith("ss://")) return "ss";
  return null;
}

/**
 * Parse a single URI line
 */
function parseUri(line: string): ParsedProxy | null {
  const trimmed = line.trim();
  if (trimmed.startsWith("vmess://")) return parseVmess(trimmed);
  if (trimmed.startsWith("vless://")) return parseVless(trimmed);
  if (trimmed.startsWith("trojan://")) return parseTrojan(trimmed);
  if (trimmed.startsWith("ss://")) return parseSs(trimmed);
  return null;
}

/**
 * Convert URI content (multi-line) to Clash proxy array
 * @param content Raw URI text content (one URI per line)
 * @returns Clash proxies array
 */
export function convertUrisToProxies(content: string): AnyJson {
  const lines = content
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"));
  const proxies: ParsedProxy[] = [];

  for (const line of lines) {
    const parsed = parseUri(line);
    if (parsed) {
      proxies.push(parsed);
    }
  }

  return proxies;
}

/**
 * Detect if content is URI-based (non-YAML subscription)
 */
export function isUriBasedContent(content: string): boolean {
  const firstLine = content.split(/\r?\n/)[0]?.trim();
  if (!firstLine) return false;
  return isUri(firstLine) !== null;
}

/**
 * Convert URI-based subscription to minimal Clash config
 */
export function convertUriToClashConfig(content: string, _profile: string): AnyJson {
  const proxies = convertUrisToProxies(content);

  return {
    proxies: proxies,
  };
}
