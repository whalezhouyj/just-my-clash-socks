import type { IncomingMessage, ServerResponse } from "http";
import https from "https";
import dns from "dns/promises";

interface SSProxy {
  name: string;
  type: "ss";
  server: string;
  port: number;
  cipher: string;
  password: string;
  udp: boolean;
}

interface VMessProxy {
  name: string;
  type: "vmess";
  server: string;
  port: number;
  uuid: string;
  alterId: number;
  cipher: string;
  udp: boolean;
  tls: boolean;
  network: string;
  "ws-opts"?: {
    path: string;
    headers: { Host: string };
  };
  "h2-opts"?: {
    host: string[];
    path: string;
  };
  "grpc-opts"?: {
    "grpc-service-name": string;
  };
  servername?: string;
}

type ClashProxy = SSProxy | VMessProxy;

const RULES_BY_ID_ENV = "JMS_CLASH_RULES_BY_ID";

const DEFAULT_RULES = [
  "DOMAIN-SUFFIX,local,DIRECT",
  "IP-CIDR,127.0.0.0/8,DIRECT",
  "IP-CIDR,10.0.0.0/8,DIRECT",
  "IP-CIDR,172.16.0.0/12,DIRECT",
  "IP-CIDR,192.168.0.0/16,DIRECT",
  "GEOIP,CN,DIRECT",
  "MATCH,Proxy",
];

function safeBase64Decode(str: string): string {
  const cleaned = str.replace(/-/g, "+").replace(/_/g, "/");
  const padded =
    cleaned.length % 4 === 0
      ? cleaned
      : cleaned + "=".repeat(4 - (cleaned.length % 4));
  return Buffer.from(padded, "base64").toString("utf-8");
}

function parseSSUri(uri: string): ClashProxy | null {
  try {
    const withoutScheme = uri.replace(/^ss:\/\//, "");
    const hashIdx = withoutScheme.lastIndexOf("#");
    const encoded = hashIdx < 0 ? withoutScheme : withoutScheme.slice(0, hashIdx);
    const rawName = hashIdx < 0 ? "" : withoutScheme.slice(hashIdx + 1);
    const name = decodeURIComponent(rawName) || "SS Node";

    const decoded = safeBase64Decode(encoded);
    const atIdx = decoded.lastIndexOf("@");

    if (atIdx < 0) return null;

    const userinfo = decoded.slice(0, atIdx);
    const hostinfo = decoded.slice(atIdx + 1);
    const colonIdx = userinfo.indexOf(":");
    if (colonIdx < 0) return null;

    const cipher = userinfo.slice(0, colonIdx);
    const password = userinfo.slice(colonIdx + 1);

    const [server, portStr] = hostinfo.split(":");
    const port = parseInt(portStr, 10);

    return {
      name,
      type: "ss",
      server,
      port,
      cipher,
      password,
      udp: true,
    };
  } catch {
    return null;
  }
}

function parseVMessUri(uri: string): ClashProxy | null {
  try {
    const withoutScheme = uri.replace(/^vmess:\/\//, "");
    const decoded = safeBase64Decode(withoutScheme);
    const cfg = JSON.parse(decoded);

    const name = cfg.ps || "VMess Node";
    const server = cfg.add || "";
    const port = parseInt(cfg.port, 10) || 0;
    const uuid = cfg.id || "";
    const alterId = parseInt(cfg.aid, 10) || 0;
    const network = cfg.net || "tcp";
    const tls = cfg.tls === "tls";
    const host = cfg.host || "";
    const path = cfg.path || "/";
    const sni = cfg.sni || "";

    if (!server || !port || !uuid) return null;

    const proxy: VMessProxy = {
      name,
      type: "vmess",
      server,
      port,
      uuid,
      alterId,
      cipher: "auto",
      udp: true,
      tls,
      network,
    };

    if (sni) {
      proxy.servername = sni;
    }

    if (network === "ws") {
      proxy["ws-opts"] = {
        path,
        headers: { Host: host || server },
      };
    } else if (network === "h2" || network === "http") {
      proxy["h2-opts"] = {
        host: [host || server],
        path,
      };
    } else if (network === "grpc") {
      proxy["grpc-opts"] = {
        "grpc-service-name": path.replace(/\//g, "") || "",
      };
    }

    return proxy;
  } catch {
    return null;
  }
}

function yamlStr(v: string): string {
  return `"${v.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function getRulesForSubscriptionId(id: string): string[] {
  const rawRulesById = process.env[RULES_BY_ID_ENV];

  // 没有配置私有规则时保持默认配置，方便本地开发和未定制订阅继续工作。
  if (!rawRulesById) {
    return DEFAULT_RULES;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawRulesById);
  } catch (err) {
    if (err instanceof SyntaxError) {
      throw new Error(`${RULES_BY_ID_ENV} must be valid JSON`);
    }
    throw err;
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`${RULES_BY_ID_ENV} must be a JSON object keyed by subscription id`);
  }

  const rules = (parsed as Record<string, unknown>)[id];

  // 只对命中的订阅 id 使用扩展规则，避免一个人的私有策略影响其它订阅。
  if (rules === undefined) {
    return DEFAULT_RULES;
  }

  if (!isStringArray(rules)) {
    throw new Error(`${RULES_BY_ID_ENV}.${id} must be an array of Clash rule strings`);
  }

  return rules;
}

function buildProxyYaml(p: ClashProxy): string {
  const lines: string[] = [];
  lines.push(`  - name: ${yamlStr(p.name)}`);
  lines.push(`    type: ${p.type}`);

  if (p.type === "ss") {
    lines.push(`    server: ${p.server}`);
    lines.push(`    port: ${p.port}`);
    lines.push(`    cipher: ${p.cipher}`);
    lines.push(`    password: ${yamlStr(p.password)}`);
  } else {
    lines.push(`    server: ${p.server}`);
    lines.push(`    port: ${p.port}`);
    lines.push(`    uuid: ${p.uuid}`);
    lines.push(`    alterId: ${p.alterId}`);
    lines.push(`    cipher: ${p.cipher}`);
    if (p.tls) {
      lines.push(`    tls: true`);
      if (p.servername) lines.push(`    servername: ${yamlStr(p.servername)}`);
    }
    if (p.network !== "tcp") {
      lines.push(`    network: ${p.network}`);
    }
    if (p["ws-opts"]) {
      lines.push(`    ws-opts:`);
      lines.push(`      path: ${yamlStr(p["ws-opts"].path)}`);
      lines.push(`      headers:`);
      lines.push(`        Host: ${yamlStr(p["ws-opts"].headers.Host)}`);
    }
    if (p["h2-opts"]) {
      lines.push(`    h2-opts:`);
      lines.push(`      host:`);
      for (const h of p["h2-opts"].host) {
        lines.push(`        - ${yamlStr(h)}`);
      }
      lines.push(`      path: ${yamlStr(p["h2-opts"].path)}`);
    }
    if (p["grpc-opts"]) {
      lines.push(`    grpc-opts:`);
      lines.push(`      grpc-service-name: ${yamlStr(p["grpc-opts"]["grpc-service-name"])}`);
    }
  }
  if (p.udp) lines.push(`    udp: true`);
  return lines.join("\n");
}

function buildClashConfig(proxies: ClashProxy[], rules: string[]): string {
  const proxyNames = proxies.map((p) => p.name);
  const nameList = proxyNames.map((n) => `      - ${yamlStr(n)}`).join("\n");

  const parts: string[] = [];
  parts.push("mixed-port: 7890");
  parts.push("allow-lan: false");
  parts.push("mode: rule");
  parts.push("log-level: info");
  parts.push("external-controller: 127.0.0.1:9090");
  parts.push("proxies:");
  for (const p of proxies) {
    parts.push(buildProxyYaml(p));
  }
  parts.push("proxy-groups:");
  parts.push(`  - name: ${yamlStr("Proxy")}`);
  parts.push("    type: select");
  parts.push("    proxies:");
  parts.push(`      - ${yamlStr("Auto")}`);
  parts.push("      - DIRECT");
  parts.push(nameList);
  parts.push(`  - name: ${yamlStr("Auto")}`);
  parts.push("    type: url-test");
  parts.push("    proxies:");
  parts.push(nameList);
  parts.push("    url: http://www.gstatic.com/generate_204");
  parts.push("    interval: 300");
  parts.push("rules:");
  for (const rule of rules) {
    parts.push(`  - ${yamlStr(rule)}`);
  }
  parts.push("");
  return parts.join("\n");
}

async function fetchWithPublicDNS(
  urlStr: string,
  opts: { headers?: Record<string, string> } = {},
  redirectCount = 0
): Promise<{ ok: boolean; status: number; text: () => Promise<string> }> {
  const MAX_REDIRECTS = 3;
  const url = new URL(urlStr);
  const hostname = url.hostname;

  const resolver = new dns.Resolver();
  resolver.setServers(["1.1.1.1", "8.8.8.8"]);
  const addresses = await resolver.resolve4(hostname);
  const ip = addresses[0];

  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: ip,
        port: 443,
        path: url.pathname + url.search,
        method: "GET",
        servername: hostname,
        headers: {
          Host: hostname,
          "User-Agent": "just-my-clash-socks/1.0",
          ...opts.headers,
        },
        timeout: 10000,
      },
      async (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", async () => {
          const body = Buffer.concat(chunks).toString("utf-8");
          const status = res.statusCode || 500;

          if (
            [301, 302, 307, 308].includes(status) &&
            res.headers.location &&
            redirectCount < MAX_REDIRECTS
          ) {
            try {
              const redirectUrl = new URL(
                res.headers.location,
                urlStr
              ).toString();
              const redirected = await fetchWithPublicDNS(
                redirectUrl,
                opts,
                redirectCount + 1
              );
              resolve(redirected);
            } catch (err) {
              reject(err);
            }
            return;
          }

          resolve({
            ok: status >= 200 && status < 400,
            status,
            text: () => Promise.resolve(body),
          });
        });
      }
    );
    req.on("error", reject);
    req.on("timeout", () => {
      req.destroy();
      reject(new Error("JMS request timeout"));
    });
    req.end();
  });
}

export default async function handler(
  req: IncomingMessage,
  res: ServerResponse
): Promise<void> {
  try {
    const url = new URL(req.url || "/", `http://${req.headers.host}`);
    const service = url.searchParams.get("service");
    const id = url.searchParams.get("id");

    if (!service || !id) {
      res.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("Missing service or id parameter");
      return;
    }

    const jmsUrl = `https://jmssub.net/members/getsub.php?service=${encodeURIComponent(service)}&id=${encodeURIComponent(id)}`;

    const jmsRes = await fetchWithPublicDNS(jmsUrl);

    if (!jmsRes.ok) {
      res.writeHead(502, { "Content-Type": "text/plain; charset=utf-8" });
      res.end(`Failed to fetch JMS subscription (${jmsRes.status})`);
      return;
    }

    const jmsBody = await jmsRes.text();
    if (!jmsBody.trim()) {
      res.writeHead(502, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("JMS subscription content is empty");
      return;
    }

    const decodedBody = safeBase64Decode(jmsBody.trim());
    const lines = decodedBody.split("\n").filter((l) => l.trim());

    if (lines.length === 0) {
      res.writeHead(502, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("No valid nodes in JMS subscription");
      return;
    }

    const proxies: ClashProxy[] = [];

    for (const line of lines) {
      let parsed: ClashProxy | null = null;

      if (line.startsWith("ss://")) {
        parsed = parseSSUri(line);
      } else if (line.startsWith("vmess://")) {
        parsed = parseVMessUri(line);
      }

      if (parsed) {
        proxies.push(parsed);
      }
    }

    if (proxies.length === 0) {
      res.writeHead(502, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("Unable to parse nodes in JMS subscription");
      return;
    }

    const format = url.searchParams.get("format") || "raw";

    let result: string;
    let contentType: string;

    if (format === "uri") {
      // URI 模式只返回原始节点订阅，不读取 Clash 规则扩展，避免无关 env 配置影响节点导出。
      result = Buffer.from(decodedBody, "utf-8").toString("base64");
      contentType = "text/plain; charset=utf-8";
    } else {
      const rules = getRulesForSubscriptionId(id);
      const yaml = buildClashConfig(proxies, rules);

      if (format === "base64") {
        result = Buffer.from(yaml, "utf-8").toString("base64");
      } else {
        result = yaml;
      }
      contentType = "text/plain; charset=utf-8";
    }

    res.writeHead(200, {
      "Content-Type": contentType,
      "Cache-Control": "max-age=300, s-maxage=300",
      "subscription-userinfo": "",
    });
    res.end(result);
  } catch (err) {
    res.writeHead(500, { "Content-Type": "text/plain; charset=utf-8" });
    res.end(`Server error: ${err instanceof Error ? err.message : "Unknown error"}`);
  }
}
