/**
 * parser.js - Header Analyzer (Phase 1)
 * spec: 03_HEADER_ANALYZER.md, 06_RISK_SCORING.md v2 (ヘッダ整合性チェック)
 *
 * Receivedチェーン解析・送信元IP抽出・認証結果(SPF/DKIM/DMARC)抽出・
 * ドメイン整合性/日付異常チェック
 */

"use strict";

const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;

/** 各オクテットが0-255か検証 (specの正規表現は999.999.999.999にもマッチするため) */
function isValidIPv4(ip) {
  return ip.split(".").every((o) => {
    const n = Number(o);
    return o.length <= 3 && n >= 0 && n <= 255;
  });
}

/** プライベート/予約IPの除外 (spec 03 除外対象) */
function isPrivateIP(ip) {
  const [a, b] = ip.split(".").map(Number);
  if (a === 127) return true;                  // loopback
  if (a === 10) return true;                   // 10.0.0.0/8
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true;     // 192.168.0.0/16
  if (a === 169 && b === 254) return true;     // link-local
  if (a === 0 || a >= 224) return true;        // reserved/multicast
  return false;
}

/** 動的ホスト名らしさの簡易判定 (spec 03 dynamic hostname) */
function looksDynamicHostname(host) {
  if (!host) return false;
  return /(dynamic|dyn|dial|dsl|pool|ppp|dhcp|home|cust|client)[-.\d]/i.test(host) ||
         /\d{1,3}[-.]\d{1,3}[-.]\d{1,3}[-.]\d{1,3}/.test(host);
}

/* ---- ドメイン整合性 (spec 06 v2) ---- */

/** ヘッダ値からメールアドレスのドメインを抽出 */
function extractEmailDomain(headerValue) {
  if (!headerValue) return null;
  const m =
    headerValue.match(/<([^<>]*@[^<>]+)>/) ||
    headerValue.match(/([^\s<>"',;]+@[^\s<>"',;]+)/);
  if (!m) return null;
  const domain = m[1].split("@").pop().toLowerCase().replace(/[>;,.\s]+$/, "");
  return domain || null;
}

/** 主要なsecond-level public suffix (spec 15, v0.7.0) */
const SECOND_LEVEL_SUFFIXES = new Set([
  "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "ad.jp", "ed.jp", "gr.jp", "lg.jp",
  "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk",
  "com.au", "net.au", "org.au", "com.cn", "net.cn", "org.cn", "com.tw", "com.hk",
  "com.br", "com.mx", "com.ar", "co.kr", "or.kr", "co.in", "co.nz",
  "com.sg", "com.my", "co.th", "co.id", "co.za",
]);

/** 登録可能ドメイン近似。主要second-level suffixは末尾3ラベル (spec 15, v0.7.0修正) */
function registrableDomain(domain) {
  if (!domain) return null;
  const labels = domain.split(".").filter(Boolean);
  const last2 = labels.slice(-2).join(".");
  if (SECOND_LEVEL_SUFFIXES.has(last2) && labels.length >= 3) {
    return labels.slice(-3).join(".");
  }
  return last2;
}

function sameOrgDomain(d1, d2) {
  return !!(d1 && d2 && registrableDomain(d1) === registrableDomain(d2));
}

/** Dateヘッダと最新Receivedの時刻差が48時間超なら異常 (spec 06 v2) */
function detectDateAnomaly(headers, chain) {
  const dh = headers["date"] && headers["date"][0];
  if (!dh) return false;
  const d = new Date(dh);
  if (isNaN(d.getTime())) return false;
  let ref = null;
  if (chain.length) {
    const tail = chain[0].raw.split(";").pop();
    const r = new Date(tail);
    if (!isNaN(r.getTime())) ref = r;
  }
  if (!ref) ref = new Date();
  return Math.abs(d.getTime() - ref.getTime()) > 48 * 3600 * 1000;
}

/**
 * Receivedヘッダ1行をパース
 * 例: "from mail.example.com (host.example.com [203.0.113.5]) by mx.example.jp ..."
 */
function parseReceivedLine(line) {
  const entry = { raw: line, fromHost: null, ips: [], byHost: null, unknown: false };

  const fromMatch = line.match(/from\s+(\S+)\s*(\(([^)]*)\))?/i);
  if (fromMatch) {
    entry.fromHost = fromMatch[1];
    if (/unknown/i.test(fromMatch[3] || "")) entry.unknown = true;
  }
  const byMatch = line.match(/\bby\s+(\S+)/i);
  if (byMatch) entry.byHost = byMatch[1];

  const ips = (line.match(IPV4_RE) || []).filter(isValidIPv4);
  entry.ips = [...new Set(ips)];
  return entry;
}

/**
 * メールヘッダ全体を解析する
 * @param {Object} headers messages.getFull() の part.headers (キーは小文字)
 * @returns {Object} 解析結果
 */
function analyzeHeaders(headers) {
  const get = (name) => (headers[name] && headers[name][0]) || "";

  const receivedLines = headers["received"] || [];
  // getFull()のreceivedは新しい順 (受信側が上)。送信元は配列の末尾側。
  const chain = receivedLines.map(parseReceivedLine);

  // 末尾(最古=送信元側)から最初のpublic IPを送信元候補とする
  let senderIP = null;
  let senderEntry = null;
  for (let i = chain.length - 1; i >= 0; i--) {
    const pub = chain[i].ips.find((ip) => !isPrivateIP(ip));
    if (pub) {
      senderIP = pub;
      senderEntry = chain[i];
      break;
    }
  }

  // 全public IP (relay経路)
  const allPublicIPs = [
    ...new Set(chain.flatMap((e) => e.ips).filter((ip) => !isPrivateIP(ip))),
  ];

  // ヘッダ整合性チェック (spec 06 v2)
  const fromDomain = extractEmailDomain(get("from"));
  const returnPathDomain = extractEmailDomain(get("return-path"));
  const replyToDomain = extractEmailDomain(get("reply-to"));
  const msgIdMatch = get("message-id").match(/@([A-Za-z0-9.-]+)/);
  const msgIdDomain = msgIdMatch ? msgIdMatch[1].toLowerCase().replace(/\.+$/, "") : null;

  const checks = {
    fromReturnPathMismatch:
      !!(fromDomain && returnPathDomain && !sameOrgDomain(fromDomain, returnPathDomain)),
    replyToMismatch:
      !!(fromDomain && replyToDomain && !sameOrgDomain(fromDomain, replyToDomain)),
    msgIdMismatch:
      !!(fromDomain && msgIdDomain && !sameOrgDomain(fromDomain, msgIdDomain)),
    dateAnomaly: detectDateAnomaly(headers, chain),
    noReceived: chain.length === 0,
    sameDomainRoute: false,
  };

  // 送信側経路(送信元hop以前)が送信ドメインのみ経由なら直送 (spec 06 v3)
  if (fromDomain && senderEntry) {
    const idx = chain.indexOf(senderEntry);
    checks.sameDomainRoute = chain
      .slice(idx)
      .every((e) => e.fromHost && sameOrgDomain(e.fromHost, fromDomain));
  }

  return {
    subject: get("subject"),
    from: get("from"),
    returnPath: get("return-path"),
    messageId: get("message-id"),
    fromDomain,
    relayCount: chain.length,
    chain,
    senderIP,
    senderHost: senderEntry ? senderEntry.fromHost : null,
    senderUnknown: senderEntry ? senderEntry.unknown : false,
    senderDynamic: senderEntry ? looksDynamicHostname(senderEntry.fromHost) : false,
    allPublicIPs,
    auth: parseAuthResults(headers),
    checks,
  };
}

/**
 * Authentication-Results から SPF/DKIM/DMARC を抽出
 * (SPF/DKIM/DMARCは独立ヘッダではないため。spec 02 補足)
 */
function parseAuthResults(headers) {
  const lines = (headers["authentication-results"] || []).join(";");
  const pick = (key) => {
    const m = lines.match(new RegExp(`${key}\\s*=\\s*(\\w+)`, "i"));
    return m ? m[1].toLowerCase() : "none";
  };
  // Received-SPF ヘッダがある場合のフォールバック
  let spf = pick("spf");
  if (spf === "none" && headers["received-spf"]) {
    const m = headers["received-spf"][0].match(/^\s*(\w+)/);
    if (m) spf = m[1].toLowerCase();
  }
  return { spf, dkim: pick("dkim"), dmarc: pick("dmarc") };
}
