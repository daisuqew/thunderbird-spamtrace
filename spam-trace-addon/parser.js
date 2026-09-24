/**
 * parser.js - Header Analyzer (Phase 1)
 * spec: 03_HEADER_ANALYZER.md, 06_RISK_SCORING.md v2 (ヘッダ整合性チェック)
 *
 * Receivedチェーン解析・送信元IP抽出・認証結果(SPF/DKIM/DMARC)抽出・
 * ドメイン整合性/日付異常チェック
 * v1.1.0: 信頼境界による送信元IPの確定、偽装 Received 判定、認証結果の絞り込み
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
  const entry = {
    raw: line, fromHost: null, ips: [], byHost: null, unknown: false,
    fromIP: null, fromRdns: null, time: null, verified: null, // v1.1.0 信頼境界用
  };

  const fromMatch = line.match(/from\s+(\S+)\s*(\(([^)]*)\))?/i);
  if (fromMatch) {
    entry.fromHost = fromMatch[1];
    if (/unknown/i.test(fromMatch[3] || "")) entry.unknown = true;

    // v1.1.0: 受信側MTAが記録した接続元IPと逆引きホスト名 (from句の括弧内)
    const inner = fromMatch[3] || "";
    const ipIn = (inner.match(IPV4_RE) || []).find(isValidIPv4);
    const ipHelo = (fromMatch[1].match(IPV4_RE) || []).find(isValidIPv4); // "from [1.2.3.4]" 形式
    entry.fromIP = ipIn || ipHelo || null;
    const rd = inner.match(/^\s*([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)\.?(?=[\s\[:]|$)/);
    if (rd && !/^[\d.]+$/.test(rd[1])) entry.fromRdns = rd[1].toLowerCase();
  }
  const byMatch = line.match(/\bby\s+(\S+)/i);
  if (byMatch) entry.byHost = byMatch[1];

  const ips = (line.match(IPV4_RE) || []).filter(isValidIPv4);
  entry.ips = [...new Set(ips)];

  const t = new Date(line.split(";").pop());
  if (!isNaN(t.getTime())) entry.time = t.getTime();
  return entry;
}

/* ---- 信頼境界 (v1.1.0) ---- */

/** ホスト名の組織ドメイン (IPやドット無しはnull) */
function orgOf(host) {
  if (!host) return null;
  const h = String(host).toLowerCase().replace(/[.\]]+$/, "").replace(/^\[/, "");
  if (!h.includes(".") || /^[\d.]+$/.test(h) || h.includes(":")) return null;
  return registrableDomain(h);
}

/** ホストが信頼サーバー一覧に一致するか (完全一致 or サブドメイン) */
function hostMatchesList(host, list) {
  if (!host || !list || !list.length) return false;
  const h = String(host).toLowerCase().replace(/\.+$/, "");
  return list.some((e) => {
    const d = String(e).toLowerCase().trim().replace(/^\*\./, "").replace(/\.+$/, "");
    return d && (h === d || h.endsWith("." + d));
  });
}

/**
 * 信頼境界の特定。Receivedを上(受信側)からたどり、自分側の受信サーバーが
 * 外部の公開IPから受け取った最初のホップのindexを返す。見つからなければ -1。
 * - manual: 設定の信頼サーバーが by として記録したホップのみ信頼
 * - auto:   接続元が private IP / 受信ホストと同一組織の逆引き なら内部とみなす
 * 注: 逆引き名は接続元IPの所有者が設定できるため、auto は推定。確実性が必要なら manual。
 */
function findTrustBoundary(chain, trusted) {
  const manual = trusted && trusted.length > 0;
  let entered = false;
  for (let i = 0; i < chain.length; i++) {
    const e = chain[i];
    if (manual) {
      if (!hostMatchesList(e.byHost, trusted)) {
        if (entered) return -1; // 信頼サーバー以外が記録 → 以降は検証不能
        continue;               // 最上部のローカル配送等は読み飛ばす
      }
      entered = true;
      if (!e.fromIP || isPrivateIP(e.fromIP)) continue;
      if (e.fromRdns && hostMatchesList(e.fromRdns, trusted)) continue;
      return i;
    }
    if (!e.fromIP || isPrivateIP(e.fromIP)) continue; // from無し/IPv6/内部
    const byOrg = orgOf(e.byHost);
    const fromOrg = orgOf(e.fromRdns);
    if (byOrg && fromOrg && byOrg === fromOrg) continue; // 同一組織内の中継
    return i;
  }
  return -1;
}

/**
 * メールヘッダ全体を解析する
 * @param {Object} headers messages.getFull() の part.headers (キーは小文字)
 * @returns {Object} 解析結果
 */
function analyzeHeaders(headers, opts = {}) {
  const get = (name) => (headers[name] && headers[name][0]) || "";
  const trusted = (opts.trustedServers || []).filter(Boolean);
  const trustMode = trusted.length ? "manual" : "auto";

  const receivedLines = headers["received"] || [];
  // getFull()のreceivedは新しい順 (受信側が上)。送信元は配列の末尾側。
  const chain = receivedLines.map(parseReceivedLine);

  // 末尾(最古=送信元側)から最初のpublic IP = 自己申告の送信元 (1.0.0までの送信元)
  let claimedOriginIP = null;
  let claimedEntry = null;
  for (let i = chain.length - 1; i >= 0; i--) {
    const pub = chain[i].ips.find((ip) => !isPrivateIP(ip));
    if (pub) {
      claimedOriginIP = pub;
      claimedEntry = chain[i];
      break;
    }
  }

  // v1.1.0: 信頼境界の接続元IPを送信元とする。境界不明時は従来方式(未確認)
  const boundary = findTrustBoundary(chain, trusted);
  let senderIP = claimedOriginIP;
  let senderEntry = claimedEntry;
  if (boundary >= 0) {
    senderIP = chain[boundary].fromIP;
    senderEntry = chain[boundary];
    chain.forEach((e, i) => { e.verified = i <= boundary; });
  }
  const senderVerified = boundary >= 0;

  // 自分側の受信組織 (偽装判定・認証結果の絞り込み用)
  let receiverOrg = null;
  if (boundary >= 0) receiverOrg = orgOf(chain[boundary].byHost);
  if (!receiverOrg) {
    const top = chain.find((e) => orgOf(e.byHost));
    if (top) receiverOrg = orgOf(top.byHost);
  }
  const isOwnServer = trustMode === "manual"
    ? (h) => hostMatchesList(h, trusted)
    : (h) => !!receiverOrg && orgOf(h) === receiverOrg;

  // v1.1.0: 偽装された Received の疑い (境界より下 = 送信者の自己申告部分)
  //  time: 境界ホップより1時間超新しい時刻 (時刻の逆転)
  //  self: 自分側の受信サーバーを名乗る by (注: 転送・メーリングリストで自組織を
  //        一度出て戻ったメールでは正当でも該当し得る = 誤検知の可能性あり)
  const forgedReasons = [];
  if (boundary >= 0) {
    const tB = chain[boundary].time;
    const below = chain.slice(boundary + 1);
    if (tB && below.some((e) => e.time && e.time - tB > 3600 * 1000)) forgedReasons.push("time");
    if (below.some((e) => e.byHost && isOwnServer(e.byHost))) forgedReasons.push("self");
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
    forgedReceived: forgedReasons.length > 0, // v1.1.0
    forgedReasons,
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
    senderVerified,     // v1.1.0: 受信サーバーの記録で確認済みか
    trustMode,          // v1.1.0: "manual" | "auto"
    trustBoundary: boundary,
    claimedOriginIP,    // v1.1.0: 自己申告の送信元 (最古ホップ)
    senderHost: senderEntry ? senderEntry.fromHost : null,
    senderUnknown: senderEntry ? senderEntry.unknown : false,
    senderDynamic: senderEntry ? looksDynamicHostname(senderEntry.fromHost) : false,
    allPublicIPs,
    auth: parseAuthResults(headers, (receiverOrg || trustMode === "manual") ? isOwnServer : null),
    checks,
  };
}

/**
 * Authentication-Results から SPF/DKIM/DMARC を抽出
 * (SPF/DKIM/DMARCは独立ヘッダではないため。spec 02 補足)
 */
function parseAuthResults(headers, isOwnServer) {
  // v1.1.0: 自分側サーバーの authserv-id を持つヘッダのみ採用。該当なしは最上部1件のみ
  // (Microsoft 365 等 authserv-id を付けない環境があるため判定不能にはしない)
  const all = headers["authentication-results"] || [];
  let chosen = [];
  if (isOwnServer) {
    chosen = all.filter((h) => isOwnServer(String(h).split(";")[0].trim().split(/\s+/)[0]));
  }
  if (!chosen.length && all.length) chosen = [all[0]];
  const lines = chosen.join(";");
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
