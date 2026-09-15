/**
 * links.js - Link Analysis / フィッシング検出 (v0.6.0)
 * spec: 14_LINK_ANALYSIS.md
 *
 * 本文(text/html, text/plain)からリンクを抽出し、偽装シグナルを判定する。
 * 強シグナル(リンク偽装/IP直リンク/punycode)は phishing フラグを立てる。
 */

"use strict";

const URL_RE = /https?:\/\/[^\s<>"')\]]+/gi;
const ANCHOR_RE = /<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;

const SHORTENER_HOSTS = [
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
  "buff.ly", "cutt.ly", "rb.gy", "tiny.cc", "shorturl.at", "lnkd.in",
];

/** 関連ドメイン判定で「意味のある共通文字列」とみなす最小長 (spec 14) */
const MIN_COMMON_LABEL = 4;

/** 登録可能ドメインの主ラベル (先頭ラベル)。例: rakuten-sec.co.jp -> "rakuten-sec" */
function _primaryLabel(domain) {
  const reg = registrableDomain(domain);
  return reg ? reg.split(".")[0] : null;
}

/**
 * 2ドメインが関連(グループ会社等)か判定 (spec 14, v0.11.0)
 * - 主ラベル完全一致
 * - 一方の主ラベルが他方を MIN_COMMON_LABEL 文字以上の部分文字列として含む (rakuten ⊂ rakuten-sec)
 * - 同一ブランドの正規ドメイン集合に属する (brandDomainsOf, brands.js)
 */
function areRelatedDomains(d1, d2) {
  if (!d1 || !d2) return false;
  if (sameOrgDomain(d1, d2)) return true;
  const a = _primaryLabel(d1);
  const b = _primaryLabel(d2);
  if (!a || !b) return false;
  if (a === b) return true;
  // 共通の連続部分文字列(ハイフン区切りの語)で関連判定
  const aw = a.split("-").filter((w) => w.length >= MIN_COMMON_LABEL);
  const bw = b.split("-").filter((w) => w.length >= MIN_COMMON_LABEL);
  if (aw.some((w) => bw.includes(w))) return true;
  if (a.length >= MIN_COMMON_LABEL && b.includes(a)) return true;
  if (b.length >= MIN_COMMON_LABEL && a.includes(b)) return true;
  // 既定ブランドの正規ドメイン集合 (brands.jsが読み込まれている場合のみ)
  if (typeof brandDomainsOf === "function") {
    const set1 = brandDomainsOf(d1);
    if (set1 && set1.has(registrableDomain(d2))) return true;
  }
  return false;
}

/** URLからホスト名を取得 (不正URLはnull) */
function _urlHost(url) {
  try {
    const u = new URL(url);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    return u.hostname.toLowerCase();
  } catch (e) {
    return null;
  }
}

/** MIMEツリーからリンクを抽出 @returns [{href, text}] */
function extractLinks(part, out, isHtml) {
  out = out || [];
  const ct = (part.contentType || "").toLowerCase();
  const html = isHtml || ct.includes("html");

  if (part.body) {
    if (html) {
      let m;
      ANCHOR_RE.lastIndex = 0;
      while ((m = ANCHOR_RE.exec(part.body)) !== null) {
        const text = m[2].replace(/<[^>]*>/g, "").trim(); // タグ除去
        out.push({ href: m[1].trim(), text });
      }
    } else {
      for (const u of part.body.match(URL_RE) || []) {
        out.push({ href: u, text: "" });
      }
    }
  }
  for (const p of part.parts || []) extractLinks(p, out, false);
  return out;
}

/**
 * リンク群の偽装シグナルを判定 (spec 14)
 * @param {Array} links extractLinks() の結果
 * @param {string|null} fromDomain parser.jsのfromDomain
 */
function analyzeLinks(links, fromDomain) {
  const info = {
    linkCount: 0,
    textHrefMismatch: false, // 強: リンクテキストがURLでhrefとドメイン不一致
    ipLink: false,           // 強: IP直リンク
    punycode: false,         // 強: xn-- ドメイン
    shortener: false,        // 短縮URL
    allMismatch: false,      // 全リンクがFromと不一致
    phishing: false,
    samples: [],             // 検出例 (ログ用URL全文, 最大10)
    domainPairs: [],         // 起因ドメイン対 (バナー表示用, 重複排除・最大3)
  };

  let mismatchFromAll = true;
  for (const l of links) {
    const host = _urlHost(l.href);
    if (!host) continue;
    info.linkCount++;

    // IP直リンク
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) && isValidIPv4(host)) {
      info.ipLink = true;
      _addSample(info, l.href);
      _addPair(info, `-> ${host}`);
    }
    // punycode
    if (host.split(".").some((lab) => lab.startsWith("xn--"))) {
      info.punycode = true;
      _addSample(info, l.href);
      _addPair(info, `-> ${host}`);
    }
    // 短縮URL
    if (SHORTENER_HOSTS.includes(host)) info.shortener = true;

    // リンク偽装: テキスト側にURLがあり、そのドメインがhrefと不一致
    // ただし関連ドメイン(グループ会社等)は偽装としない (spec 14, v0.11.0)
    const textUrl = (l.text.match(URL_RE) || [])[0];
    if (textUrl) {
      const textHost = _urlHost(textUrl);
      if (textHost && !areRelatedDomains(textHost, host)) {
        info.textHrefMismatch = true;
        _addSample(info, `${textUrl} -> ${l.href}`);
        _addPair(info, `${registrableDomain(textHost)} -> ${registrableDomain(host)}`);
      }
    }

    // From一致または関連ドメインのリンクが1つでもあれば allMismatch ではない
    if (fromDomain && areRelatedDomains(host, fromDomain)) mismatchFromAll = false;
  }

  info.allMismatch = !!(fromDomain && info.linkCount > 0 && mismatchFromAll);
  info.phishing = info.textHrefMismatch || info.ipLink || info.punycode;
  return info;
}

function _addSample(info, s) {
  if (info.samples.length < 10) info.samples.push(s);
}

function _addPair(info, p) {
  if (!info.domainPairs.includes(p) && info.domainPairs.length < 3) info.domainPairs.push(p);
}
