/**
 * stats.js - 送信元情報の蓄積とサーバ送信 (v0.5.0)
 * spec: 13_STATS_UPLOAD.md, 08_API_SPEC.md, 07_DATABASE_SCHEMA.md
 *
 * - メール解析のたびにイベント(hash/IP/ASN/国/スコア)を storage.local に記録
 * - ASN/国/ランク別の集計統計を維持
 * - spec 08 形式のJSONを生成し、設定されたAPIサーバへPOST
 */

"use strict";

const STATS_EVENTS_KEY = "stats:events";
const STATS_AGG_KEY = "stats:aggregate";
const SETTINGS_KEY = "settings";
const MAX_EVENTS = 1000;

/** このアドオンが作成する全ファイルの出力フォルダ (ダウンロード配下, spec 18) */
const OUTPUT_DIR = "spam-trace";

/* ---- 設定 ---- */

const DEFAULT_SETTINGS = { serverUrl: "", autoSend: false, batchSize: 20, alertThreshold: null, customBrands: [], trustedDomains: [], homeCountry: "", homeLat: null, homeLon: null, geoProvider: "local", torEnabled: false };

async function getSettings() {
  const obj = await messenger.storage.local.get(SETTINGS_KEY);
  return Object.assign({}, DEFAULT_SETTINGS, obj[SETTINGS_KEY] || {});
}

async function saveSettings(settings) {
  await messenger.storage.local.set({ [SETTINGS_KEY]: settings });
}

/* ---- ハッシュ ---- */

async function sha256hex(text) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** getFull()のMIMEツリーから本文テキストを集める */
function collectBodyText(part) {
  let out = "";
  if (part.body) out += part.body;
  for (const p of part.parts || []) out += collectBodyText(p);
  return out;
}

/* ---- 記録 (spec 13) ---- */

/**
 * 解析結果をイベントとして記録し、集計を更新する。
 * @returns {Object|null} 記録したイベント (重複時はnull)
 */
async function recordEvent(full, parsed, cls, risk) {
  const st = await messenger.storage.local.get([STATS_EVENTS_KEY, STATS_AGG_KEY]);
  const events = st[STATS_EVENTS_KEY] || [];

  // message_id による重複防止
  if (parsed.messageId && events.some((e) => e.message_id === parsed.messageId)) {
    return null;
  }

  const body = collectBodyText(full);
  const ev = {
    message_id: parsed.messageId || null,
    subject_hash: parsed.subject ? await sha256hex(parsed.subject) : null,
    body_hash: body ? await sha256hex(body) : null,
    sender_ip: parsed.senderIP || null,
    asn: cls ? cls.asn : null,
    country: cls ? cls.countryCode : null,
    score: risk.score,
    rank: risk.rank,
    phishing: !!risk.phishing,
    ts: new Date().toISOString(),
  };

  events.push(ev);
  while (events.length > MAX_EVENTS) events.shift();

  // 集計 (送信後も保持)
  const agg = st[STATS_AGG_KEY] || {
    total: 0,
    byRank: {},
    byCountry: {},
    byAsn: {},
    first_seen: ev.ts,
  };
  agg.total++;
  if (ev.phishing) agg.phishingCount = (agg.phishingCount || 0) + 1;
  agg.byRank[ev.rank] = (agg.byRank[ev.rank] || 0) + 1;
  if (ev.country) agg.byCountry[ev.country] = (agg.byCountry[ev.country] || 0) + 1;
  if (ev.asn) agg.byAsn[ev.asn] = (agg.byAsn[ev.asn] || 0) + 1;
  agg.last_seen = ev.ts;

  await messenger.storage.local.set({
    [STATS_EVENTS_KEY]: events,
    [STATS_AGG_KEY]: agg,
  });

  // 送信元プロファイル学習 (spec 15): 重複排除後のみ
  try {
    await updateSenderProfile(parsed.fromDomain, cls);
  } catch (e) {
    /* 学習失敗は無視 */
  }
  return ev;
}

/** 未送信イベント数 */
async function pendingEventCount() {
  const st = await messenger.storage.local.get(STATS_EVENTS_KEY);
  return (st[STATS_EVENTS_KEY] || []).length;
}

/* ---- ペイロード生成・送信 (spec 08) ---- */

/** spec 08 Request形式のJSONを生成 */
async function buildStatsPayload() {
  const st = await messenger.storage.local.get([STATS_EVENTS_KEY, STATS_AGG_KEY]);
  return {
    client: {
      name: "spam-trace",
      version: messenger.runtime.getManifest().version,
    },
    generated_at: new Date().toISOString(),
    stats: st[STATS_AGG_KEY] || { total: 0, byRank: {}, byCountry: {}, byAsn: {} },
    events: st[STATS_EVENTS_KEY] || [],
  };
}

/**
 * 設定されたサーバへPOST。成功(2xx)で未送信イベントをクリア。
 * @returns {number} 送信したイベント件数
 */
async function postStats() {
  const settings = await getSettings();
  if (!settings.serverUrl) throw new Error(_t("optNoUrl"));

  const payload = await buildStatsPayload();
  const res = await fetch(settings.serverUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);

  // 成功: イベントをクリア (集計は保持, spec 13)
  await messenger.storage.local.set({ [STATS_EVENTS_KEY]: [] });
  const settings2 = await getSettings();
  settings2.lastSent = new Date().toISOString();
  await saveSettings(settings2);
  return payload.events.length;
}

/** 自動送信判定 (spec 13): autoSend ON かつ 未送信がバッチ件数以上 */
async function maybeAutoSend() {
  const settings = await getSettings();
  if (!settings.autoSend || !settings.serverUrl) return;
  const count = await pendingEventCount();
  if (count >= settings.batchSize) {
    try {
      await postStats();
      console.log(`stats auto-sent (${count} events)`);
    } catch (e) {
      console.warn("stats auto-send failed:", e.message);
    }
  }
}

/* ---- 送信元プロファイル学習 (spec 15, v0.7.0) ---- */

const PROFILE_MIN_HISTORY = 5;

async function _getProfile(domainReg) {
  const key = `profile:${domainReg}`;
  const obj = await messenger.storage.local.get(key);
  return obj[key] || { total: 0, asn: {}, country: {} };
}

/** 既知ドメイン(履歴5通以上)が初見の国/ASNから届いたか。履歴不足はnull */
async function checkOriginAnomaly(fromDomain, cls) {
  if (!fromDomain || !cls) return null;
  const reg = registrableDomain(fromDomain);
  if (!reg) return null;
  const p = await _getProfile(reg);
  if (p.total < PROFILE_MIN_HISTORY) return null;
  return {
    domain: reg,
    newCountry: !!(cls.countryCode && !p.country[cls.countryCode]),
    newAsn: !!(cls.asn && !p.asn[cls.asn]),
  };
}

/** プロファイル更新 (recordEventから呼ぶ) */
async function updateSenderProfile(fromDomain, cls) {
  if (!fromDomain || !cls) return;
  const reg = registrableDomain(fromDomain);
  if (!reg) return;
  const p = await _getProfile(reg);
  p.total++;
  if (cls.asn) p.asn[cls.asn] = (p.asn[cls.asn] || 0) + 1;
  if (cls.countryCode) p.country[cls.countryCode] = (p.country[cls.countryCode] || 0) + 1;
  await messenger.storage.local.set({ [`profile:${reg}`]: p });
}

/** 信頼ドメイン判定 (spec 15, v0.8.0)。登録可能ドメインで比較 */
async function isTrustedDomain(fromDomain) {
  if (!fromDomain) return false;
  const reg = registrableDomain(fromDomain);
  if (!reg) return false;
  const s = await getSettings();
  return (s.trustedDomains || []).some(
    (d) => registrableDomain(String(d).trim().toLowerCase()) === reg
  );
}
