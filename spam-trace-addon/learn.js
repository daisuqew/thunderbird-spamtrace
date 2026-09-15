/**
 * learn.js - フィードバック学習 (v0.17.0)
 * spec: 17_FEEDBACK_LEARNING.md
 *
 * 人手判定を両側で学習する:
 *  - 「不審メール」報告 → スパム証拠を蓄積 (ドメイン/ASN/シグナルに加点)
 *  - 「正規メール」報告 → ホワイト証拠を蓄積 (ドメイン/ASNに減点)
 * いずれもトグル式・全ローカル・サーバ不要。
 * シグナル頻度学習は不審側のみ(認証pass等の巻き添え誤判定を避けるため)。
 */

"use strict";

const LEARN_SIG_KEY = "learn:spam:signals";    // { signalKey: count } 不審側のみ
const LEARN_META_KEY = "learn:meta";           // { spamReports: int }
const LEARN_VERDICTS_KEY = "learn:verdicts";   // { message_id: "spam"|"ham" }

function _dKey(reg) { return `learn:spam:domain:${reg}`; } // 値: {spam,ham}
function _aKey(asn) { return `learn:spam:asn:${asn}`; }    // 値: {spam,ham}

/** 旧形式(整数=spam件数)を {spam,ham} に正規化 */
function _pair(v) {
  if (v == null) return { spam: 0, ham: 0 };
  if (typeof v === "number") return { spam: Math.max(0, v), ham: 0 };
  return { spam: Math.max(0, v.spam || 0), ham: Math.max(0, v.ham || 0) };
}

/** 学習設定 (rules.json learn、なければ既定) */
async function _learnCfg() {
  try {
    const cfg = await ensureRiskConfig();
    return Object.assign({ scale: 8, cap: 30, minReports: 5, domainCap: 25 }, cfg.learn || {});
  } catch (e) {
    return { scale: 8, cap: 30, minReports: 5, domainCap: 25 };
  }
}

function _spamReports(meta) {
  return (meta && (meta.spamReports != null ? meta.spamReports : meta.reports)) || 0;
}

/** このメールの判定 ("spam"|"ham"|null) */
async function getVerdict(messageId) {
  const st = await messenger.storage.local.get(LEARN_VERDICTS_KEY);
  const v = st[LEARN_VERDICTS_KEY] || {};
  return v[messageId] || null;
}

/** 後方互換: 旧APIの呼び出し名 */
async function isReported(messageId) {
  return (await getVerdict(messageId)) === "spam";
}

/**
 * 判定を設定 (spec 17)。verdict ∈ {"spam","ham",null}。null=取消。
 * 同一メールの判定切替(spam↔ham)・取消を整合的に巻き戻す。
 * @returns {Promise<("spam"|"ham"|null)>} 設定後の判定
 */
async function setVerdict(messageId, signals, domainReg, asn, verdict) {
  const keys = [LEARN_SIG_KEY, LEARN_META_KEY, LEARN_VERDICTS_KEY];
  if (domainReg) keys.push(_dKey(domainReg));
  if (asn) keys.push(_aKey(asn));
  const st = await messenger.storage.local.get(keys);

  const sig = st[LEARN_SIG_KEY] || {};
  const meta = { spamReports: _spamReports(st[LEARN_META_KEY]) };
  const verdicts = st[LEARN_VERDICTS_KEY] || {};
  const dom = domainReg ? _pair(st[_dKey(domainReg)]) : null;
  const asnRec = asn ? _pair(st[_aKey(asn)]) : null;

  const prev = verdicts[messageId] || null;
  if (prev === verdict) return prev; // 変化なし

  // 前判定を巻き戻す
  const undo = (label) => {
    if (label === "spam") {
      meta.spamReports = Math.max(0, meta.spamReports - 1);
      for (const k of signals || []) sig[k] = Math.max(0, (sig[k] || 0) - 1);
      if (dom) dom.spam = Math.max(0, dom.spam - 1);
      if (asnRec) asnRec.spam = Math.max(0, asnRec.spam - 1);
    } else if (label === "ham") {
      if (dom) dom.ham = Math.max(0, dom.ham - 1);
      if (asnRec) asnRec.ham = Math.max(0, asnRec.ham - 1);
    }
  };
  const apply = (label) => {
    if (label === "spam") {
      meta.spamReports += 1;
      for (const k of signals || []) sig[k] = (sig[k] || 0) + 1;
      if (dom) dom.spam += 1;
      if (asnRec) asnRec.spam += 1;
    } else if (label === "ham") {
      if (dom) dom.ham += 1;
      if (asnRec) asnRec.ham += 1;
    }
  };

  if (prev) undo(prev);
  if (verdict) apply(verdict);

  if (verdict) verdicts[messageId] = verdict;
  else delete verdicts[messageId];

  const out = { [LEARN_SIG_KEY]: sig, [LEARN_META_KEY]: meta, [LEARN_VERDICTS_KEY]: verdicts };
  if (domainReg) out[_dKey(domainReg)] = dom;
  if (asn) out[_aKey(asn)] = asnRec;
  await messenger.storage.local.set(out);
  return verdict;
}

/**
 * 学習スコア調整 (spec 17)。不審=加点 / 正規=減点。上限付き。
 * @returns {Promise<{score:number, reasons:string[]}>}
 */
async function computeLearnAdjustment(signals, domainReg, asn) {
  const cfg = await _learnCfg();
  const keys = [LEARN_SIG_KEY, LEARN_META_KEY];
  if (domainReg) keys.push(_dKey(domainReg));
  if (asn) keys.push(_aKey(asn));
  const st = await messenger.storage.local.get(keys);
  const spamReports = _spamReports(st[LEARN_META_KEY]);

  let score = 0;
  const reasons = [];
  const clampPos = (v, lim) => Math.min(lim, v);

  // 1. ドメイン評価 (不審=加点 / 正規=減点)
  if (domainReg) {
    const d = _pair(st[_dKey(domainReg)]);
    const pos = clampPos(8 * d.spam, cfg.domainCap);
    const neg = clampPos(8 * d.ham, cfg.domainCap);
    const net = pos - neg;
    if (net > 0) { score += net; reasons.push(`+${net} ${_t("reasonReportedDomain", [domainReg])}`); }
    else if (net < 0) { score += net; reasons.push(`${net} ${_t("reasonLegitDomain", [domainReg])}`); }
  }

  // 2. ASN評価 (ドメインより弱め)
  if (asn) {
    const a = _pair(st[_aKey(asn)]);
    const lim = Math.round(cfg.domainCap / 2);
    const pos = clampPos(5 * a.spam, lim);
    const neg = clampPos(5 * a.ham, lim);
    const net = pos - neg;
    if (net > 0) { score += net; reasons.push(`+${net} ${_t("reasonReportedAsn", [asn])}`); }
    else if (net < 0) { score += net; reasons.push(`${net} ${_t("reasonLegitAsn", [asn])}`); }
  }

  // 3. シグナル頻度 (不審側のみ。報告がminReports以上たまったら)
  if (spamReports >= cfg.minReports) {
    const sig = st[LEARN_SIG_KEY] || {};
    let frac = 0;
    for (const k of signals || []) frac += (sig[k] || 0) / spamReports;
    const s = Math.min(cfg.cap, Math.round(frac * cfg.scale));
    if (s > 0) { score += s; reasons.push(`+${s} ${_t("reasonReportedSignals")}`); }
  }

  return { score, reasons };
}

/** 学習データをJSONで返す (エクスポート) */
async function exportLearnData() {
  const all = await messenger.storage.local.get(null);
  const out = {};
  for (const k of Object.keys(all)) if (k.startsWith("learn:")) out[k] = all[k];
  return out;
}

/** 学習データを全消去 */
async function resetLearnData() {
  const all = await messenger.storage.local.get(null);
  const keys = Object.keys(all).filter((k) => k.startsWith("learn:"));
  if (keys.length) await messenger.storage.local.remove(keys);
}
