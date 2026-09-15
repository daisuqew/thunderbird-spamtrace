/**
 * risk.js - Risk Engine v3 (テーブル駆動)
 * spec: 06_RISK_SCORING.md, 16_MAINTENANCE.md, 17_FEEDBACK_LEARNING.md
 *
 * 全点数・閾値は rules.json (単一ソース) で定義。
 * 本ファイルはシグナル→点数の合成のみを行う。
 * 理由ラベルは i18n (_t, spec 12)
 *
 * v0.12.0: DMARC/DKIM pass でインフラ系加点(hosting/highRiskCloud)を無効化 (spec 06)。
 * v0.13.0: 学習スコア(learn.js)を上限付きで加算 (spec 17)。
 * v0.14.0: 学習対象はリスク加点(正)シグナルのみ。減点シグナル(認証pass等)は除外。
 */

"use strict";

let _riskConfig = null;

/** rules.json を読み込む (初回のみ。失敗時は例外) */
async function ensureRiskConfig() {
  if (_riskConfig) return _riskConfig;
  const res = await fetch(messenger.runtime.getURL("rules.json"));
  if (!res.ok) throw new Error(`rules.json load failed: HTTP ${res.status}`);
  _riskConfig = await res.json();
  return _riskConfig;
}

/**
 * @returns {Promise<{score:number, rank:string, reasons:string[], phishing:boolean, signals:string[]}>}
 *   signals は学習対象のリスク加点(正)シグナルキーのみ。
 */
async function calcRisk(parsed, cls, linkInfo, brandInfo, originInfo) {
  const cfg = await ensureRiskConfig();
  const W = cfg.weights;

  let score = 0;
  const reasons = [];
  const signals = []; // リスク加点(正)シグナルのみ (学習用, spec 17)
  const add = (pts, label, key) => {
    if (!pts) return;
    score += pts;
    reasons.push(`${pts > 0 ? "+" : ""}${pts} ${label}`);
    if (key && pts > 0) signals.push(key); // 正の加点のみ学習対象
  };

  const { spf, dkim, dmarc } = parsed.auth;
  const authVerified = dmarc === "pass" || dkim === "pass";

  /* ---- ネットワーク (spec 04) ---- */
  if (cls) {
    if (cls.hosting && !authVerified) add(W.hosting, _t("reasonHosting"), "hosting");
    if (cls.highRiskCloud && !authVerified) add(W.highRiskCloud, _t("reasonHighRiskCloud", [cls.org || "-"]), "highRiskCloud");
    if (cls.proxyOrVpn) add(W.vpnProxy, _t("reasonVpnProxy"), "vpnProxy");
    if (cls.tor === true) add(W.tor, _t("reasonTor"), "tor");
  }

  /* ---- 認証 (spec 06) ---- */
  if (spf === "fail") add(W.spfFail, _t("reasonSpf", [spf]), "spfFail");
  else if (spf === "softfail") add(W.spfSoftfail, _t("reasonSpf", [spf]), "spfSoftfail");
  else if (spf === "pass") add(W.spfPass, _t("deductSpfPass"), "spfPass");

  if (dkim === "fail") add(W.dkimFail, _t("reasonDkimFail"), "dkimFail");
  else if (dkim === "pass") add(W.dkimPass, _t("deductDkimPass"), "dkimPass");

  if (dmarc === "fail") add(W.dmarcFail, _t("reasonDmarcFail"), "dmarcFail");
  else if (dmarc === "pass") add(W.dmarcPass, _t("deductDmarcPass"), "dmarcPass");

  /* ---- ヘッダ整合性 (spec 06 v2) ---- */
  const c = parsed.checks || {};
  if (c.fromReturnPathMismatch) add(W.fromRpMismatch, _t("reasonFromRpMismatch"), "fromRpMismatch");
  if (c.replyToMismatch) add(W.replyToMismatch, _t("reasonReplyToMismatch"), "replyToMismatch");
  if (c.msgIdMismatch) add(W.msgIdMismatch, _t("reasonMsgIdMismatch"), "msgIdMismatch");
  if (c.dateAnomaly) add(W.dateAnomaly, _t("reasonDateAnomaly"), "dateAnomaly");
  if (c.noReceived) add(W.noReceived, _t("reasonNoReceived"), "noReceived");

  /* ---- 経路: 同一ドメイン直送の減点 (spec 06 v3) ---- */
  const noAuthFail = spf !== "fail" && dkim !== "fail" && dmarc !== "fail";
  if (c.sameDomainRoute && noAuthFail) add(W.sameDomainRoute, _t("deductSameDomainRoute"), "sameDomainRoute");

  /* ---- 信頼送信ホスト (spec 04 v0.11.0) ---- */
  if (cls && cls.trustedHost && (dkim === "pass" || spf === "pass")) {
    add(W.trustedHost, _t("deductTrustedHost"), "trustedHost");
  }

  /* ---- 本文リンク (spec 14) ---- */
  if (linkInfo) {
    if (linkInfo.textHrefMismatch) add(W.linkTextSpoof, _t("reasonLinkTextSpoof"), "linkTextSpoof");
    if (linkInfo.ipLink) add(W.ipLink, _t("reasonIpLink"), "ipLink");
    if (linkInfo.punycode) add(W.punycode, _t("reasonPunycode"), "punycode");
    if (linkInfo.shortener) add(W.shortener, _t("reasonShortener"), "shortener");
    if (linkInfo.allMismatch) add(W.allLinksMismatch, _t("reasonAllLinksMismatch"), "allLinksMismatch");
  }

  /* ---- ブランド整合 (spec 15) ---- */
  if (brandInfo) {
    if (brandInfo.spoof) add(W.brandSpoof, _t("reasonBrandSpoof", [brandInfo.brand]), "brandSpoof");
    else if (brandInfo.authFail) add(W.brandAuthFail, _t("reasonBrandAuthFail", [brandInfo.brand]), "brandAuthFail");
    else if (brandInfo.unverified) add(W.brandUnverified, _t("reasonBrandUnverified", [brandInfo.brand]), "brandUnverified");
    else if (brandInfo.mention) add(W.brandMention, _t("reasonBrandMention", [brandInfo.brand]), "brandMention");
  }

  /* ---- 送信元プロファイル (spec 15) ---- */
  if (originInfo) {
    if (originInfo.newCountry) add(W.newCountry, _t("reasonNewCountry", [originInfo.domain]), "newCountry");
    if (originInfo.newAsn) add(W.newAsn, _t("reasonNewAsn", [originInfo.domain]), "newAsn");
  }

  /* ---- 送信元ホスト (spec 03) ---- */
  if (parsed.senderUnknown) add(W.unknownHost, _t("reasonUnknownHost"), "unknownHost");
  if (parsed.senderDynamic) add(W.dynamicHost, _t("reasonDynamicHost"), "dynamicHost");

  /* ---- 学習スコア (spec 17): 報告スパムのドメイン/ASN/シグナル ---- */
  if (typeof computeLearnAdjustment === "function") {
    try {
      const domReg = typeof registrableDomain === "function" ? registrableDomain(parsed.fromDomain) : null;
      const adj = await computeLearnAdjustment(signals, domReg, cls ? cls.asn : null);
      score += adj.score;
      for (const r of adj.reasons) reasons.push(r);
    } catch (e) {
      console.warn("learn adjustment failed:", e.message);
    }
  }

  score = Math.max(0, Math.min(100, score)); // clamp 0-100

  const T = cfg.thresholds;
  let rank;
  if (score < T.medium) rank = "LOW";
  else if (score < T.high) rank = "MEDIUM";
  else if (score < T.critical) rank = "HIGH";
  else rank = "CRITICAL";

  return {
    score,
    rank,
    reasons,
    signals,
    phishing: !!((linkInfo && linkInfo.phishing) || (brandInfo && (brandInfo.spoof || brandInfo.authFail))),
  };
}
