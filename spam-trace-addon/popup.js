/**
 * popup.js - UI orchestrator
 * 表示中メールを取得 → ヘッダ解析 → リンク解析 → GeoIP/ASN → リスクスコア → 表示
 *
 * 2通りの起動方法に対応:
 * - messageDisplayActionボタン (表示中メールを解析)
 * - 自動アラートの独立ウィンドウ (?messageId= で対象指定, spec 11)
 * 文字列は i18n (_t / localizeDocument, spec 12)
 * v0.17.0: 「不審メール」「正規メール」2ボタンで両側学習 + TB迷惑メールマーク連動 (spec 17)。
 * v0.18.2: 「不審メール」クリックでの中央アラート窓オープンは廃止(v0.18.0で追加→取りやめ)。
 *          中央アラート窓は自動アラート(高スコア)のときのみ。クリックは判定保存+junkマークのみ。
 */

"use strict";

function $(id) {
  return document.getElementById(id);
}

function setText(id, text) {
  $(id).textContent = text == null || text === "" ? "-" : String(text);
}

function setAuth(id, value) {
  const el = $(id);
  el.textContent = value;
  el.className = value === "pass" ? "pass"
    : value === "fail" || value === "softfail" ? "fail"
    : "none";
}

function setBool(id, value, trueLabel, nullLabel) {
  const el = $(id);
  if (value === null || value === undefined) {
    el.textContent = nullLabel || _t("unknownVerdict");
    el.className = "none";
  } else if (value) {
    el.textContent = trueLabel || "YES";
    el.className = "fail";
  } else {
    el.textContent = "NO";
    el.className = "pass";
  }
}

function rootHeaders(fullPart) {
  return fullPart.headers || {};
}

async function resolveMessageId() {
  const params = new URLSearchParams(location.search);
  if (params.has("messageId")) {
    return parseInt(params.get("messageId"), 10);
  }
  const [tab] = await messenger.tabs.query({ active: true, currentWindow: true });
  const message = await messenger.messageDisplay.getDisplayedMessage(tab.id);
  return message ? message.id : null;
}

// 現在解析中のメール (判定用, spec 17)
let _current = null;

async function main() {
  localizeDocument();
  const status = $("status");
  try {
    const messageId = await resolveMessageId();
    if (messageId == null) {
      status.textContent = _t("statusNoMessage");
      return;
    }

    const full = await messenger.messages.getFull(messageId);
    const trustedServers = (await getSettings()).trustedServers || []; // v1.1.0
    const parsed = analyzeHeaders(rootHeaders(full), { trustedServers });
    const linkInfo = analyzeLinks(extractLinks(full), parsed.fromDomain);
    const brandInfo = await checkBrand(parsed);

    let cls = null;
    let geoError = null;
    if (parsed.senderIP) {
      try {
        const [geo, tor] = await Promise.all([
          lookupIP(parsed.senderIP),
          isTorExit(parsed.senderIP),
        ]);
        cls = classifyASN(geo, tor);
      } catch (e) {
        geoError = e.message;
      }
    }

    const originInfo = await checkOriginAnomaly(parsed.fromDomain, cls);
    const risk = await calcRisk(parsed, cls, linkInfo, brandInfo, originInfo);

    _current = { messageId, parsed, cls, linkInfo, brandInfo, originInfo, signals: risk.signals };

    render(parsed, cls, risk, geoError, linkInfo, brandInfo);
    status.hidden = true;
    $("result").hidden = false;

    try {
      const verdict = await getVerdict(messageId);
      updateVerdictButtons(verdict);
    } catch (e) {
      console.warn("verdict state failed:", e.message);
    }

    // ローカルDB(DB-IP)使用時は CC BY 帰属表示を出す (RELEASE_PREP §2-1 / §3)
    try {
      const s = await getSettings();
      const attr = $("dbip-attr");
      if (attr) attr.hidden = s.geoProvider !== "local";
    } catch (e) {
      /* 設定取得失敗時は非表示のまま */
    }

    await renderRouteMap(parsed);
  } catch (e) {
    status.innerHTML = "";
    status.className = "err";
    status.textContent = _t("errorGeneric", [e.message]);
    console.error(e);
  }
}

/** ボタン表示を判定状態に合わせる */
function updateVerdictButtons(verdict) {
  const spamBtn = $("fb-report");
  const hamBtn = $("fb-legit");
  if (spamBtn) {
    spamBtn.textContent = verdict === "spam" ? _t("feedbackReported") : _t("feedbackReportSpam");
    spamBtn.classList.toggle("active", verdict === "spam");
  }
  if (hamBtn) {
    hamBtn.textContent = verdict === "ham" ? _t("feedbackLegitMarked") : _t("feedbackLegit");
    hamBtn.classList.toggle("active", verdict === "ham");
  }
}

/** 判定トグル (spec 17): kind="spam"|"ham"。同じものを再クリックで取消。 */
async function onVerdict(kind) {
  if (!_current) return;
  const { messageId, parsed, cls, linkInfo, brandInfo, originInfo, signals } = _current;
  try {
    const current = await getVerdict(messageId);
    const next = current === kind ? null : kind;
    await setVerdict(messageId, signals, registrableDomain(parsed.fromDomain),
      cls ? cls.asn : null, next);

    // Thunderbird迷惑メールマーク連動: spam→junk, それ以外→非junk
    let junkError = null;
    try {
      await messenger.messages.update(messageId, { junk: next === "spam" });
    } catch (e) {
      junkError = e && e.message ? e.message : String(e);
      console.warn("SPAMTRACE junk mark failed:", junkError, e);
    }

    updateVerdictButtons(next);
    const risk2 = await calcRisk(parsed, cls, linkInfo, brandInfo, originInfo);
    render(parsed, cls, risk2, null, linkInfo, brandInfo);
    updateVerdictButtons(next);

    $("feedback-status").textContent =
      next === "spam" ? _t("feedbackReportedDone")
      : next === "ham" ? _t("feedbackLegitDone")
      : _t("feedbackUnreportedDone");

    if (junkError) {
      const b = $("phishing-banner");
      b.hidden = false;
      b.textContent = `${_t("feedbackJunkFailed")}: ${junkError}`;
    }
  } catch (e) {
    $("feedback-status").textContent = _t("errorGeneric", [e.message]);
  }
}

function render(parsed, cls, risk, geoError, linkInfo, brandInfo) {
  const banner = $("phishing-banner");
  if (risk.phishing) {
    banner.hidden = false;
    const pairs = [];
    if (linkInfo && linkInfo.domainPairs) pairs.push(...linkInfo.domainPairs);
    if (brandInfo && brandInfo.spoof) {
      pairs.push(`${brandInfo.brand} -> ${registrableDomain(parsed.fromDomain) || "-"}`);
    }
    banner.textContent =
      _t("phishingWarning") + (pairs.length ? ` [${pairs.join(" , ")}]` : "");
  } else {
    banner.hidden = true;
  }

  setText("score-num", risk.score);
  const badge = $("rank-badge");
  badge.textContent = risk.rank;
  badge.className = `rank-${risk.rank}`;
  const bar = $("score-bar");
  bar.style.width = `${risk.score}%`;
  bar.style.background =
    risk.score <= 20 ? "#2e7d32" : risk.score <= 50 ? "#f9a825" :
    risk.score <= 80 ? "#e65100" : "#b71c1c";

  const reasons = $("reasons");
  reasons.innerHTML = "";
  const items = risk.reasons.length ? risk.reasons : [_t("noScoreFactors")];
  for (const r of items) {
    const li = document.createElement("li");
    li.textContent = r;
    reasons.appendChild(li);
  }
  if (geoError) {
    const li = document.createElement("li");
    li.className = "err";
    li.textContent = _t("geoLookupFailed", [geoError]);
    reasons.appendChild(li);
  }

  setText("subject", parsed.subject);
  setText("from", parsed.from);
  setText("return-path", parsed.returnPath);
  setText("message-id", parsed.messageId);

  setAuth("spf", parsed.auth.spf);
  setAuth("dkim", parsed.auth.dkim);
  setAuth("dmarc", parsed.auth.dmarc);

  setText("sender-ip", parsed.senderIP || _t("senderNotDetected"));
  setText("sender-trust", parsed.senderIP
    ? _t(parsed.senderVerified
        ? (parsed.trustMode === "manual" ? "trustVerifiedManual" : "trustVerifiedAuto")
        : "trustEstimated")
    : "-"); // v1.1.0
  setText("sender-host", parsed.senderHost);
  setText("relay-count", parsed.relayCount);
  if (cls) {
    setText("country", `${cls.country || "-"} (${cls.countryCode || "-"})`);
    setText("asn", cls.asn);
    setText("org", cls.org);
    setBool("hosting", cls.hosting);
    setBool("proxy", cls.proxyOrVpn);
    setBool("tor", cls.tor);
  } else {
    ["country", "asn", "org", "hosting", "proxy", "tor"].forEach((id) =>
      setText(id, "-")
    );
  }

  $("received-chain").textContent = parsed.chain.length
    ? parsed.chain.map((e, i) =>
        `[${i + 1}] ${e.verified === false ? _t("chainUnverifiedTag") + " " : ""}${e.raw}`).join("\n\n")
    : _t("noReceivedHeader");
}

async function renderRouteMap(parsed) {
  const routeIPs = [];
  const ipVerified = {}; // v1.1.0: IPごとの確度 (境界以上に1度でも現れれば確認済み)
  for (let i = parsed.chain.length - 1; i >= 0; i--) {
    const v = parsed.chain[i].verified;
    for (const ip of parsed.chain[i].ips) {
      if (!isPrivateIP(ip) && !routeIPs.includes(ip)) routeIPs.push(ip);
      if (v === true || !(ip in ipVerified)) ipVerified[ip] = v === true ? true : v;
    }
  }
  const points = [];
  let lookupErr = null;
  for (const ip of routeIPs) {
    try {
      const geo = await lookupIP(ip);
      points.push({
        ip, lat: geo.lat, lon: geo.lon, country: geo.country,
        asn: (geo.as || "").split(" ")[0] || null,
        org: geo.org || geo.isp || null,
        isOrigin: ip === parsed.senderIP,
        verified: ipVerified[ip] === undefined ? null : ipVerified[ip], // v1.1.0
      });
    } catch (e) {
      if (!lookupErr) lookupErr = e && e.message ? e.message : String(e);
      console.warn(`geo lookup failed for ${ip}:`, e.message);
    }
  }

  // 地図の中心（現在地, spec 09）: オプション設定があればそこを中心にする
  let home = null;
  try {
    const s = await getSettings();
    if (Number.isFinite(s.homeLat) && Number.isFinite(s.homeLon)) {
      home = { lat: s.homeLat, lon: s.homeLon };
    }
  } catch (e) {
    /* 設定取得失敗時は従来どおり(自動中心) */
  }
  renderMap(points, home);
  renderHopTable(points);

  // 取得失敗で地図が空のとき、理由を地図欄に表示(診断)。オンライン照会の権限/通信/レート制限の切り分け用
  if (!points.length && routeIPs.length && lookupErr) {
    const note = document.getElementById("map-note");
    if (note) {
      note.className = "err";
      note.textContent = _t("geoLookupFailed", [lookupErr]);
    }
  }
}

document.addEventListener("DOMContentLoaded", () => {
  main();
  const sb = $("fb-report");
  const hb = $("fb-legit");
  if (sb) sb.addEventListener("click", () => onVerdict("spam"));
  if (hb) hb.addEventListener("click", () => onVerdict("ham"));
});
