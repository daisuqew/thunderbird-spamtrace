/**
 * options.js - 設定画面
 * spec: 13_STATS_UPLOAD.md, 11_AUTO_ALERT.md, 18_OUTPUT_FILES.md
 *
 * サーバURL / 自動送信 / バッチ件数 / アラート閾値 / 信頼ドメイン / カスタムブランドの設定、
 * 手動送信、統計・学習JSONエクスポート。
 */

"use strict";

function setStatus(msg, ok) {
  const el = document.getElementById("opt-status");
  el.textContent = msg;
  el.className = ok ? "ok" : "err";
}

/** rules.json の既定アラート閾値を取得 (設定未指定時の表示用, spec 11) */
async function defaultAlertThreshold() {
  try {
    const res = await fetch(messenger.runtime.getURL("rules.json"));
    const cfg = await res.json();
    return cfg.thresholds.alert;
  } catch (e) {
    return 51;
  }
}

/** Blobを出力フォルダ配下のファイルとして保存 (spec 18) */
async function saveToOutputDir(obj, basename) {
  const dir = typeof OUTPUT_DIR === "string" ? OUTPUT_DIR : "spam-trace";
  const blob = new Blob([JSON.stringify(obj, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  try {
    await messenger.downloads.download({
      url,
      filename: `${dir}/${basename}`,
      saveAs: false,
      conflictAction: "uniquify",
    });
  } finally {
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  }
}

async function refreshPending() {
  const count = await pendingEventCount();
  document.getElementById("pending").textContent = `${_t("optPending")}: ${count}`;
}

async function load() {
  localizeDocument();
  const s = await getSettings();
  document.getElementById("server-url").value = s.serverUrl;
  document.getElementById("auto-send").checked = s.autoSend;
  document.getElementById("batch-size").value = s.batchSize;
  document.getElementById("alert-threshold").value =
    Number.isFinite(s.alertThreshold) ? s.alertThreshold : await defaultAlertThreshold();
  document.getElementById("custom-brands").value =
    s.customBrands && s.customBrands.length ? JSON.stringify(s.customBrands) : "";
  document.getElementById("trusted-domains").value = (s.trustedDomains || []).join("\n");
  document.getElementById("trusted-servers").value = (s.trustedServers || []).join("\n"); // v1.1.0

  // IP位置情報プロバイダ（既定 local, RELEASE_PREP §2-1）。旧値(ip-api等)は local に正規化
  document.getElementById("geo-provider").value =
    ["local", "ipwho.is", "off"].includes(s.geoProvider) ? s.geoProvider : "local";

  // Tor判定（オプトイン, RELEASE_PREP §2-3）
  document.getElementById("tor-enabled").checked = !!s.torEnabled;

  // 地図の中心（現在地, spec 09）
  document.getElementById("home-country").value = s.homeCountry || "";
  document.getElementById("home-lat").value = Number.isFinite(s.homeLat) ? s.homeLat : "";
  document.getElementById("home-lon").value = Number.isFinite(s.homeLon) ? s.homeLon : "";

  await refreshPending();
}

/** 国セレクト変更時: 緯度経度欄を代表座標で自動入力（Autoなら空に） */
function onHomeCountryChange() {
  const sel = document.getElementById("home-country");
  const opt = sel.options[sel.selectedIndex];
  const lat = opt && opt.dataset ? opt.dataset.lat : "";
  const lon = opt && opt.dataset ? opt.dataset.lon : "";
  document.getElementById("home-lat").value = lat || "";
  document.getElementById("home-lon").value = lon || "";
}

async function onSave() {
  try {
    // --- DOM値は同期で取得(user activation を消費しない) ---
    const url = document.getElementById("server-url").value.trim();
    const provider = document.getElementById("geo-provider").value;
    const torOn = document.getElementById("tor-enabled").checked;

    let serverOrigin = null;
    if (url) {
      try {
        const u = new URL(url);
        serverOrigin = `${u.protocol}//${u.host}/*`;
      } catch (e) {
        throw new Error(_t("optBadUrl"));
      }
    }

    // --- 権限要求は「最初の await」として必要オリジンをまとめて1回で行う。
    //     ここより前に await を挟むと transient user activation が失効し
    //     permissions.request が拒否される(=保存できない)ため順序が重要。 ---
    const origins = [];
    if (serverOrigin) origins.push(serverOrigin);
    if (provider === "ipwho.is") origins.push("https://ipwho.is/*");
    if (torOn) origins.push("https://check.torproject.org/*");
    if (origins.length) {
      const granted = await messenger.permissions.request({ origins });
      if (!granted) throw new Error(_t("optPermDenied"));
    }

    const s = await getSettings();
    s.serverUrl = url;
    s.autoSend = document.getElementById("auto-send").checked;
    s.batchSize = Math.max(1, parseInt(document.getElementById("batch-size").value, 10) || 20);

    // アラート閾値 (spec 11): 0-100。空欄ならrules.json既定に戻す(null)
    const atRaw = document.getElementById("alert-threshold").value.trim();
    if (atRaw === "") {
      s.alertThreshold = null;
    } else {
      const at = parseInt(atRaw, 10);
      s.alertThreshold = Number.isFinite(at) ? Math.max(0, Math.min(100, at)) : null;
    }

    const brandsTxt = document.getElementById("custom-brands").value.trim();
    let customBrands = [];
    if (brandsTxt) {
      try {
        customBrands = JSON.parse(brandsTxt);
        if (!Array.isArray(customBrands)) throw new Error("not array");
      } catch (e2) {
        throw new Error(_t("optBadBrands"));
      }
    }
    s.customBrands = customBrands;
    s.trustedDomains = document.getElementById("trusted-domains").value
      .split(/[\n,]/).map((d) => d.trim().toLowerCase()).filter(Boolean);
    s.trustedServers = document.getElementById("trusted-servers").value // v1.1.0
      .split(/[\n,]/).map((d) => d.trim().toLowerCase()).filter(Boolean);

    // 地図の中心（現在地, spec 09）: 緯度経度欄が有効ならそれ、無ければnull(自動)。国はUI復元用に保持
    s.homeCountry = document.getElementById("home-country").value;
    const latN = parseFloat(document.getElementById("home-lat").value);
    const lonN = parseFloat(document.getElementById("home-lon").value);
    const latOk = Number.isFinite(latN) && latN >= -90 && latN <= 90;
    const lonOk = Number.isFinite(lonN) && lonN >= -180 && lonN <= 180;
    s.homeLat = latOk && lonOk ? latN : null;
    s.homeLon = latOk && lonOk ? lonN : null;

    // プロバイダ / Tor（ホスト権限は冒頭でまとめて要求済み）
    s.geoProvider = provider;
    s.torEnabled = torOn;

    await saveSettings(s);
    setStatus(_t("optSaved"), true);
  } catch (e) {
    setStatus(e.message, false);
  }
}

async function onSendNow() {
  try {
    const n = await postStats();
    setStatus(_t("optSendOk", [String(n)]), true);
    await refreshPending();
  } catch (e) {
    setStatus(_t("optSendFail", [e.message]), false);
  }
}

async function onLearnExport() {
  const data = await exportLearnData();
  await saveToOutputDir(data, `learning-${new Date().toISOString().slice(0, 10)}.json`);
}

async function onLearnReset() {
  await resetLearnData();
  setStatus(_t("optLearnResetDone"), true);
}

async function onExport() {
  const payload = await buildStatsPayload();
  await saveToOutputDir(payload, `stats-${new Date().toISOString().slice(0, 10)}.json`);
}

document.addEventListener("DOMContentLoaded", () => {
  load();
  document.getElementById("save").addEventListener("click", onSave);
  document.getElementById("send-now").addEventListener("click", onSendNow);
  document.getElementById("export").addEventListener("click", onExport);
  document.getElementById("learn-export").addEventListener("click", onLearnExport);
  document.getElementById("learn-reset").addEventListener("click", onLearnReset);
  document.getElementById("home-country").addEventListener("change", onHomeCountryChange);
  const help = document.getElementById("open-welcome");
  if (help) {
    help.addEventListener("click", (e) => {
      e.preventDefault();
      try {
        messenger.tabs.create({ url: messenger.runtime.getURL("welcome.html") });
      } catch (err) {
        /* 無視 */
      }
    });
  }
});
