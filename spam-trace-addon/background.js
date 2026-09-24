/**
 * background.js - Auto Alert + Stats記録 (v0.18.5)
 * spec: 11_AUTO_ALERT.md, 13_STATS_UPLOAD.md, 14_LINK_ANALYSIS.md, 17_FEEDBACK_LEARNING.md
 *
 * メール表示時に自動解析し、
 * - 全メール: リンク解析+イベント記録+集計更新、自動送信条件を満たせばPOST
 * - スコアがアラート閾値以上: 自動アラート(中央窓は自動アラートのときのみ)
 *   アラート閾値は 設定(options) > rules.json thresholds.alert の優先順 (spec 11)
 *
 * v0.18.3: 送信系フォルダは解析・アラート対象外。
 * v0.18.4: accountsRead で送信系判定を確実化 + 送信系では Spam Trace ボタンを無効化。
 * v0.18.5: アラート窓は常に1つだけ(別メールを出すときは既存窓を閉じる)。
 *   Thunderbird本体ウィンドウが全て閉じたら(終了時)、残ったアラート窓も閉じる。
 */

"use strict";

/* 初回インストール時に説明ページ(welcome.html)を開く (v0.19.12) */
messenger.runtime.onInstalled.addListener((details) => {
  if (details && details.reason === "install") {
    try {
      messenger.tabs.create({ url: messenger.runtime.getURL("welcome.html") });
    } catch (e) {
      /* 開けなくても無視 */
    }
  }
});

const ALERT_WIN_W = 460;
const ALERT_WIN_H = 720;
const ALERT_URL_BASE = "popup.html?messageId=";

/** セッション中に自動アラート済みのメールID (自動表示の重複抑止) */
const _alerted = new Set();

/** 自分が作成したメール(送信系)を解析・アラート対象から除外 (spec 11, v0.18.3) */
const EXCLUDED_FOLDER_USES = new Set(["sent", "drafts", "templates", "outbox"]);

/**
 * 表示中メールが送信系フォルダにあるか。
 * specialUse(TB128, 配列, accountsRead で取得) を優先、旧 type(文字列) をフォールバック。
 * specialUse が空のときは account の特殊フォルダと path 照合で再確認する。
 */
async function isExcludedFolder(folder) {
  if (!folder) return false;
  const uses = Array.isArray(folder.specialUse)
    ? folder.specialUse
    : folder.type
    ? [folder.type]
    : [];
  if (uses.some((u) => EXCLUDED_FOLDER_USES.has(u))) return true;

  try {
    if (folder.accountId && folder.path) {
      const account = await messenger.accounts.get(folder.accountId);
      const list = (account && account.folders) || [];
      const match = findFolderByPath(list, folder.path);
      if (match) {
        const mu = Array.isArray(match.specialUse)
          ? match.specialUse
          : match.type
          ? [match.type]
          : [];
        return mu.some((u) => EXCLUDED_FOLDER_USES.has(u));
      }
    }
  } catch (e) {
    /* 照合不可は除外しない */
  }
  return false;
}

/** account.folders(ネスト可)から path 一致のフォルダを探す */
function findFolderByPath(folders, path) {
  for (const f of folders || []) {
    if (f.path === path) return f;
    const sub = findFolderByPath(f.subFolders || f.folders || [], path);
    if (sub) return sub;
  }
  return null;
}

/** このアドオンのアラート窓URL断片 (messageId付き) */
function _alertUrlPart(messageId) {
  return `${ALERT_URL_BASE}${messageId}`;
}

/**
 * 現在開いている全アラート窓を列挙。[{ windowId, messageId(string) }]
 * 実ウィンドウ(windows.getAll)を一次情報とする。
 */
async function listAlertWindows() {
  const out = [];
  let wins;
  try {
    wins = await messenger.windows.getAll({ populate: true });
  } catch (e) {
    return out; // 列挙不可
  }
  for (const w of wins) {
    if (w.type && w.type !== "popup") continue;
    for (const t of w.tabs || []) {
      const url = t.url || "";
      const i = url.indexOf(ALERT_URL_BASE);
      if (i >= 0) {
        const mid = url.slice(i + ALERT_URL_BASE.length).split(/[&#]/)[0];
        out.push({ windowId: w.id, messageId: mid });
        break;
      }
    }
  }
  return out;
}

/**
 * アラート窓を開く(自動アラート経路から呼ぶ)。
 * アラート窓は常に1つだけ: 同じメールの窓が既にあればフォーカス、
 * 別メールの窓は閉じてから新規に開く (v0.18.5)。
 * @param {number} messageId
 * @returns {Promise<{opened:boolean, focused?:boolean}>}
 */
async function openAlertWindow(messageId) {
  const target = String(messageId);
  const existing = await listAlertWindows();
  let sameId = null;
  for (const w of existing) {
    if (w.messageId === target) sameId = w.windowId;
    else {
      try {
        await messenger.windows.remove(w.windowId); // 別メールの窓は閉じる(常に1つ)
      } catch (e) {
        /* 既に閉じている等は無視 */
      }
    }
  }
  if (sameId != null) {
    try {
      await messenger.windows.update(sameId, { focused: true });
    } catch (e) {
      /* フォーカス失敗は無視 */
    }
    return { opened: false, focused: true };
  }
  await messenger.windows.create({
    url: _alertUrlPart(messageId),
    type: "popup",
    width: ALERT_WIN_W,
    height: ALERT_WIN_H,
  });
  return { opened: true };
}

/**
 * 本体(normal)ウィンドウが全て閉じたら(=Thunderbird終了)、残ったアラート窓も閉じる。
 * (メイン3ペインを閉じたのにポップアップだけ残るのを防ぐ, v0.18.5)
 */
messenger.windows.onRemoved.addListener(async () => {
  try {
    const wins = await messenger.windows.getAll({ populate: true });
    const hasNormal = wins.some((w) => w.type === "normal");
    if (hasNormal) return;
    for (const w of wins) {
      if (w.type && w.type !== "popup") continue;
      for (const t of w.tabs || []) {
        if ((t.url || "").indexOf(ALERT_URL_BASE) >= 0) {
          try {
            await messenger.windows.remove(w.id);
          } catch (e) {
            /* 無視 */
          }
          break;
        }
      }
    }
  } catch (e) {
    /* 無視 */
  }
});

/** 送信系フォルダでは Spam Trace ボタンを無効化、それ以外は有効化 (v0.18.4) */
async function updateActionState(tabId, excluded) {
  try {
    if (excluded) await messenger.messageDisplayAction.disable(tabId);
    else await messenger.messageDisplayAction.enable(tabId);
  } catch (e) {
    console.warn("messageDisplayAction toggle failed:", e.message);
  }
}

messenger.messageDisplay.onMessageDisplayed.addListener(async (tab, message) => {
  try {
    if (!message) return;

    // 送信系フォルダ(送信/下書き/テンプレート/送信トレイ)は対象外 (v0.18.3/0.18.4)
    const excluded = await isExcludedFolder(message.folder);
    await updateActionState(tab.id, excluded);
    if (excluded) return;

    const full = await messenger.messages.getFull(message.id);
    const trustedServers = (await getSettings()).trustedServers || []; // v1.1.0
    const parsed = analyzeHeaders(full.headers || {}, { trustedServers });

    let cls = null;
    if (parsed.senderIP) {
      try {
        const [geo, tor] = await Promise.all([
          lookupIP(parsed.senderIP),
          isTorExit(parsed.senderIP),
        ]);
        cls = classifyASN(geo, tor);
      } catch (e) {
        console.warn("auto analysis: geo lookup failed:", e.message);
      }
    }

    const linkInfo = analyzeLinks(extractLinks(full), parsed.fromDomain);
    const brandInfo = await checkBrand(parsed);
    const originInfo = await checkOriginAnomaly(parsed.fromDomain, cls);
    const risk = await calcRisk(parsed, cls, linkInfo, brandInfo, originInfo);

    // 統計記録 (spec 13): 全メール対象。失敗しても解析は継続
    try {
      await recordEvent(full, parsed, cls, risk);
      await maybeAutoSend();
    } catch (e) {
      console.warn("stats record failed:", e.message);
    }

    // 自動アラート閾値 (spec 11, v0.15.0): 設定 > rules.json の優先順。
    const cfgAlert = (await ensureRiskConfig()).thresholds.alert;
    const settings = await getSettings();
    const alertThreshold = Number.isFinite(settings.alertThreshold)
      ? settings.alertThreshold
      : cfgAlert;

    const shouldAlert = risk.score >= alertThreshold;
    if (!shouldAlert || _alerted.has(message.id)) return;
    if (await isTrustedDomain(parsed.fromDomain)) return;
    _alerted.add(message.id);

    // 検出ログの自動保存 (spec 14 v0.9.0): phishing検出のみ
    if (risk.phishing) {
      await savePhishLog(parsed, linkInfo, brandInfo, risk);
    }
    await openAlertWindow(message.id);
  } catch (e) {
    console.error("auto analysis failed:", e);
  }
});
