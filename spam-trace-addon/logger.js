/**
 * logger.js - フィッシング検出ログ (v0.14.1)
 * spec: 14_LINK_ANALYSIS.md 検出ログ, 18_OUTPUT_FILES.md
 *
 * phishing検出のたびに、詳細(全URL対を含む)をログファイルとして
 * このアドオンの出力フォルダ (ダウンロード/<OUTPUT_DIR>/) へ自動保存する。
 * 出力先フォルダは stats.js の OUTPUT_DIR に集約 (spec 18)。
 */

"use strict";

/** ログ本文を生成 (プレーンテキスト) */
function buildPhishLog(parsed, linkInfo, brandInfo, risk) {
  const lines = [];
  lines.push("=== Spam Trace phishing detection ===");
  lines.push(`time: ${new Date().toISOString()}`);
  lines.push(`message-id: ${parsed.messageId || "-"}`);
  lines.push(`from: ${parsed.from || "-"}`);
  lines.push(`subject: ${parsed.subject || "-"}`);
  lines.push(`sender-ip: ${parsed.senderIP || "-"}`);
  lines.push(`score: ${risk.score} (${risk.rank})`);
  lines.push(`signals: ${risk.reasons.join(" | ")}`);
  if (brandInfo && (brandInfo.spoof || brandInfo.authFail)) {
    lines.push(
      `brand: ${brandInfo.brand} (spoof=${brandInfo.spoof}, authFail=${brandInfo.authFail})`
    );
  }
  if (linkInfo && linkInfo.domainPairs && linkInfo.domainPairs.length) {
    lines.push("domains:");
    for (const p of linkInfo.domainPairs) lines.push(`  ${p}`);
  }
  if (linkInfo && linkInfo.samples && linkInfo.samples.length) {
    lines.push("links (full):");
    for (const s of linkInfo.samples) lines.push(`  ${s}`);
  }
  return lines.join("\n") + "\n";
}

/** ログを出力フォルダへ保存 (<OUTPUT_DIR>/phish-<日時>.log, spec 18) */
async function savePhishLog(parsed, linkInfo, brandInfo, risk) {
  const text = buildPhishLog(parsed, linkInfo, brandInfo, risk);
  const blob = new Blob([text], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const dir = typeof OUTPUT_DIR === "string" ? OUTPUT_DIR : "spam-trace";
  try {
    await messenger.downloads.download({
      url,
      filename: `${dir}/phish-${ts}.log`,
      saveAs: false,
      conflictAction: "uniquify",
    });
  } catch (e) {
    console.warn("phish log save failed:", e.message);
  } finally {
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  }
}
