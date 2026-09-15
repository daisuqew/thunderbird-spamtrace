/**
 * welcome.js - 初回インストール時に開く説明ページ (v0.19.12)
 * i18n を適用し、「設定を開く」ボタンを配線する。
 */
"use strict";
document.addEventListener("DOMContentLoaded", () => {
  try { localizeDocument(); } catch (e) { /* i18n 失敗時は既定文言のまま */ }
  const b = document.getElementById("open-options");
  if (b) {
    b.addEventListener("click", () => {
      try { messenger.runtime.openOptionsPage(); } catch (e) { /* 無視 */ }
    });
  }
});
