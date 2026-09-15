/**
 * i18n.js - 多言語対応ヘルパー (v0.4.0)
 * spec: 12_I18N.md
 *
 * 全スクリプトの先頭で読み込むこと (popup.html / manifest background)。
 */

"use strict";

/**
 * 翻訳文字列を取得。i18n API が使えない環境(単体テスト等)ではキーをそのまま返す。
 * @param {string} key messages.json のキー
 * @param {string[]} [subs] プレースホルダ置換値
 */
function _t(key, subs) {
  try {
    if (typeof messenger !== "undefined" && messenger.i18n) {
      const m = messenger.i18n.getMessage(key, subs);
      if (m) return m;
    }
  } catch (e) {
    /* fall through */
  }
  return key;
}

/** data-i18n 属性を持つ全要素のtextContentを翻訳で置き換える */
function localizeDocument() {
  if (typeof document === "undefined") return;
  for (const el of document.querySelectorAll("[data-i18n]")) {
    const msg = _t(el.getAttribute("data-i18n"));
    if (msg) el.textContent = msg;
  }
}
