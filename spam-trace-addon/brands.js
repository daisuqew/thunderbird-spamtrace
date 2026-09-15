/**
 * brands.js - ブランドなりすまし検出 (v0.7.0)
 * spec: 15_BRAND_CHECK.md
 *
 * From表示名/件名のブランド名と、Fromドメイン・認証結果の整合を判定する。
 * 「Amazonを名乗るのに無関係なインフラから送信」型のフィッシングを
 * 国に依存せず検出する。
 */

"use strict";

/** 既定ブランド表 (spec 15)。domains は登録可能ドメインで記載 */
const DEFAULT_BRANDS = [
  { name: "Amazon", patterns: ["amazon", "アマゾン"], domains: ["amazon.co.jp", "amazon.com", "amazon.de", "amazon.fr", "amazon.it", "amazon.es", "amazon.co.uk", "amazon.ca", "amazon.in", "amazon.com.au", "amazon.cn"] },
  { name: "Rakuten", patterns: ["rakuten", "楽天"], domains: ["rakuten.co.jp", "rakuten.com", "rakuten-card.co.jp", "rakuten-bank.co.jp"] },
  { name: "PayPal", patterns: ["paypal", "ペイパル"], domains: ["paypal.com", "paypal.jp"] },
  { name: "Apple", patterns: ["apple", "アップル", "icloud"], domains: ["apple.com", "icloud.com"] },
  { name: "Microsoft", patterns: ["microsoft", "マイクロソフト"], domains: ["microsoft.com", "microsoftonline.com", "outlook.com", "live.com"] },
  { name: "Google", patterns: ["google", "グーグル"], domains: ["google.com", "gmail.com", "googlemail.com"] },
  { name: "Netflix", patterns: ["netflix", "ネットフリックス"], domains: ["netflix.com"] },
  { name: "SMBC", patterns: ["smbc", "三井住友"], domains: ["smbc.co.jp", "smbc-card.com", "smbc-finance.co.jp"] },
  { name: "MUFG", patterns: ["mufg", "三菱ufj", "三菱UFJ銀行"], domains: ["mufg.jp", "bk.mufg.jp"] },
  { name: "Mizuho", patterns: ["mizuho", "みずほ"], domains: ["mizuhobank.co.jp", "mizuho-fg.co.jp"] },
  { name: "Yamato", patterns: ["クロネコ", "ヤマト運輸", "kuronekoyamato"], domains: ["kuronekoyamato.co.jp", "yamato-transport.com"] },
  { name: "Sagawa", patterns: ["佐川急便", "sagawa"], domains: ["sagawa-exp.co.jp"] },
  { name: "JapanPost", patterns: ["日本郵便", "ゆうちょ", "japanpost"], domains: ["japanpost.jp", "jp-bank.japanpost.jp"] },
  { name: "Aeon", patterns: ["イオンカード", "aeon"], domains: ["aeon.co.jp", "aeoncard.co.jp"] },
];

/** 既定 + 設定のカスタムブランドを返す */
async function getBrands() {
  try {
    const s = await getSettings();
    const custom = Array.isArray(s.customBrands) ? s.customBrands : [];
    return DEFAULT_BRANDS.concat(
      custom.filter((b) => b && b.name && Array.isArray(b.patterns) && Array.isArray(b.domains))
    );
  } catch (e) {
    return DEFAULT_BRANDS;
  }
}

/** 指定ドメインが属する既定ブランドの正規ドメイン集合を返す (links.jsの関連判定用, spec 14)。
 *  該当なしはnull。登録可能ドメインのSetを返す。 */
function brandDomainsOf(domain) {
  const reg = registrableDomain(domain);
  if (!reg) return null;
  for (const b of DEFAULT_BRANDS) {
    const set = new Set(b.domains.map((d) => registrableDomain(d.toLowerCase())));
    if (set.has(reg)) return set;
  }
  return null;
}

/** ASCIIパターンは単語境界つき、非ASCIIは部分一致で検索 */
function _matchesPattern(text, pattern) {
  if (/^[\x00-\x7F]+$/.test(pattern)) {
    const re = new RegExp(`(?:^|[^a-z0-9])${pattern.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?:[^a-z0-9]|$)`, "i");
    return re.test(text);
  }
  return text.includes(pattern);
}

/**
 * ブランド整合チェック (spec 15)
 * @param {Object} parsed analyzeHeaders() の結果
 * @returns {Object|null} {brand, spoof, authFail, unverified} ブランド非検出ならnull
 */
async function checkBrand(parsed) {
  const fromReg = registrableDomain(parsed.fromDomain);

  // 信頼ドメインはブランド判定をスキップ (spec 15, v0.8.0)
  if (fromReg && (await isTrustedDomain(parsed.fromDomain))) return null;

  // 表示名(なりすましの典型) と 件名(正規キャンペーンでも頻出) を分離 (v0.8.0)
  const displayName = (parsed.from || "").replace(/<[^>]*>/g, "").toLowerCase();
  const subject = (parsed.subject || "").toLowerCase();

  const brands = await getBrands();
  for (const b of brands) {
    const inName = b.patterns.some((p) => _matchesPattern(displayName, p.toLowerCase()));
    const inSubject = b.patterns.some((p) => _matchesPattern(subject, p.toLowerCase()));
    if (!inName && !inSubject) continue;

    const isBrandDomain = !!fromReg && b.domains.some((d) => registrableDomain(d.toLowerCase()) === fromReg);

    if (!isBrandDomain) {
      if (inName) {
        // 表示名でブランドを名乗るのに正規ドメインでない → なりすまし (強)
        return { brand: b.name, spoof: true, mention: false, authFail: false, unverified: false };
      }
      // 件名のみの言及 → 弱シグナル (正規メルマガの可能性)
      return { brand: b.name, spoof: false, mention: true, authFail: false, unverified: false };
    }
    const { spf, dkim, dmarc } = parsed.auth;
    if (spf === "fail" || dkim === "fail" || dmarc === "fail") {
      // 正規ドメインだが認証fail → From偽装の疑い (強)
      return { brand: b.name, spoof: false, mention: false, authFail: true, unverified: false };
    }
    if (spf === "none" && dkim === "none" && dmarc === "none") {
      // 認証結果なし → 検証不能 (弱)
      return { brand: b.name, spoof: false, mention: false, authFail: false, unverified: true };
    }
    return { brand: b.name, spoof: false, mention: false, authFail: false, unverified: false };
  }
  return null;
}
