/**
 * asn.js - ASN Analyzer (Phase 2)
 * spec: 04_ASN_ANALYZER.md
 *
 * ip-api.com の結果から ASN / Organization / Hosting / VPN-Proxy を分類し、
 * 高リスククラウド事業者リストと照合する。
 */

"use strict";

/** spec 04 高リスク候補。
 *  注: amazon/aws は除外 (v0.11.1)。Amazon SES等の正規メール送信に多用され
 *  誤検知源となるため。AWS悪用スパムは hosting 加点と認証failで捕捉する。 */
const HIGH_RISK_ORGS = [
  "ovh",
  "hetzner",
  "digitalocean",
  "azure", // Microsoft Azure (VM/ホスティング)
  "tencent",
  "alibaba",
  "linode",
  "vultr",
];

/** 信頼送信ホスト(主要メール配信基盤, spec 04 v0.11.0)。org/asname/ISP の部分一致で判定。
 *  認証pass条件付きで減点 (risk.js)。保守は spec 16。 */
const TRUSTED_SENDING_HOSTS = [
  "sendgrid",
  "amazon ses",
  "amazonses",
  "mailgun",
  "mailchimp",
  "mandrill",
  "sparkpost",
  "postmark",
  "sendinblue",
  "brevo",
  "constant contact",
  "salesforce",
  "mailjet",
  "zoho",
  "benchmark",
  "klaviyo",
];

/**
 * @param {Object} geo lookupIP() の結果
 * @param {boolean|null} tor isTorExit() の結果 (nullは判定不能)
 * @returns {Object} 分類結果
 */
function classifyASN(geo, tor) {
  const orgText = `${geo.org || ""} ${geo.isp || ""} ${geo.asname || ""}`.toLowerCase();
  const highRiskCloud = HIGH_RISK_ORGS.some((o) => orgText.includes(o));
  const trustedHost = TRUSTED_SENDING_HOSTS.some((h) => orgText.includes(h));

  return {
    asn: (geo.as || "").split(" ")[0] || null, // "AS12345 Org" -> "AS12345"
    asname: geo.asname || null,
    org: geo.org || geo.isp || null,
    isp: geo.isp || null,
    country: geo.country || null,
    countryCode: geo.countryCode || null,
    hosting: !!geo.hosting,
    proxyOrVpn: !!geo.proxy,
    tor: tor, // true / false / null(判定不能)
    highRiskCloud,
    trustedHost, // 信頼送信ホスト (spec 04 v0.11.0)
  };
}
