/**
 * geo.js - GeoIP / ASN lookup (Phase 2 / v0.19.4-)
 * spec: 04_ASN_ANALYZER.md, RELEASE_PREP §2-1, §2-3
 *
 * プロバイダ (settings.geoProvider):
 *   - "local"   : 同梱ローカルDB(DB-IP由来)でIPv4→国のみ解決。外部通信なし・権限不要。既定。
 *   - "ipwho.is": ipwho.is (HTTPS・キー不要, オプトイン)。ホスト権限は options で optional 要求。
 *   - "off"     : オンライン照会しない。
 *   (v0.19.4: ip-api.com は廃止=HTTP のため。未知の値は local 扱い)
 * Tor判定 (isTorExit) は settings.torEnabled のオプトイン (既定off)。
 * オンライン結果は 24h storage.local キャッシュ。
 */

"use strict";

const GEO_CACHE_TTL = 24 * 60 * 60 * 1000; // 24h
const TOR_CACHE_TTL = 60 * 60 * 1000; // 1h

/** 現在のプロバイダ (設定、既定 local) */
async function _geoProvider() {
  try {
    const p = (await getSettings()).geoProvider;
    return p === "ipwho.is" || p === "off" ? p : "local";
  } catch (e) {
    return "local";
  }
}

/** 選択プロバイダでIP情報を取得。offは例外。localはオフライン即時 */
async function lookupIP(ip) {
  const provider = await _geoProvider();
  if (provider === "off") throw new Error("online geo lookup disabled");
  if (provider !== "ipwho.is") return _lookupLocal(ip);

  const cacheKey = `geo:ipwho.is:${ip}`;
  const cached = await getCache(cacheKey, GEO_CACHE_TTL);
  if (cached) return cached;
  const data = await _lookupIpwhois(ip);
  await setCache(cacheKey, data);
  return data;
}

/** ローカルDB(オフライン)。国コードのみ→代表座標を補完。ASN等は無し */
async function _lookupLocal(ip) {
  const cc = await localCountryLookup(ip); // geolocal.js
  const centroid = cc ? countryCentroid(cc) : null; // geodata.js
  return {
    status: "success",
    query: ip,
    country: cc ? countryName(cc) : null,
    countryCode: cc || null,
    city: null,
    lat: centroid ? centroid[0] : null,
    lon: centroid ? centroid[1] : null,
    isp: null,
    org: null,
    as: "",
    asname: null,
    proxy: false,
    hosting: false,
    _local: true,
  };
}

/** ipwho.is (HTTPS)。応答を ip-api 互換の形へ正規化 (classifyASN/map が参照) */
async function _lookupIpwhois(ip) {
  const res = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`);
  if (res.status === 429) throw new Error("ipwho.is rate limited (429)");
  if (!res.ok) throw new Error(`ipwho.is HTTP ${res.status}`);
  const d = await res.json();
  if (d && d.success === false) {
    throw new Error(`ipwho.is: ${d.message || "lookup failed"}`);
  }
  const conn = d.connection || {};
  return {
    status: "success",
    query: d.ip || ip,
    country: d.country || null,
    countryCode: d.country_code || null,
    city: d.city || null,
    lat: typeof d.latitude === "number" ? d.latitude : null,
    lon: typeof d.longitude === "number" ? d.longitude : null,
    isp: conn.isp || null,
    org: conn.org || conn.isp || null,
    as: conn.asn ? `AS${conn.asn}` : "",
    asname: conn.org || conn.isp || null,
    proxy: false,
    hosting: false,
  };
}

/**
 * TOR exit nodeリストを取得し、ipが含まれるか判定 (キャッシュ付き)。
 * settings.torEnabled が false のときは照会せず null (オプトイン, §2-3)。
 */
async function isTorExit(ip) {
  let enabled = false;
  try {
    enabled = !!(await getSettings()).torEnabled;
  } catch (e) {
    enabled = false;
  }
  if (!enabled) return null;

  const cacheKey = "tor:exitlist";
  let list = await getCache(cacheKey, TOR_CACHE_TTL);
  if (!list) {
    try {
      const res = await fetch("https://check.torproject.org/torbulkexitlist");
      if (!res.ok) throw new Error(`torproject HTTP ${res.status}`);
      const text = await res.text();
      list = text.split("\n").map((l) => l.trim()).filter(Boolean);
      await setCache(cacheKey, list);
    } catch (e) {
      console.warn("TOR list fetch failed:", e);
      return null;
    }
  }
  return list.includes(ip);
}

/* ---- storage.local cache helpers ---- */

async function getCache(key, ttl) {
  const obj = await messenger.storage.local.get(key);
  const hit = obj[key];
  if (hit && Date.now() - hit.t < ttl) return hit.v;
  return null;
}

async function setCache(key, value) {
  await messenger.storage.local.set({ [key]: { t: Date.now(), v: value } });
}
