/**
 * geolocal.js - ローカル(オフライン)IP→国 照会 (v0.19.2)
 * spec: RELEASE_PREP §2-1
 *
 * ビルド時に生成した data/ip-country-v4.bin (DB-IP IP-to-Country Lite 由来, CC BY 4.0)
 * を読み込み、IPv4 → 国コードを二分探索で解決する。外部通信なし。
 * DBが未同梱/読込不可でも例外を出さず null を返す(=不明)。
 * 国コード→代表座標/名称は geodata.js。IPv6 は本バージョン未対応(null)。
 */

"use strict";

let _ipc = null;
let _ipcTried = false;

async function _loadIpCountryDb() {
  if (_ipcTried) return _ipc;
  _ipcTried = true;
  try {
    const url = messenger.runtime.getURL("data/ip-country-v4.bin");
    const res = await fetch(url);
    if (!res.ok) throw new Error(`bin HTTP ${res.status}`);
    const ab = await res.arrayBuffer();
    const dv = new DataView(ab);
    // magic "IPC1"
    if (
      dv.getUint8(0) !== 0x49 || dv.getUint8(1) !== 0x50 ||
      dv.getUint8(2) !== 0x43 || dv.getUint8(3) !== 0x31
    ) {
      throw new Error("bad magic");
    }
    let o = 4;
    const N = dv.getUint32(o, true); o += 4;
    const C = dv.getUint16(o, true); o += 2;
    const countries = [];
    for (let i = 0; i < C; i++) {
      countries.push(String.fromCharCode(dv.getUint8(o), dv.getUint8(o + 1)));
      o += 2;
    }
    o = (o + 3) & ~3; // 4バイト境界へ
    const starts = new Uint32Array(ab, o, N); o += N * 4;
    const idx = new Uint16Array(ab, o, N);
    _ipc = { N, countries, starts, idx };
  } catch (e) {
    console.warn("SPAMTRACE local ip-country db unavailable:", e.message);
    _ipc = null;
  }
  return _ipc;
}

function _ip2int(s) {
  const p = s.split(".");
  if (p.length !== 4) return null;
  let n = 0;
  for (const o of p) {
    const v = Number(o);
    if (!Number.isInteger(v) || v < 0 || v > 255) return null;
    n = n * 256 + v;
  }
  return n >>> 0;
}

/** IPv4 → 国コード(2文字)。不明/IPv6/DB無しは null */
async function localCountryLookup(ip) {
  if (!ip || ip.includes(":")) return null; // IPv6 未対応
  const n = _ip2int(ip);
  if (n == null) return null;
  const db = await _loadIpCountryDb();
  if (!db || db.N === 0) return null;
  let lo = 0;
  let hi = db.N - 1;
  let ans = 0;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (db.starts[mid] <= n) { ans = mid; lo = mid + 1; } else { hi = mid - 1; }
  }
  const cc = db.countries[db.idx[ans]];
  return cc && cc !== "??" ? cc : null;
}
