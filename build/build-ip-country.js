#!/usr/bin/env node
/**
 * build-ip-country.js — DB-IP IP-to-Country Lite CSV を
 * コンパクトな IPv4 国レンジ表(data/ip-country-v4.bin)へ変換する。
 *
 * 入力: DB-IP "IP to Country Lite" CSV (start_ip,end_ip,country_code)。.gz 可。
 *       IPv6 行(':' を含む)はスキップ(v0.19.2 は IPv4 のみ)。
 * 出力バイナリ形式 (little-endian, "IPC1"):
 *   [0]   magic "IPC1" (4B)
 *   [4]   uint32 N   エントリ数
 *   [8]   uint16 C   国コード数(index0='??'=不明)
 *   [10]  C*2B       国コード ASCII (2文字ずつ)
 *   pad   4バイト境界まで 0 埋め
 *   +     N*uint32   starts (昇順)
 *   +     N*uint16   idx    (starts[i]..starts[i+1)-1 の国index。0=不明/gap)
 * ライセンス: DB-IP Lite は CC BY 4.0。UI に db-ip.com へのリンク表示が必須。
 *
 * 使い方: node build/build-ip-country.js <input.csv[.gz]> [out=spam-trace-addon/data/ip-country-v4.bin]
 */
"use strict";
const fs = require("fs");
const path = require("path");
const zlib = require("zlib");

function ip2int(s) {
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

function main() {
  const inPath = process.argv[2];
  const outPath = process.argv[3] || "spam-trace-addon/data/ip-country-v4.bin";
  if (!inPath) {
    console.error("usage: node build/build-ip-country.js <csv[.gz]> [out]");
    process.exit(1);
  }
  let buf = fs.readFileSync(inPath);
  if (inPath.endsWith(".gz")) buf = zlib.gunzipSync(buf);
  const text = buf.toString("utf8");

  const rows = [];
  let skippedV6 = 0;
  for (const line of text.split(/\r?\n/)) {
    if (!line) continue;
    const m = line.split(",");
    if (m.length < 3) continue;
    const start = m[0].replace(/"/g, "").trim();
    const end = m[1].replace(/"/g, "").trim();
    const cc = m[2].replace(/"/g, "").trim().toUpperCase();
    if (start.includes(":") || end.includes(":")) { skippedV6++; continue; }
    const s = ip2int(start);
    const e = ip2int(end);
    if (s == null || e == null || !/^[A-Z]{2}$/.test(cc)) continue;
    if (cc === "ZZ" || cc === "XX") continue; // 予約/不明はgap(=不明)扱い
    rows.push([s, e, cc]);
  }
  rows.sort((a, b) => a[0] - b[0]);

  const countries = ["??"];
  const cidx = { "??": 0 };
  const idxOf = (cc) => (cidx[cc] != null ? cidx[cc] : (cidx[cc] = countries.push(cc) - 1));

  const starts = [];
  const idxs = [];
  const push = (start, idx) => {
    if (idxs.length && idxs[idxs.length - 1] === idx) return; // merge
    starts.push(start >>> 0);
    idxs.push(idx);
  };
  let cursor = 0;
  for (const [s, e, cc] of rows) {
    if (s > cursor) push(cursor, 0); // gap → unknown
    push(s, idxOf(cc));
    cursor = e >= 0xffffffff ? 0x100000000 : (e + 1) >>> 0;
  }
  if (cursor < 0x100000000) push(cursor >>> 0, 0); // trailing unknown
  if (starts.length === 0 || starts[0] !== 0) { starts.unshift(0); idxs.unshift(0); }

  const N = starts.length;
  const C = countries.length;
  let header = 4 + 4 + 2 + C * 2;
  const pad = (4 - (header % 4)) % 4;
  header += pad;
  const out = Buffer.alloc(header + N * 4 + N * 2);
  let o = 0;
  out.write("IPC1", o, "ascii"); o = 4;
  out.writeUInt32LE(N, o); o += 4;
  out.writeUInt16LE(C, o); o += 2;
  for (const cc of countries) { out.write(cc.padEnd(2).slice(0, 2), o, "ascii"); o += 2; }
  o += pad; // alignment padding (zeros)
  for (let i = 0; i < N; i++) { out.writeUInt32LE(starts[i] >>> 0, o); o += 4; }
  for (let i = 0; i < N; i++) { out.writeUInt16LE(idxs[i], o); o += 2; }

  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, out);
  console.log(
    `IPv4 rows=${rows.length} (v6 skipped=${skippedV6}) → entries N=${N}, countries C=${C}, ` +
    `bytes=${out.length} (${(out.length / 1024 / 1024).toFixed(2)} MB) → ${outPath}`
  );
}

main();
