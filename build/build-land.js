#!/usr/bin/env node
/**
 * build-land.js — Natural Earth land シェープファイル(.shp, Polygon=type5)を
 * コンパクトな JSON(data/land.json)へ変換する。GDAL 等は不要(.shp を直接パース)。
 *
 * 入力: ne_110m_land.shp (WGS84 lon/lat, shapeType 5)
 * 出力: { polys: [ [ [lon,lat,lon,lat,...](ring), ...(holes) ], ... ] }  座標は小数2桁に丸め
 * 使い方: node build/build-land.js <path/to/ne_110m_land.shp> [out=spam-trace-addon/data/land.json]
 */
"use strict";
const fs = require("fs");
const path = require("path");

function main() {
  const inPath = process.argv[2];
  const outPath = process.argv[3] || "spam-trace-addon/data/land.json";
  if (!inPath) { console.error("usage: node build/build-land.js <ne_110m_land.shp> [out]"); process.exit(1); }
  const b = fs.readFileSync(inPath);
  if (b.readInt32LE(32) !== 5) { console.error("shapeType != 5 (Polygon). got " + b.readInt32LE(32)); process.exit(1); }

  const R = (v) => Math.round(v * 1000) / 1000; // 小数3桁(約110m精度)
  const polys = [];
  let off = 100; // ヘッダ後
  while (off + 8 <= b.length) {
    // レコードヘッダ(big-endian): 番号, 内容長(16bit語)
    const contentLen = b.readInt32BE(off + 4) * 2;
    let p = off + 8;
    const shapeType = b.readInt32LE(p); p += 4;
    if (shapeType === 5) {
      p += 32; // box (4 doubles)
      const numParts = b.readInt32LE(p); p += 4;
      const numPoints = b.readInt32LE(p); p += 4;
      const parts = [];
      for (let i = 0; i < numParts; i++) { parts.push(b.readInt32LE(p)); p += 4; }
      const ptsOff = p;
      const rings = [];
      for (let i = 0; i < numParts; i++) {
        const s = parts[i];
        const e = i + 1 < numParts ? parts[i + 1] : numPoints;
        const ring = [];
        let plx = NaN;
        let ply = NaN;
        for (let k = s; k < e; k++) {
          const x = R(b.readDoubleLE(ptsOff + k * 16));
          const y = R(b.readDoubleLE(ptsOff + k * 16 + 8));
          if (x === plx && y === ply) continue; // 連続重複点を除去
          ring.push(x, y);
          plx = x; ply = y;
        }
        if (ring.length >= 6) rings.push(ring);
      }
      polys.push(rings);
    }
    off += 8 + contentLen;
  }

  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, JSON.stringify({ polys }));
  const totalPts = polys.reduce((a, r) => a + r.reduce((b2, ring) => b2 + ring.length / 2, 0), 0);
  console.log(`polygons=${polys.length} rings=${polys.reduce((a,r)=>a+r.length,0)} points=${totalPts} bytes=${fs.statSync(outPath).size} (${(fs.statSync(outPath).size/1024).toFixed(1)}KB) -> ${outPath}`);
}
main();
