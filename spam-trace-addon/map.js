/**
 * map.js - Map Visualization (Phase 2 / v0.19.11)
 * spec: 09_MAP_VISUALIZATION.md, RELEASE_PREP §2-2
 *
 * オフライン地図。Web Mercator 投影(中心/ズーム/日付変更線処理)。
 * v0.19.9 : 描画を DOM(div) ベースに(popup で SVG が描画されない事象への対策)。
 * v0.19.11: 同梱の Natural Earth 陸地(data/land.json, CC0)を canvas に塗って**大陸を表示**。
 *   レイヤ順: canvas(海+陸) → グリッド(div) → 経路線(div) → マーカー(div)。canvas は TB でも確実に描ける。
 *   陸地データが無ければ従来どおりグリッドのみ(graceful)。ホップ表は renderHopTable。
 */

"use strict";

const TILE_SIZE = 256;
const MAP_MIN_Z = 1;
const MAP_MAX_Z = 12;
const MAP_CENTER_FIT_MAX = 8;

const _mapState = { points: [], zoom: 5, el: null, center: null };

/* ---- 同梱陸地データ(Natural Earth ne_110m_land) ---- */
let _land = null;
let _landTried = false;
async function _loadLand() {
  if (_landTried) return _land;
  _landTried = true;
  try {
    const res = await fetch(messenger.runtime.getURL("data/land.json"));
    if (res.ok) {
      const j = await res.json();
      _land = (j && j.polys) || [];
    } else {
      _land = [];
    }
  } catch (e) {
    _land = [];
  }
  return _land;
}

function _worldX(lon, z) { return ((lon + 180) / 360) * TILE_SIZE * Math.pow(2, z); }
function _worldY(lat, z) {
  const r = (lat * Math.PI) / 180;
  const v = Math.log(Math.tan(r) + 1 / Math.cos(r));
  return ((1 - v / Math.PI) / 2) * TILE_SIZE * Math.pow(2, z);
}
function _latFromWorldY(y, worldW) {
  const t = Math.PI * (1 - (2 * y) / worldW);
  return ((2 * Math.atan(Math.exp(t)) - Math.PI / 2) * 180) / Math.PI;
}
function _wrap180(d) { return (((d + 180) % 360) + 360) % 360 - 180; }

const _NICE_STEPS = [90, 45, 30, 20, 10, 5, 2, 1, 0.5, 0.2, 0.1, 0.05, 0.02, 0.01];
function _niceStep(spanDeg) {
  const target = Math.max(spanDeg, 1e-6) / 5;
  for (const s of _NICE_STEPS) if (s <= target) return s;
  return _NICE_STEPS[_NICE_STEPS.length - 1];
}

function _computeCenter(points) {
  const lats = points.map((p) => p.lat);
  const cLat = (Math.max(...lats) + Math.min(...lats)) / 2;
  const lons = points.map((p) => p.lon);
  if (lons.length === 1) return { lat: cLat, lon: lons[0] };
  const s = [...lons].sort((a, b) => a - b);
  let maxGap = -1;
  let gapAt = 0;
  for (let i = 0; i < s.length; i++) {
    const next = i + 1 < s.length ? s[i + 1] : s[0] + 360;
    const gap = next - s[i];
    if (gap > maxGap) { maxGap = gap; gapAt = i; }
  }
  const start = s[(gapAt + 1) % s.length];
  return { lat: cLat, lon: _wrap180(start + (360 - maxGap) / 2) };
}

function _fitZoomCentered(points, center, w, h) {
  for (let z = Math.min(MAP_MAX_Z, MAP_CENTER_FIT_MAX); z >= MAP_MIN_Z; z--) {
    const worldW = TILE_SIZE * Math.pow(2, z);
    const hx = _worldX(center.lon, z);
    const hy = _worldY(center.lat, z);
    let ok = true;
    for (const p of points) {
      let dx = _worldX(p.lon, z) - hx;
      dx = ((dx % worldW) + worldW) % worldW;
      if (dx > worldW / 2) dx -= worldW;
      const dy = _worldY(p.lat, z) - hy;
      if (Math.abs(dx) > w * 0.4 || Math.abs(dy) > h * 0.4) { ok = false; break; }
    }
    if (ok) return z;
  }
  return MAP_MIN_Z;
}

function _label(i) {
  let s = "";
  i += 1;
  while (i > 0) { const r = (i - 1) % 26; s = String.fromCharCode(65 + r) + s; i = Math.floor((i - 1) / 26); }
  return s;
}

async function renderMap(points, homeCenter) {
  const mapDiv = document.getElementById("map");
  const note = document.getElementById("map-note");
  const valid = points.filter((p) => typeof p.lat === "number" && typeof p.lon === "number");
  if (!valid.length) {
    mapDiv.style.display = "none";
    note.textContent = _t("mapNoGeo");
    return;
  }
  mapDiv.style.display = "";
  note.textContent = _t("mapClickHint");

  _mapState.points = valid;
  _mapState.el = mapDiv;
  _mapState.center =
    homeCenter && Number.isFinite(homeCenter.lat) && Number.isFinite(homeCenter.lon)
      ? { lat: homeCenter.lat, lon: homeCenter.lon }
      : _computeCenter(valid);

  const w = mapDiv.clientWidth || 392;
  const h = mapDiv.clientHeight || 240;
  _mapState.zoom = valid.length === 1 && !homeCenter ? 5 : _fitZoomCentered(valid, _mapState.center, w, h);

  mapDiv.style.position = "relative";
  mapDiv.style.overflow = "hidden";
  mapDiv.style.background = "#dbe9f5";

  await _loadLand();
  _drawMap();
}

function _add(el, css, text) {
  const d = document.createElement("div");
  d.style.cssText = "position:absolute;" + css;
  if (text != null) d.textContent = text;
  el.appendChild(d);
  return d;
}

/** 陸地を canvas に塗る。日付変更線は連続アンラップで処理 */
function _drawLand(el, w, h, zoom, left, top, worldW, screenX, screenY) {
  const cv = document.createElement("canvas");
  cv.width = w;
  cv.height = h;
  cv.style.cssText = "position:absolute;left:0;top:0;pointer-events:none;";
  el.appendChild(cv);
  const ctx = cv.getContext("2d");
  ctx.fillStyle = "#dbe9f5"; // 海
  ctx.fillRect(0, 0, w, h);
  if (!_land || !_land.length) return;
  ctx.fillStyle = "#eae3cf"; // 陸
  ctx.strokeStyle = "#c3ba9f"; // 海岸線
  ctx.lineWidth = 0.6;
  for (const poly of _land) {
    ctx.beginPath();
    const clY = (lat) => screenY(Math.max(-85, Math.min(85, lat))); // 極を避ける(Mercator発散対策)
    for (const ring of poly) {
      if (ring.length < 6) continue;
      let prev = screenX(ring[0]); // 中心に最も近いコピー
      ctx.moveTo(prev, clY(ring[1]));
      for (let k = 2; k < ring.length; k += 2) {
        let x = _worldX(ring[k], zoom) - left; // raw
        x = x - Math.round((x - prev) / worldW) * worldW; // prev に連続させる
        ctx.lineTo(x, clY(ring[k + 1]));
        prev = x;
      }
      ctx.closePath();
    }
    ctx.fill("evenodd");
    ctx.stroke();
  }
}

function _drawMap() {
  const { points, zoom, el, center } = _mapState;
  const w = el.clientWidth || 392;
  const h = el.clientHeight || 240;
  el.textContent = "";

  const cx = _worldX(center.lon, zoom);
  const cy = _worldY(center.lat, zoom);
  const left = cx - w / 2;
  const top = cy - h / 2;
  const worldW = TILE_SIZE * Math.pow(2, zoom);
  const screenX = (lon) => {
    let x = _worldX(lon, zoom) - left;
    x = ((x % worldW) + worldW) % worldW;
    if (x - w / 2 > worldW / 2) x -= worldW;
    return x;
  };
  const screenY = (lat) => _worldY(lat, zoom) - top;

  // --- 陸地(canvas, 最背面) ---
  _drawLand(el, w, h, zoom, left, top, worldW, screenX, screenY);

  // --- 緯度経度グリッド(div) ---
  const lonLeft = (left / worldW) * 360 - 180;
  const lonRight = ((left + w) / worldW) * 360 - 180;
  const latTop = _latFromWorldY(top, worldW);
  const latBottom = _latFromWorldY(top + h, worldW);
  const lonStep = _niceStep(lonRight - lonLeft);
  const latStep = _niceStep(Math.abs(latTop - latBottom));
  const decOf = (st) => (st < 0.1 ? 2 : st < 1 ? 1 : 0);

  for (let lon = Math.ceil(lonLeft / lonStep) * lonStep; lon <= lonRight + 1e-9; lon += lonStep) {
    const x = screenX(lon);
    if (x < -1 || x > w + 1) continue;
    const disp = _wrap180(lon);
    const strong = Math.abs(disp) < 1e-6;
    const tw = strong ? 2 : 1;
    _add(el, `left:${(x - tw / 2).toFixed(1)}px;top:0;width:${tw}px;height:${h}px;` +
      `background:${strong ? "#3d5f7d" : "#7ea3c0"};opacity:0.5;`);
    _add(el, `left:${(x + 2).toFixed(1)}px;top:1px;font-size:9px;color:#3d5f7d;` +
      "pointer-events:none;", `${disp.toFixed(decOf(lonStep))}°`);
  }
  for (let lat = Math.ceil(latBottom / latStep) * latStep; lat <= latTop + 1e-9; lat += latStep) {
    if (lat < -85 || lat > 85) continue;
    const y = screenY(lat);
    if (y < -1 || y > h + 1) continue;
    const strong = Math.abs(lat) < 1e-6;
    const tw = strong ? 2 : 1;
    _add(el, `left:0;top:${(y - tw / 2).toFixed(1)}px;width:${w}px;height:${tw}px;` +
      `background:${strong ? "#3d5f7d" : "#7ea3c0"};opacity:0.5;`);
    _add(el, `left:1px;top:${(y + 1).toFixed(1)}px;font-size:9px;color:#3d5f7d;` +
      "pointer-events:none;", `${lat.toFixed(decOf(latStep))}°`);
  }

  // --- 経路線(div, 回転) ---
  for (let i = 1; i < points.length; i++) {
    const x1 = screenX(points[i - 1].lon);
    const y1 = screenY(points[i - 1].lat);
    const x2 = screenX(points[i].lon);
    const y2 = screenY(points[i].lat);
    const dx = x2 - x1;
    const dy = y2 - y1;
    const len = Math.hypot(dx, dy);
    const ang = (Math.atan2(dy, dx) * 180) / Math.PI;
    _add(el,
      `left:${x1.toFixed(1)}px;top:${(y1 - 1).toFixed(1)}px;width:${len.toFixed(1)}px;height:2px;` +
      "transform-origin:0 50%;transform:rotate(" + ang.toFixed(2) + "deg);pointer-events:none;" +
      "background:repeating-linear-gradient(90deg,#e65100 0 6px,transparent 6px 10px);");

    // v1.1.1: 線の中間に進行方向(送信側→受信側)の矢じり。短すぎる線(同一地点等)は省略
    if (len >= 16) {
      const mx = (x1 + x2) / 2;
      const my = (y1 + y2) / 2;
      _add(el,
        `left:${(mx - 4).toFixed(1)}px;top:${(my - 5).toFixed(1)}px;width:0;height:0;` +
        "border-top:5px solid transparent;border-bottom:5px solid transparent;" +
        "border-left:8px solid #e65100;" +
        "transform-origin:50% 50%;transform:rotate(" + ang.toFixed(2) + "deg);pointer-events:none;");
    }
  }

  // --- マーカー(番号付き) ---
  points.forEach((p, i) => {
    const size = p.isOrigin ? 18 : 15;
    const unv = !p.isOrigin && p.verified === false; // v1.1.0: 境界より下 = 未検証
    const m = _add(el,
      `width:${size}px;height:${size}px;border-radius:50%;` +
      `left:${(screenX(p.lon) - size / 2).toFixed(1)}px;top:${(screenY(p.lat) - size / 2).toFixed(1)}px;` +
      `background:${p.isOrigin ? "#e53935" : unv ? "#bdbdbd" : "#42a5f5"};` +
      `border:2px ${unv ? "dashed" : "solid"} ${p.isOrigin ? "#b71c1c" : unv ? "#616161" : "#1565c0"};` +
      "box-sizing:border-box;cursor:pointer;color:#fff;font-size:9px;font-weight:bold;" +
      "display:flex;align-items:center;justify-content:center;line-height:1;", _label(i));
    const kind = _t(p.isOrigin ? "markerOrigin" : unv ? "markerUnverified" : "markerRelay");
    m.title = `${_label(i)} ${kind}: ${p.ip}`;
    m.addEventListener("click", () => {
      document.getElementById("map-note").textContent =
        `${_label(i)} ${kind}: ${p.ip} | ${p.country || "-"} | ${p.asn || "-"} | ${p.org || "-"}`;
    });
  });

  // --- ズームボタン ---
  const zoomBox = _add(el, "left:6px;top:6px;display:flex;flex-direction:column;gap:2px;");
  for (const [label, delta] of [["+", 1], ["−", -1]]) {
    const btn = document.createElement("button");
    btn.textContent = label;
    btn.style.cssText =
      "width:24px;height:24px;font-size:14px;font-weight:bold;cursor:pointer;" +
      "border:1px solid #999;border-radius:3px;background:#fff;padding:0;";
    btn.addEventListener("click", () => {
      const nz = _mapState.zoom + delta;
      if (nz >= MAP_MIN_Z && nz <= MAP_MAX_Z) { _mapState.zoom = nz; _drawMap(); }
    });
    zoomBox.appendChild(btn);
  }
}

/** ホップ一覧表を描画 (popup 側 #hop-table)。マーカー番号と対応 */
function renderHopTable(points) {
  const box = document.getElementById("hop-table");
  if (!box) return;
  box.textContent = "";
  const valid = points.filter((p) => typeof p.lat === "number" && typeof p.lon === "number");
  const list = valid.length ? valid : points;
  if (!list.length) return;

  const table = document.createElement("table");
  table.style.cssText = "width:100%;border-collapse:collapse;font-size:11px;margin-top:4px;";
  const head = document.createElement("tr");
  for (const key of ["hopColNo", "hopColIp", "hopColCountry", "hopColAsn", "hopColTrust"]) {
    const th = document.createElement("td");
    th.textContent = _t(key);
    th.style.cssText = "color:#777;border-bottom:1px solid #ddd;padding:2px 4px;white-space:nowrap;";
    head.appendChild(th);
  }
  table.appendChild(head);
  list.forEach((p, i) => {
    const tr = document.createElement("tr");
    const trust = p.verified === true ? _t("hopVerified")
      : p.verified === false ? _t("hopUnverified") : "-"; // v1.1.0
    const cells = [_label(i), p.ip || "-", `${p.country || "-"}`, p.asn || "-", trust];
    cells.forEach((c, ci) => {
      const td = document.createElement("td");
      td.textContent = c;
      td.style.cssText =
        "padding:2px 4px;vertical-align:top;word-break:break-all;" +
        (ci === 0 ? "font-weight:bold;color:#1565c0;white-space:nowrap;" : "");
      tr.appendChild(td);
    });
    table.appendChild(tr);
  });
  box.appendChild(table);
}
