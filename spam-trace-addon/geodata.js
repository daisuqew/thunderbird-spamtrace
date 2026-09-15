/**
 * geodata.js - 国コード → 国名 + 代表座標(重心近似) (v0.19.2)
 * spec: RELEASE_PREP §2-1
 *
 * ローカルDB(国レベル)には緯度経度が無いため、地図表示用に国コードから
 * 代表座標(おおよその重心)を引く。座標は概算。未収録コードは名称=コード・座標なし。
 * 外部データ非依存(ハードコード)。
 */

"use strict";

// CC: [国名, 緯度, 経度]
const COUNTRY_INFO = {
  AD: ["Andorra", 42.5, 1.6], AE: ["United Arab Emirates", 24.0, 54.0],
  AF: ["Afghanistan", 33.9, 67.7], AL: ["Albania", 41.1, 20.1],
  AM: ["Armenia", 40.1, 45.0], AO: ["Angola", -11.2, 17.9],
  AR: ["Argentina", -34.0, -64.0], AT: ["Austria", 47.6, 14.1],
  AU: ["Australia", -25.0, 133.0], AZ: ["Azerbaijan", 40.4, 47.6],
  BA: ["Bosnia and Herzegovina", 43.9, 17.7], BD: ["Bangladesh", 23.7, 90.4],
  BE: ["Belgium", 50.6, 4.6], BG: ["Bulgaria", 42.7, 25.5],
  BH: ["Bahrain", 26.0, 50.5], BO: ["Bolivia", -16.3, -63.6],
  BR: ["Brazil", -10.0, -55.0], BY: ["Belarus", 53.7, 27.9],
  CA: ["Canada", 56.0, -106.0], CH: ["Switzerland", 46.8, 8.2],
  CL: ["Chile", -35.7, -71.5], CN: ["China", 35.0, 103.0],
  CO: ["Colombia", 4.6, -74.3], CR: ["Costa Rica", 9.7, -83.8],
  CY: ["Cyprus", 35.1, 33.4], CZ: ["Czechia", 49.8, 15.5],
  DE: ["Germany", 51.0, 10.0], DK: ["Denmark", 56.0, 9.5],
  DO: ["Dominican Republic", 18.7, -70.2], DZ: ["Algeria", 28.0, 2.6],
  EC: ["Ecuador", -1.4, -78.2], EE: ["Estonia", 58.6, 25.0],
  EG: ["Egypt", 26.8, 30.8], ES: ["Spain", 40.0, -3.7],
  ET: ["Ethiopia", 9.1, 40.5], FI: ["Finland", 64.0, 26.0],
  FR: ["France", 46.5, 2.5], GB: ["United Kingdom", 54.0, -2.0],
  GE: ["Georgia", 42.3, 43.4], GH: ["Ghana", 7.9, -1.0],
  GR: ["Greece", 39.1, 22.0], GT: ["Guatemala", 15.7, -90.2],
  HK: ["Hong Kong", 22.3, 114.2], HR: ["Croatia", 45.1, 15.5],
  HU: ["Hungary", 47.2, 19.4], ID: ["Indonesia", -2.5, 118.0],
  IE: ["Ireland", 53.2, -8.0], IL: ["Israel", 31.4, 35.0],
  IN: ["India", 22.0, 79.0], IQ: ["Iraq", 33.2, 43.7],
  IR: ["Iran", 32.4, 53.7], IS: ["Iceland", 64.9, -19.0],
  IT: ["Italy", 42.5, 12.5], JO: ["Jordan", 31.2, 36.8],
  JP: ["Japan", 36.2, 138.25], KE: ["Kenya", 0.2, 37.9],
  KH: ["Cambodia", 12.6, 104.9], KR: ["South Korea", 36.5, 127.8],
  KW: ["Kuwait", 29.3, 47.5], KZ: ["Kazakhstan", 48.0, 68.0],
  LA: ["Laos", 19.9, 102.5], LB: ["Lebanon", 33.9, 35.9],
  LK: ["Sri Lanka", 7.9, 80.7], LT: ["Lithuania", 55.2, 23.9],
  LU: ["Luxembourg", 49.8, 6.1], LV: ["Latvia", 56.9, 24.6],
  LY: ["Libya", 26.3, 17.2], MA: ["Morocco", 31.8, -7.1],
  MD: ["Moldova", 47.2, 28.5], ME: ["Montenegro", 42.7, 19.4],
  MK: ["North Macedonia", 41.6, 21.7], MM: ["Myanmar", 21.9, 95.9],
  MN: ["Mongolia", 46.9, 103.8], MT: ["Malta", 35.9, 14.4],
  MX: ["Mexico", 23.6, -102.5], MY: ["Malaysia", 4.2, 108.0],
  NG: ["Nigeria", 9.1, 8.7], NL: ["Netherlands", 52.2, 5.3],
  NO: ["Norway", 64.0, 12.0], NP: ["Nepal", 28.4, 84.1],
  NZ: ["New Zealand", -41.5, 173.0], OM: ["Oman", 21.5, 55.9],
  PA: ["Panama", 8.5, -80.1], PE: ["Peru", -9.2, -75.0],
  PH: ["Philippines", 12.9, 121.8], PK: ["Pakistan", 30.4, 69.3],
  PL: ["Poland", 52.1, 19.4], PT: ["Portugal", 39.6, -8.0],
  PY: ["Paraguay", -23.4, -58.4], QA: ["Qatar", 25.3, 51.2],
  RO: ["Romania", 45.9, 24.9], RS: ["Serbia", 44.2, 20.9],
  RU: ["Russia", 61.5, 105.0], SA: ["Saudi Arabia", 24.0, 45.0],
  SE: ["Sweden", 62.0, 15.0], SG: ["Singapore", 1.35, 103.8],
  SI: ["Slovenia", 46.1, 14.8], SK: ["Slovakia", 48.7, 19.7],
  SV: ["El Salvador", 13.8, -88.9], SY: ["Syria", 35.0, 38.0],
  TH: ["Thailand", 15.1, 101.0], TN: ["Tunisia", 34.0, 9.6],
  TR: ["Turkey", 39.0, 35.2], TW: ["Taiwan", 23.7, 121.0],
  TZ: ["Tanzania", -6.4, 34.9], UA: ["Ukraine", 48.4, 31.2],
  UG: ["Uganda", 1.4, 32.3], US: ["United States", 39.5, -98.35],
  UY: ["Uruguay", -32.5, -55.8], UZ: ["Uzbekistan", 41.4, 63.6],
  VE: ["Venezuela", 6.4, -66.6], VN: ["Vietnam", 16.2, 107.8],
  YE: ["Yemen", 15.6, 48.0], ZA: ["South Africa", -29.0, 24.0],
  ZM: ["Zambia", -13.5, 27.8], ZW: ["Zimbabwe", -19.0, 29.9],
};

/** 国コード → 国名(未収録はコードをそのまま返す) */
function countryName(cc) {
  if (!cc) return null;
  const e = COUNTRY_INFO[cc.toUpperCase()];
  return e ? e[0] : cc;
}

/** 国コード → [lat, lon](未収録は null) */
function countryCentroid(cc) {
  if (!cc) return null;
  const e = COUNTRY_INFO[cc.toUpperCase()];
  return e ? [e[1], e[2]] : null;
}
