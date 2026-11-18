/**
 * Privacy of places in grants (master plan §10). A credential is readable by every site it is
 * shown to, so a precise circle around someone's home tells those sites where they live. These
 * helpers find such circles and offer coarser ones that still contain the original.
 */

const COARSE_DECIMALS = 2;          // 0.01° ≈ 1.1 km of latitude
const PRECISE_RADIUS_M = 1000;
const EARTH_RADIUS_M = 6371008.8;

function decimals(value) {
  const text = String(value);
  if (/e/i.test(text)) return 20;
  return (text.split('.')[1] || '').length;
}

function distanceM(a, b) {
  const rad = Math.PI / 180;
  const dLat = (b.lat - a.lat) * rad; const dLon = (b.lon - a.lon) * rad;
  const h = Math.sin(dLat / 2) ** 2 + Math.cos(a.lat * rad) * Math.cos(b.lat * rad) * Math.sin(dLon / 2) ** 2;
  return 2 * EARTH_RADIUS_M * Math.asin(Math.min(1, Math.sqrt(h)));
}

const isArea = a => a && typeof a === 'object' && Number.isFinite(a.lat) && Number.isFinite(a.lon) && Number.isFinite(a.radius_m);

/** True when an area pinpoints a place: under 1 km across, or centered more precisely than ~100 m. */
export function isPreciseArea(area) {
  return isArea(area) && (area.radius_m < PRECISE_RADIUS_M || decimals(area.lat) > COARSE_DECIMALS + 1 || decimals(area.lon) > COARSE_DECIMALS + 1);
}

/** Every precise area in a grant list, as { grant, area } index pairs. */
export function preciseAreas(grants) {
  const found = [];
  if (!Array.isArray(grants)) return found;
  grants.forEach((grant, g) => (Array.isArray(grant?.where?.areas) ? grant.where.areas : []).forEach((area, a) => { if (isPreciseArea(area)) found.push({ grant: g, area: a }); }));
  return found;
}

/**
 * A coarser area that still contains the original circle: center rounded to 0.01°, radius
 * grown by the distance the center moved, rounded up to 100 m, and at least 1 km.
 */
export function coarsenArea(area) {
  if (!isArea(area)) return area;
  const round = v => Number(v.toFixed(COARSE_DECIMALS));
  const center = { lat: round(area.lat), lon: round(area.lon) };
  const radius = Math.max(PRECISE_RADIUS_M, Math.ceil((area.radius_m + distanceM(area, center)) / 100) * 100);
  return { ...area, ...center, radius_m: radius };
}

/** A copy of the grants with every precise area coarsened. */
export function coarsenGrants(grants) {
  if (!Array.isArray(grants)) return grants;
  return grants.map(grant => {
    if (!Array.isArray(grant?.where?.areas)) return grant;
    return { ...grant, where: { ...grant.where, areas: grant.where.areas.map(a => isPreciseArea(a) ? coarsenArea(a) : a) } };
  });
}

/** The warning shown next to precise areas. */
export const PRECISE_AREA_WARNING = 'This credential pinpoints a place: every site it is shown to can read the circle, so a small one around a home or office reveals where that is. Coarser areas (about 1 km or more) still keep the device near the place.';
