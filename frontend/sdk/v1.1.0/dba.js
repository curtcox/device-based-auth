// devicebasedauth.org browser SDK v1.1.0. Built by scripts/build-sdk.mjs from packages/browser-sdk and packages/verify. MIT.

// packages/verify/src/jose.js
var encoder = new TextEncoder();
var decoder = new TextDecoder();
var ES256 = { name: "ECDSA", namedCurve: "P-256" };
var SIGN = { name: "ECDSA", hash: "SHA-256" };
function b64u(input) {
  const bytes = typeof input === "string" ? encoder.encode(input) : input instanceof Uint8Array ? input : new Uint8Array(input);
  let binary = "";
  for (let i = 0; i < bytes.length; i += 32768) binary += String.fromCharCode(...bytes.subarray(i, i + 32768));
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}
function unb64u(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]*$/.test(value)) throw new Error("invalid base64url");
  const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - value.length % 4) % 4);
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}
function unb64uJson(value) {
  return JSON.parse(decoder.decode(unb64u(value)));
}
async function sha256b64u(value) {
  return b64u(new Uint8Array(await crypto.subtle.digest("SHA-256", typeof value === "string" ? encoder.encode(value) : value)));
}
function publicJwk(jwk) {
  if (!jwk || jwk.kty !== "EC" || jwk.crv !== "P-256" || typeof jwk.x !== "string" || typeof jwk.y !== "string") throw new Error("expected a P-256 public JWK");
  return { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y };
}
async function generateKeyPair(extractable = false) {
  return crypto.subtle.generateKey(ES256, extractable, ["sign", "verify"]);
}
async function exportPublicJwk(publicKey) {
  return publicJwk(await crypto.subtle.exportKey("jwk", publicKey));
}
async function signJws(header, payload, privateKey) {
  const input = `${b64u(JSON.stringify({ ...header, alg: "ES256" }))}.${b64u(JSON.stringify(payload))}`;
  const signature = new Uint8Array(await crypto.subtle.sign(SIGN, privateKey, encoder.encode(input)));
  return `${input}.${b64u(signature)}`;
}
function decodeJws(jws) {
  if (typeof jws !== "string" || jws.length > 65536) throw new Error("invalid_format");
  const parts = jws.split(".");
  if (parts.length !== 3) throw new Error("invalid_format");
  try {
    const header = unb64uJson(parts[0]);
    const payload = unb64uJson(parts[1]);
    const signature = unb64u(parts[2]);
    if (!header || typeof header !== "object" || !payload || typeof payload !== "object" || Array.isArray(payload)) throw new Error("invalid_format");
    return { header, payload, signature, signingInput: `${parts[0]}.${parts[1]}` };
  } catch {
    throw new Error("invalid_format");
  }
}

// packages/verify/src/grants.js
var DAYS = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];
var USE_PERIODS = ["minute", "hour", "day", "month", "total"];
var GRANT_KEYS = /* @__PURE__ */ new Set(["actions", "resources", "when", "where", "limits", "require"]);
var WHEN_KEYS = /* @__PURE__ */ new Set(["tz", "windows", "not_before", "not_after"]);
var WINDOW_KEYS = /* @__PURE__ */ new Set(["days", "from", "to"]);
var WHERE_KEYS = /* @__PURE__ */ new Set(["source", "countries", "regions", "areas", "networks"]);
var AREA_KEYS = /* @__PURE__ */ new Set(["lat", "lon", "radius_m"]);
var LIMIT_KEYS = /* @__PURE__ */ new Set(["uses", "spend_usd_per_month"]);
var USES_KEYS = /* @__PURE__ */ new Set(["count", "per"]);
var REQUIRE_KEYS = /* @__PURE__ */ new Set(["online", "step_up", "attestation", "verified_boot"]);
var ATTESTATION_LEVELS = { hardware: ["tee", "strongbox"], strongbox: ["strongbox"] };
var ACTION = /^[a-z0-9-]{1,32}(?::[a-z0-9_.-]{1,64})*:(?:[a-z0-9_.-]{1,64}|\*)$/;
var TIME = /^(?:[01]\d|2[0-3]):[0-5]\d$|^24:00$/;
var DEVICE_LOCATION_MAX_AGE = 300;
var LIMITS = Object.freeze({ grants: 32, actions: 64, resources: 64, windows: 16, places: 64, networks: 64, resourceLength: 256 });
var isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
var minutes = (time) => Number(time.slice(0, 2)) * 60 + Number(time.slice(3));
function validTimeZone(tz) {
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: tz });
    return typeof tz === "string" && tz.length > 0;
  } catch {
    return false;
  }
}
function parseIp(ip) {
  if (typeof ip !== "string") return null;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) {
    const parts = ip.split(".").map(Number);
    if (parts.some((p) => p > 255)) return null;
    return { bits: 32, value: parts.reduce((acc, p) => (acc << 8n) + BigInt(p), 0n) };
  }
  if (!/^[0-9a-fA-F:.]+$/.test(ip) || !ip.includes(":")) return null;
  let address = ip;
  const v4 = address.match(/(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (v4) {
    const parsed = parseIp(v4[1]);
    if (!parsed) return null;
    address = address.slice(0, -v4[1].length) + (parsed.value >> 16n).toString(16) + ":" + (parsed.value & 0xffffn).toString(16);
  }
  const halves = address.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 1 && missing !== 0 || missing < 0) return null;
  const groups = [...head, ...Array(halves.length === 2 ? missing : 0).fill("0"), ...tail];
  if (groups.length !== 8 || groups.some((g) => !/^[0-9a-fA-F]{1,4}$/.test(g))) return null;
  return { bits: 128, value: groups.reduce((acc, g) => (acc << 16n) + BigInt(parseInt(g, 16)), 0n) };
}
function parseCidr(cidr) {
  if (typeof cidr !== "string") return null;
  const [ip, prefixText, extra] = cidr.split("/");
  if (extra !== void 0 || prefixText === void 0 || !/^\d{1,3}$/.test(prefixText)) return null;
  const parsed = parseIp(ip);
  const prefix = Number(prefixText);
  if (!parsed || prefix > parsed.bits) return null;
  return { ...parsed, prefix };
}
function ipInCidr(ip, cidr) {
  const address = parseIp(ip);
  const range = parseCidr(cidr);
  if (!address || !range || address.bits !== range.bits) return false;
  const shift = BigInt(range.bits - range.prefix);
  return address.value >> shift === range.value >> shift;
}
function distanceMeters(a, b) {
  const rad = (d) => d * Math.PI / 180;
  const R = 63710088e-1;
  const dLat = rad(b.lat - a.lat);
  const dLon = rad(b.lon - a.lon);
  const h = Math.sin(dLat / 2) ** 2 + Math.cos(rad(a.lat)) * Math.cos(rad(b.lat)) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.min(1, Math.sqrt(h)));
}
function actionMatches(pattern, action) {
  if (pattern === action) return true;
  return pattern.endsWith(":*") && action.startsWith(pattern.slice(0, -1));
}
function resourceMatches(pattern, resource) {
  if (pattern === "*") return true;
  if (typeof resource !== "string") return false;
  if (pattern.endsWith("*")) return resource.startsWith(pattern.slice(0, -1));
  return pattern === resource;
}
function checkKeys(value, allowed, path, errors) {
  if (!isObject(value)) {
    errors.push(`${path} must be an object`);
    return false;
  }
  for (const key of Object.keys(value)) if (!allowed.has(key)) errors.push(`${path}.${key} is not a known constraint`);
  return true;
}
function checkStringList(value, path, errors, max, test, message) {
  if (!Array.isArray(value) || value.length === 0 || value.length > max) {
    errors.push(`${path} must be a list of 1\u2013${max} entries`);
    return;
  }
  value.forEach((item, i) => {
    if (typeof item !== "string" || !test(item)) errors.push(`${path}[${i}] ${message}`);
  });
}
function validateGrant(grant, path = "grant") {
  const errors = [];
  if (!checkKeys(grant, GRANT_KEYS, path, errors)) return errors;
  checkStringList(grant.actions, `${path}.actions`, errors, LIMITS.actions, (a) => ACTION.test(a), 'must look like "namespace:verb" or "namespace:*"');
  if (grant.resources !== void 0) checkStringList(grant.resources, `${path}.resources`, errors, LIMITS.resources, (r) => r.length > 0 && r.length <= LIMITS.resourceLength, `must be 1\u2013${LIMITS.resourceLength} characters`);
  if (grant.when !== void 0 && checkKeys(grant.when, WHEN_KEYS, `${path}.when`, errors)) {
    const { tz, windows, not_before: nb, not_after: na } = grant.when;
    if (windows !== void 0) {
      if (!validTimeZone(tz)) errors.push(`${path}.when.tz must be an IANA time zone when windows are given`);
      if (!Array.isArray(windows) || windows.length === 0 || windows.length > LIMITS.windows) errors.push(`${path}.when.windows must be a list of 1\u2013${LIMITS.windows} windows`);
      else windows.forEach((w, i) => {
        const wp = `${path}.when.windows[${i}]`;
        if (!checkKeys(w, WINDOW_KEYS, wp, errors)) return;
        if (w.days !== void 0 && (!Array.isArray(w.days) || w.days.length === 0 || w.days.some((d) => !DAYS.includes(d)))) errors.push(`${wp}.days must list days from ${DAYS.join(", ")}`);
        if (typeof w.from !== "string" || !TIME.test(w.from) || w.from === "24:00") errors.push(`${wp}.from must be HH:MM (00:00\u201323:59)`);
        if (typeof w.to !== "string" || !TIME.test(w.to)) errors.push(`${wp}.to must be HH:MM (00:00\u201324:00)`);
        if (w.from === w.to) errors.push(`${wp} from and to must differ`);
      });
    } else if (tz !== void 0 && !validTimeZone(tz)) errors.push(`${path}.when.tz must be an IANA time zone`);
    for (const [k, v] of [["not_before", nb], ["not_after", na]]) if (v !== void 0 && !Number.isSafeInteger(v)) errors.push(`${path}.when.${k} must be a NumericDate (seconds)`);
    if (Number.isSafeInteger(nb) && Number.isSafeInteger(na) && nb >= na) errors.push(`${path}.when.not_before must be earlier than not_after`);
  }
  if (grant.where !== void 0 && checkKeys(grant.where, WHERE_KEYS, `${path}.where`, errors)) {
    const w = grant.where;
    if (!["network", "device", "both"].includes(w.source)) errors.push(`${path}.where.source must be "network", "device" or "both"`);
    if (w.countries !== void 0) checkStringList(w.countries, `${path}.where.countries`, errors, LIMITS.places, (c) => /^[A-Z]{2}$/.test(c), 'must be an ISO 3166-1 alpha-2 code like "US"');
    if (w.regions !== void 0) checkStringList(w.regions, `${path}.where.regions`, errors, LIMITS.places, (r) => /^[A-Z]{2}-[A-Z0-9]{1,3}$/.test(r), 'must be an ISO 3166-2 code like "US-MO"');
    if (w.areas !== void 0) {
      if (!Array.isArray(w.areas) || w.areas.length === 0 || w.areas.length > LIMITS.places) errors.push(`${path}.where.areas must be a list of 1\u2013${LIMITS.places} areas`);
      else w.areas.forEach((a, i) => {
        const ap = `${path}.where.areas[${i}]`;
        if (!checkKeys(a, AREA_KEYS, ap, errors)) return;
        if (!(Number.isFinite(a.lat) && a.lat >= -90 && a.lat <= 90)) errors.push(`${ap}.lat must be between -90 and 90`);
        if (!(Number.isFinite(a.lon) && a.lon >= -180 && a.lon <= 180)) errors.push(`${ap}.lon must be between -180 and 180`);
        if (!(Number.isFinite(a.radius_m) && a.radius_m >= 10 && a.radius_m <= 20037508)) errors.push(`${ap}.radius_m must be between 10 and 20,037,508`);
      });
    }
    if (w.networks !== void 0) checkStringList(w.networks, `${path}.where.networks`, errors, LIMITS.networks, (n) => !!parseCidr(n), 'must be a CIDR range like "203.0.113.0/24"');
    if (w.countries === void 0 && w.regions === void 0 && w.areas === void 0 && w.networks === void 0) errors.push(`${path}.where needs at least one of countries, regions, areas or networks`);
    if (w.source === "device" && (w.countries || w.regions || w.networks)) errors.push(`${path}.where with source "device" can only use areas (a device reports coordinates, not countries or networks)`);
  }
  if (grant.limits !== void 0 && checkKeys(grant.limits, LIMIT_KEYS, `${path}.limits`, errors)) {
    const { uses, spend_usd_per_month: spend } = grant.limits;
    if (uses !== void 0 && checkKeys(uses, USES_KEYS, `${path}.limits.uses`, errors)) {
      if (!Number.isSafeInteger(uses.count) || uses.count < 1 || uses.count > 1e9) errors.push(`${path}.limits.uses.count must be an integer from 1 to 1,000,000,000`);
      if (!USE_PERIODS.includes(uses.per)) errors.push(`${path}.limits.uses.per must be one of ${USE_PERIODS.join(", ")}`);
    }
    if (spend !== void 0 && !(Number.isFinite(spend) && spend >= 0 && spend <= 1e6)) errors.push(`${path}.limits.spend_usd_per_month must be a number from 0 to 1,000,000`);
  }
  if (grant.require !== void 0 && checkKeys(grant.require, REQUIRE_KEYS, `${path}.require`, errors)) {
    for (const key of ["online", "step_up", "verified_boot"]) if (grant.require[key] !== void 0 && typeof grant.require[key] !== "boolean") errors.push(`${path}.require.${key} must be true or false`);
    if (grant.require.attestation !== void 0 && (typeof grant.require.attestation !== "string" || !Object.hasOwn(ATTESTATION_LEVELS, grant.require.attestation))) errors.push(`${path}.require.attestation must be "hardware" or "strongbox"`);
  }
  return errors;
}
function localTime(nowSeconds, tz) {
  const parts = Object.fromEntries(new Intl.DateTimeFormat("en-US", { timeZone: tz, weekday: "short", hour: "2-digit", minute: "2-digit", hourCycle: "h23" }).formatToParts(new Date(nowSeconds * 1e3)).map((p) => [p.type, p.value]));
  return { day: DAYS.indexOf(parts.weekday.toLowerCase().slice(0, 3)), minutes: Number(parts.hour) * 60 + Number(parts.minute) };
}
function inWindow(window2, local) {
  const days = window2.days || DAYS;
  const from = minutes(window2.from);
  const to = window2.to === "24:00" ? 1440 : minutes(window2.to);
  const today = DAYS[local.day];
  const yesterday = DAYS[(local.day + 6) % 7];
  if (from < to) return days.includes(today) && local.minutes >= from && local.minutes < to;
  return days.includes(today) && local.minutes >= from || days.includes(yesterday) && local.minutes < to;
}
function placeMatches(where, loc, kind) {
  if (kind === "network") {
    if (where.countries?.includes(loc.country)) return true;
    if (where.regions?.includes(loc.region)) return true;
  }
  if (where.areas && Number.isFinite(loc.lat) && Number.isFinite(loc.lon)) {
    const slack = kind === "device" ? Number.isFinite(loc.acc_m) ? loc.acc_m : Infinity : 0;
    return where.areas.some((area) => distanceMeters(area, loc) + slack <= area.radius_m);
  }
  return false;
}
function checkSource(where, loc, kind, now, reasons) {
  if (!loc) {
    reasons.push(`location_unavailable:${kind}`);
    return;
  }
  if (kind === "device" && !(Number.isFinite(loc.t) && Math.abs(now - loc.t) <= DEVICE_LOCATION_MAX_AGE)) {
    reasons.push("location_stale:device");
    return;
  }
  const places = where.countries || where.regions || where.areas;
  if (places && !placeMatches(where, loc, kind)) reasons.push(`outside_location:${kind}`);
  if (kind === "network" && where.networks && !where.networks.some((n) => ipInCidr(loc.ip, n))) reasons.push("network_not_allowed");
}
function evaluateGrant(grant, context) {
  const reasons = [];
  const online = {};
  const unknown = !isObject(grant) ? ["grant"] : [
    ...Object.keys(grant).filter((k) => !GRANT_KEYS.has(k)),
    ...isObject(grant.when) ? Object.keys(grant.when).filter((k) => !WHEN_KEYS.has(k)).map((k) => `when.${k}`) : [],
    ...isObject(grant.where) ? Object.keys(grant.where).filter((k) => !WHERE_KEYS.has(k)).map((k) => `where.${k}`) : [],
    ...isObject(grant.limits) ? Object.keys(grant.limits).filter((k) => !LIMIT_KEYS.has(k)).map((k) => `limits.${k}`) : [],
    ...isObject(grant.require) ? Object.keys(grant.require).filter((k) => !REQUIRE_KEYS.has(k)).map((k) => `require.${k}`) : []
  ];
  if (unknown.length) return { ok: false, reasons: unknown.map((k) => `unknown_constraint:${k}`), online };
  if (validateGrant(grant).length) return { ok: false, reasons: ["invalid_grant"], online };
  const now = context.now;
  if (!grant.actions.some((p) => actionMatches(p, context.action))) reasons.push("action_not_granted");
  if (!(grant.resources || ["*"]).some((p) => resourceMatches(p, context.resource))) reasons.push("resource_not_granted");
  const when = grant.when;
  if (when) {
    if (when.not_before !== void 0 && now < when.not_before) reasons.push("before_not_before");
    if (when.not_after !== void 0 && now >= when.not_after) reasons.push("after_not_after");
    if (when.windows) {
      const local = localTime(now, when.tz);
      if (!when.windows.some((w) => inWindow(w, local))) reasons.push("outside_time_window");
    }
  }
  const where = grant.where;
  if (where) {
    const location2 = context.location || {};
    if (where.source === "network" || where.source === "both") checkSource(where, location2.network, "network", now, reasons);
    if (where.source === "device" || where.source === "both") checkSource(where, location2.device, "device", now, reasons);
  }
  const attestation = context.attestation;
  if (grant.require?.attestation !== void 0 && !(isObject(attestation) && ATTESTATION_LEVELS[grant.require.attestation].includes(attestation.security_level))) reasons.push("attestation_required");
  if (grant.require?.verified_boot && !(isObject(attestation) && attestation.verified_boot === "verified" && attestation.device_locked === true)) reasons.push("verified_boot_required");
  if (grant.limits?.uses) online.uses = grant.limits.uses;
  if (grant.require?.step_up) online.step_up = true;
  if (grant.require?.online) online.required = true;
  if (!reasons.length && Object.keys(online).length && !context.online) reasons.push("online_required");
  return { ok: reasons.length === 0, reasons, online };
}
function evaluateGrants(grants, context) {
  if (!Array.isArray(grants)) return { allow: false, grant_index: null, reasons: [["invalid_grants"]], online_required: false };
  const results = grants.map((g) => evaluateGrant(g, context));
  const index = results.findIndex((r) => r.ok);
  const onlineRequired = index < 0 && results.some((r) => r.reasons.length === 1 && r.reasons[0] === "online_required");
  return {
    allow: index >= 0,
    grant_index: index >= 0 ? index : null,
    grant: index >= 0 ? grants[index] : null,
    online: index >= 0 ? results[index].online : {},
    caveats: index >= 0 && grants[index].limits?.spend_usd_per_month !== void 0 ? { spend_usd_per_month: grants[index].limits.spend_usd_per_month } : {},
    reasons: results.map((r) => r.reasons),
    online_required: onlineRequired,
    results
  };
}
var DAY_NAMES = { sun: "Sunday", mon: "Monday", tue: "Tuesday", wed: "Wednesday", thu: "Thursday", fri: "Friday", sat: "Saturday" };
function list(items, joiner = "or") {
  if (items.length <= 1) return items.join("");
  return `${items.slice(0, -1).join(", ")} ${joiner} ${items.at(-1)}`;
}
function describeDays(days) {
  if (!days || days.length === 7) return "every day";
  const key = DAYS.filter((d) => days.includes(d)).join(",");
  if (key === "mon,tue,wed,thu,fri") return "weekdays";
  if (key === "sun,sat") return "weekends";
  return list(DAYS.filter((d) => days.includes(d)).map((d) => DAY_NAMES[d]));
}
var iso = (seconds) => new Date(seconds * 1e3).toISOString().replace(".000Z", "Z");
function describeGrant(grant) {
  if (!isObject(grant) || !Array.isArray(grant.actions)) return "An invalid grant (it allows nothing).";
  const parts = [`May ${list(grant.actions.map((a) => `"${a}"`))}`];
  const resources = grant.resources || ["*"];
  parts.push(resources.length === 1 && resources[0] === "*" ? "on any resource" : `on ${list(resources.map((r) => r.endsWith("*") ? `resources starting with "${r.slice(0, -1)}"` : `"${r}"`))}`);
  const when = grant.when;
  if (when?.windows) parts.push(`${list(when.windows.map((w) => `${describeDays(w.days)} ${w.from}\u2013${w.to}`))} (${when.tz} time)`);
  if (when?.not_before !== void 0) parts.push(`from ${iso(when.not_before)}`);
  if (when?.not_after !== void 0) parts.push(`until ${iso(when.not_after)}`);
  const where = grant.where;
  if (where) {
    const places = [...where.countries || [], ...where.regions || [], ...(where.areas || []).map((a) => `within ${a.radius_m >= 1e3 ? `${+(a.radius_m / 1e3).toFixed(1)} km` : `${a.radius_m} m`} of ${a.lat},${a.lon}`)];
    const source = { network: "as seen from its network connection", device: "as reported by the device", both: "both as seen from its network and as reported by the device" }[where.source] || "";
    if (places.length) parts.push(`only from ${list(places)} (${source})`);
    if (where.networks) parts.push(`only from network ${list(where.networks)}`);
  }
  const uses = grant.limits?.uses;
  if (uses) parts.push(uses.per === "total" ? `at most ${uses.count} time${uses.count === 1 ? "" : "s"} in total` : `at most ${uses.count} time${uses.count === 1 ? "" : "s"} per ${uses.per}`);
  if (grant.limits?.spend_usd_per_month !== void 0) parts.push(`spending at most $${grant.limits.spend_usd_per_month.toFixed(2)} per month`);
  if (grant.require?.attestation === "strongbox") parts.push("only with a key attested to be in a StrongBox secure element");
  else if (grant.require?.attestation === "hardware") parts.push("only with a key attested to be in secure hardware");
  if (grant.require?.verified_boot) parts.push("only from a device attested to have verified boot and a locked bootloader");
  if (grant.require?.step_up) parts.push("with the owner approving each use");
  if (grant.require?.online) parts.push("checked online with devicebasedauth.org every time");
  return `${parts.join(", ")}.`;
}

// packages/verify/src/credential.js
var PROOF_TYP = "dpop+jwt";
var MAX_STATUS_INDEX = 2 ** 31 - 1;
function inspectCredential(jws) {
  const { header, payload } = decodeJws(jws);
  return { header, payload };
}
function htu(url) {
  const u = new URL(url);
  return `${u.protocol}//${u.host}${u.pathname}`;
}
async function createProof({ privateKey, publicJwk: jwk, method, url, credential, nonce, location: location2, now = Math.floor(Date.now() / 1e3), jti }) {
  const payload = { jti: jti || b64u(crypto.getRandomValues(new Uint8Array(16))), htm: method.toUpperCase(), htu: htu(url), iat: now };
  if (credential) payload.ath = await sha256b64u(credential);
  if (nonce) payload.nonce = nonce;
  if (location2) payload.loc = location2;
  return signJws({ typ: PROOF_TYP, jwk: publicJwk(jwk) }, payload, privateKey);
}

// packages/browser-sdk/dba.js
var VERSION = "1.1.0";
var DB = "devicebasedauth";
var STORE = "devices";
function openDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}
async function idb(mode, fn) {
  const db = await openDb();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, mode);
      const request = fn(tx.objectStore(STORE));
      tx.oncomplete = () => resolve(request?.result);
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}
var DBAError = class extends Error {
  constructor(message, code, details = {}) {
    super(message);
    this.code = code;
    Object.assign(this, details);
  }
};
var MAX_TIMER_MS = 2 ** 31 - 1;
var DBA = class {
  /**
   * @param {object} [options]
   * @param {string} [options.origin] devicebasedauth.org origin (default https://devicebasedauth.org)
   * @param {string} [options.name] slot name, so one page can hold several device identities
   */
  constructor({ origin = "https://devicebasedauth.org", name = "default" } = {}) {
    this.origin = origin.replace(/\/$/, "");
    this.name = `${this.origin}#${name}`;
    this.state = null;
    this.renewTimer = null;
  }
  /** Load the stored key and credential. Returns true when a usable (unexpired) credential exists. */
  async ready() {
    this.state = await idb("readonly", (store) => store.get(this.name)) || null;
    return !!this.credential && this.expiresIn() > 0;
  }
  async save() {
    await idb("readwrite", (store) => store.put(this.state, this.name));
  }
  /** The current credential (compact JWS) or null. */
  get credential() {
    return this.state?.credential || null;
  }
  /** The decoded credential payload (not verified — use for display and local checks only). */
  get payload() {
    return this.credential ? inspectCredential(this.credential).payload : null;
  }
  /** Seconds until the credential expires (0 when none). */
  expiresIn() {
    const p = this.payload;
    return p ? Math.max(0, p.exp - Math.floor(Date.now() / 1e3)) : 0;
  }
  /** Plain-English descriptions of each grant. */
  describe() {
    return (this.payload?.grants || []).map(describeGrant);
  }
  /**
   * Would the credential allow this action right now (time, location and action checks only)?
   * A hint for UI; servers still decide, and only they know about revocation.
   */
  allows(action, { resource, location: location2 } = {}) {
    const p = this.payload;
    if (!p || this.expiresIn() <= 0) return false;
    return evaluateGrants(p.grants, { now: Math.floor(Date.now() / 1e3), action, resource, location: location2, online: false, attestation: p.device?.attestation }).allow;
  }
  async key() {
    if (!this.state?.privateKey) {
      const pair = await generateKeyPair(false);
      this.state = { privateKey: pair.privateKey, publicJwk: await exportPublicJwk(pair.publicKey), credential: null, created_at: Date.now() };
      await this.save();
    }
    return this.state;
  }
  async api(path, { method = "GET", body, auth = false } = {}) {
    const url = `${this.origin}${path}`;
    const headers = { ...body ? { "Content-Type": "application/json" } : {}, ...auth ? await this.headers(method, url) : {} };
    const response = await fetch(url, { method, headers, body: body ? JSON.stringify(body) : void 0 });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new DBAError(data.error || `HTTP ${response.status}`, data.code || "http_error", { status: response.status, details: data });
    return data;
  }
  /**
   * Ask the account owner to approve this device. Opens the approval page in a popup (call from a
   * click handler so it is not blocked) and resolves with the credential.
   * @param {object} request { aud: string[], grants: object[], device?: {name, kind}, lifetime_seconds? }
   * @param {object} [options] { popup: true, onApprovalUrl(url), timeoutMs, enrollmentToken }
   *   enrollmentToken: a dbae_… token the owner created (kiosks, fleets); the credential is issued
   *   at once without a popup, and aud/grants may be left out to take the token's.
   */
  async enroll(request, { popup = true, onApprovalUrl, timeoutMs = 15 * 6e4, enrollmentToken } = {}) {
    const { privateKey, publicJwk: publicJwk2 } = await this.key();
    const device = { name: defaultDeviceName(), kind: "browser", ...request.device, key_protection: "webcrypto-nonextractable" };
    const signed = await signJws({ typ: "dba-enroll+jwt", jwk: publicJwk2 }, { iat: Math.floor(Date.now() / 1e3), ...request.aud ? { aud: request.aud } : {}, ...request.grants ? { grants: request.grants } : {}, device, ...request.lifetime_seconds ? { lifetime_seconds: request.lifetime_seconds } : {}, return_origin: location.origin }, privateKey);
    if (enrollmentToken) {
      const issued = await this.api("/api/v1/enrollments/redeem", { method: "POST", body: { request: signed, enrollment_token: enrollmentToken } });
      this.state.credential = issued.credential;
      await this.save();
      return issued.credential;
    }
    const started = await this.api("/api/v1/enrollments", { method: "POST", body: { request: signed } });
    const win = popup ? window.open(started.approval_url, "devicebasedauth-approve", "popup,width=520,height=760") : null;
    if (!win && onApprovalUrl) onApprovalUrl(started.approval_url);
    else if (!win && popup) throw new DBAError("The approval popup was blocked; call enroll() from a click handler or pass onApprovalUrl", "popup_blocked", { approval_url: started.approval_url });
    const result = await new Promise((resolve, reject) => {
      const deadline = Date.now() + timeoutMs;
      let done = false;
      const finish = (fn, value) => {
        if (done) return;
        done = true;
        window.removeEventListener("message", onMessage);
        fn(value);
      };
      const onMessage = (event) => {
        if (event.origin !== this.origin || event.data?.source !== "devicebasedauth" || event.data.enrollment_id !== started.enrollment_id) return;
        if (event.data.status === "approved") finish(resolve, event.data);
        else finish(reject, new DBAError("The owner did not approve this device", "denied"));
      };
      window.addEventListener("message", onMessage);
      const poll = async () => {
        if (done) return;
        if (Date.now() > deadline) return finish(reject, new DBAError("Enrollment timed out", "expired"));
        try {
          const state = await fetch(started.poll_url).then((r) => r.json());
          if (state.status === "approved") return finish(resolve, state);
          if (state.status === "denied" || state.status === "expired") return finish(reject, new DBAError(`Enrollment ${state.status}`, state.status));
        } catch {
        }
        setTimeout(poll, (started.interval || 3) * 1e3);
      };
      setTimeout(poll, (started.interval || 3) * 1e3);
    });
    this.state.credential = result.credential;
    await this.save();
    return result.credential;
  }
  /** Headers for one request: Authorization: DBA <credential> and a fresh DPoP proof. */
  async headers(method, url, { location: loc } = {}) {
    if (!this.credential) throw new DBAError("No credential; call enroll() first", "no_credential");
    const proof = await createProof({ privateKey: this.state.privateKey, publicJwk: this.state.publicJwk, method, url: new URL(url, location.href).href, credential: this.credential, location: loc });
    return { Authorization: `DBA ${this.credential}`, DPoP: proof };
  }
  /** fetch() with the credential and a proof attached. */
  async fetch(input, init = {}) {
    const request = new Request(input, init);
    const headers = new Headers(request.headers);
    for (const [k, v] of Object.entries(await this.headers(request.method, request.url, init.dba || {}))) headers.set(k, v);
    return fetch(new Request(request, { headers }));
  }
  /** Renew before expiry (same key), or rotate to a fresh non-extractable key. */
  async renew({ rotate = false } = {}) {
    const p = this.payload;
    if (!p) throw new DBAError("No credential to renew", "no_credential");
    const path = `/api/v1/credentials/${p.cid}/renew`;
    const body = {};
    let next = null;
    if (rotate) {
      const pair = await generateKeyPair(false);
      const jwk = await exportPublicJwk(pair.publicKey);
      body.new_key_proof = await signJws({ typ: "dba-rotate+jwt", jwk }, { cid: p.cid, iat: Math.floor(Date.now() / 1e3) }, pair.privateKey);
      next = { privateKey: pair.privateKey, publicJwk: jwk };
    }
    const result = await this.api(path, { method: "POST", body, auth: true });
    this.state = { ...this.state, ...next || {}, credential: result.credential };
    await this.save();
    return result;
  }
  /**
   * Renew automatically at two thirds of the credential's lifetime while the page is open, and at
   * once (free) if the issuer has withdrawn the key that signed it.
   */
  autoRenew({ onError } = {}) {
    clearTimeout(this.renewTimer);
    const p = this.payload;
    if (!p) return;
    const run = () => this.renew().then(() => this.autoRenew({ onError }), onError || (() => {
    }));
    const at = (p.iat + (p.exp - p.iat) * 2 / 3) * 1e3 - Date.now();
    this.renewTimer = at > MAX_TIMER_MS ? setTimeout(() => this.autoRenew({ onError }), MAX_TIMER_MS) : setTimeout(run, Math.max(0, at));
    const { kid } = inspectCredential(this.credential).header;
    this.checkedKids ||= /* @__PURE__ */ new Set();
    if (at > 0 && !this.checkedKids.has(kid)) {
      this.checkedKids.add(kid);
      const credential = this.credential;
      this.keyWithdrawn().then((withdrawn) => {
        if (withdrawn && this.credential === credential) {
          clearTimeout(this.renewTimer);
          run();
        }
      }, () => {
      });
    }
  }
  /**
   * True when the issuer's JWKS no longer lists the key that signed this credential (the key was
   * withdrawn after a compromise). Relying parties then refuse the credential; renew() replaces it
   * at no charge. False when there is no credential or the JWKS cannot be fetched.
   */
  async keyWithdrawn() {
    if (!this.credential) return false;
    const { header } = inspectCredential(this.credential);
    const response = await fetch(`${this.origin}/.well-known/jwks.json`, { cache: "no-cache" }).catch(() => null);
    const keys = response?.ok ? (await response.json().catch(() => ({}))).keys : null;
    return Array.isArray(keys) && keys.length > 0 && !keys.some((k) => k.kid === header.kid);
  }
  /** A short-lived bearer token for one audience (for code that cannot sign each request). */
  async token(audience) {
    return (await this.api("/api/v1/token", { method: "POST", body: { audience }, auth: true })).access_token;
  }
  /** Revoke this device's credential everywhere and forget the key. */
  async revoke() {
    if (this.credential) await this.api("/api/v1/self/revoke", { method: "POST", auth: true });
    await this.forget();
  }
  /** Delete the key and credential from this browser (does not revoke). */
  async forget() {
    clearTimeout(this.renewTimer);
    this.state = null;
    await idb("readwrite", (store) => store.delete(this.name));
  }
  /** Decode any credential for display (no verification). */
  static inspect(jws) {
    return inspectCredential(jws);
  }
};
function defaultDeviceName() {
  const ua = navigator.userAgent;
  const browser = /Edg\//.test(ua) ? "Edge" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "Browser";
  const os = /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iOS" : /Mac OS X/.test(ua) ? "macOS" : /Windows/.test(ua) ? "Windows" : /Linux/.test(ua) ? "Linux" : "";
  return `${browser}${os ? ` on ${os}` : ""} (${location.host})`;
}
export {
  DBA,
  DBAError,
  VERSION,
  describeGrant
};
