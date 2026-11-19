/** Helpers shared by the developer tools. */

/** IANA time zones known to this browser (UTC first). */
export function timeZones() {
  let zones = [];
  try { zones = Intl.supportedValuesOf('timeZone'); } catch { zones = ['America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles', 'Europe/London', 'Europe/Berlin', 'Asia/Tokyo', 'Australia/Sydney']; }
  return ['UTC', ...zones.filter(z => z !== 'UTC')];
}

/** The browser's own time zone. */
export function localZone() { try { return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'; } catch { return 'UTC'; } }

/** Offset of a zone from UTC at an instant, in milliseconds. */
function offset(ms, tz) {
  const parts = Object.fromEntries(new Intl.DateTimeFormat('en-US', { timeZone: tz, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' })
    .formatToParts(new Date(ms)).map(p => [p.type, p.value]));
  return Date.UTC(+parts.year, +parts.month - 1, +parts.day, +parts.hour, +parts.minute, +parts.second) - Math.floor(ms / 1000) * 1000;
}

/**
 * Seconds since the epoch for a wall-clock time ("YYYY-MM-DDTHH:MM", as from datetime-local)
 * in an IANA zone. Corrects once for a DST change between the guess and the answer.
 */
export function zonedToEpoch(local, tz) {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/.exec(local || '');
  if (!match) return null;
  const [, Y, M, D, hh, mm] = match.map(Number);
  const wall = Date.UTC(Y, M - 1, D, hh, mm);
  let guess = wall - offset(wall, tz);
  guess = wall - offset(guess, tz);
  return Math.floor(guess / 1000);
}

/** "YYYY-MM-DDTHH:MM" for an instant in a zone (for datetime-local inputs). */
export function epochToZoned(seconds, tz) {
  const parts = Object.fromEntries(new Intl.DateTimeFormat('en-US', { timeZone: tz, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
    .formatToParts(new Date(seconds * 1000)).map(p => [p.type, p.value]));
  return `${parts.year}-${parts.month}-${parts.day}T${parts.hour}:${parts.minute}`;
}

/** "Wednesday 10:00" in a zone. */
export function describeInstant(seconds, tz) {
  return new Intl.DateTimeFormat('en-US', { timeZone: tz, weekday: 'long', year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hourCycle: 'h23', timeZoneName: 'short' }).format(new Date(seconds * 1000));
}

/** Plain-English meaning of each evaluation reason code (spec/evaluation.md). */
export function explainReason(code) {
  const [base, detail] = code.split(':');
  const source = detail === 'device' ? 'the device-reported location' : 'the network location';
  return ({
    action_not_granted: 'The action is not in this grant.',
    resource_not_granted: 'The resource is not covered by this grant.',
    before_not_before: 'Too early: the grant\'s not_before is later.',
    after_not_after: 'Too late: the grant\'s not_after has passed.',
    outside_time_window: 'Outside every time window, in the grant\'s time zone.',
    location_unavailable: `No ${source} was available.`,
    location_stale: 'The device location is more than 5 minutes old.',
    outside_location: `${source[0].toUpperCase()}${source.slice(1)} is outside every allowed country, region and area.`,
    network_not_allowed: 'The IP address is outside every allowed network.',
    online_required: 'Usage limits, step-up, gates or require.online: only devicebasedauth.org can decide this (online authorization).',
    confirmation_required: 'The credential needs a current confirmation (DBA-Confirmation) and the device sent none.',
    confirmation_expired: 'The device\'s confirmation has run out: its gates must confirm it again.',
    confirmation_by_timeout_refused: 'The confirmation passed only because nobody answered, and this action\'s policy refuses that.',
    gate_required: 'The site requires gates for this action and the grant names none (of an accepted kind).',
    unknown_constraint: `Unknown constraint "${code.slice(19)}": fails closed.`,
    invalid_grant: 'The grant is invalid, so it allows nothing.',
    invalid_grants: 'The grants are not a list.'
  })[base] || code;
}

/** Read "a, b" into a list, or undefined when empty. */
export function listOrUndefined(text) {
  const items = String(text || '').split(/[\n,]+/).map(s => s.trim()).filter(Boolean);
  return items.length ? items : undefined;
}

/** A finite number from an input, or undefined when empty. */
export function numberOrUndefined(text) {
  if (String(text ?? '').trim() === '') return undefined;
  const n = Number(text);
  return Number.isFinite(n) ? n : undefined;
}
