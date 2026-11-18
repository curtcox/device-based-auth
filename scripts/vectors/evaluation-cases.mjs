// Hand-written conformance cases. Expectations are stated here, never computed from the
// implementation, so the vectors test the evaluator instead of echoing it.
const t = iso => Math.floor(Date.parse(iso) / 1000);
const W = ['hashbin:content:write'];
const WED_1500Z = t('2026-11-18T15:00:00Z'); // Wednesday 09:00 in America/Chicago (CST, UTC-6)
const ctx = (extra = {}) => ({ now: WED_1500Z, action: 'hashbin:content:write', resource: 'doc-1', ...extra });
const stl = { lat: 38.627, lon: -90.199 };
const area = { lat: stl.lat, lon: stl.lon, radius_m: 50000 };

export const cases = [
  ['empty grant list denies', [], ctx(), false, null, []],
  ['exact action allows', [{ actions: W }], ctx(), true, 0, [[]]],
  ['other action denies', [{ actions: ['hashbin:uploads:read'] }], ctx(), false, null, [['action_not_granted']]],
  ['namespace wildcard allows', [{ actions: ['hashbin:*'] }], ctx(), true, 0, [[]]],
  ['sub-namespace wildcard allows', [{ actions: ['hashbin:content:*'] }], ctx(), true, 0, [[]]],
  ['wildcard does not cross namespaces', [{ actions: ['hash:*'] }], ctx(), false, null, [['action_not_granted']]],
  ['wildcard needs a segment boundary', [{ actions: ['hashbin:cont:*'] }], ctx(), false, null, [['action_not_granted']]],
  ['resource exact match', [{ actions: W, resources: ['doc-1'] }], ctx(), true, 0, [[]]],
  ['resource prefix match', [{ actions: W, resources: ['doc-*'] }], ctx(), true, 0, [[]]],
  ['resource mismatch denies', [{ actions: W, resources: ['doc-2'] }], ctx(), false, null, [['resource_not_granted']]],
  ['missing resource only matches *', [{ actions: W, resources: ['doc-*'] }], ctx({ resource: undefined }), false, null, [['resource_not_granted']]],
  ['second grant allows', [{ actions: ['x:y'] }, { actions: W }], ctx(), true, 1, [['action_not_granted'], []]],
  ['inside weekday window (local time)', [{ actions: W, when: { tz: 'America/Chicago', windows: [{ days: ['mon', 'tue', 'wed', 'thu', 'fri'], from: '08:00', to: '18:00' }] } }], ctx(), true, 0, [[]]],
  ['window end is exclusive', [{ actions: W, when: { tz: 'America/Chicago', windows: [{ from: '08:00', to: '09:00' }] } }], ctx(), false, null, [['outside_time_window']]],
  ['window start is inclusive', [{ actions: W, when: { tz: 'America/Chicago', windows: [{ from: '09:00', to: '10:00' }] } }], ctx(), true, 0, [[]]],
  ['wrong day denies', [{ actions: W, when: { tz: 'America/Chicago', windows: [{ days: ['sat', 'sun'], from: '00:00', to: '24:00' }] } }], ctx(), false, null, [['outside_time_window']]],
  ['window evaluated in its own zone', [{ actions: W, when: { tz: 'UTC', windows: [{ from: '08:00', to: '09:00' }] } }], ctx(), false, null, [['outside_time_window']]],
  ['overnight window after midnight belongs to start day', [{ actions: W, when: { tz: 'UTC', windows: [{ days: ['tue'], from: '22:00', to: '06:00' }] } }], ctx({ now: t('2026-11-18T05:59:00Z') }), true, 0, [[]]],
  ['overnight window does not cover the next morning of a non-listed day', [{ actions: W, when: { tz: 'UTC', windows: [{ days: ['wed'], from: '22:00', to: '06:00' }] } }], ctx({ now: t('2026-11-18T05:59:00Z') }), false, null, [['outside_time_window']]],
  ['summer time shifts local hour (CDT)', [{ actions: W, when: { tz: 'America/Chicago', windows: [{ from: '10:00', to: '11:00' }] } }], ctx({ now: t('2026-07-15T15:30:00Z') }), true, 0, [[]]],
  ['not_before in the future denies', [{ actions: W, when: { not_before: WED_1500Z + 1 } }], ctx(), false, null, [['before_not_before']]],
  ['not_after is exclusive', [{ actions: W, when: { not_after: WED_1500Z } }], ctx(), false, null, [['after_not_after']]],
  ['network country allows', [{ actions: W, where: { source: 'network', countries: ['US'] } }], ctx({ location: { network: { country: 'US' } } }), true, 0, [[]]],
  ['network country denies', [{ actions: W, where: { source: 'network', countries: ['US'] } }], ctx({ location: { network: { country: 'CA' } } }), false, null, [['outside_location:network']]],
  ['places are a union', [{ actions: W, where: { source: 'network', countries: ['CA'], regions: ['US-MO'] } }], ctx({ location: { network: { country: 'US', region: 'US-MO' } } }), true, 0, [[]]],
  ['missing network location denies', [{ actions: W, where: { source: 'network', countries: ['US'] } }], ctx(), false, null, [['location_unavailable:network']]],
  ['network coordinates inside area', [{ actions: W, where: { source: 'network', areas: [area] } }], ctx({ location: { network: { lat: 38.7, lon: -90.3 } } }), true, 0, [[]]],
  ['network coordinates outside area', [{ actions: W, where: { source: 'network', areas: [area] } }], ctx({ location: { network: { lat: 41.88, lon: -87.63 } } }), false, null, [['outside_location:network']]],
  ['networks CIDR allows', [{ actions: W, where: { source: 'network', networks: ['203.0.113.0/24'] } }], ctx({ location: { network: { ip: '203.0.113.9' } } }), true, 0, [[]]],
  ['networks CIDR denies', [{ actions: W, where: { source: 'network', networks: ['203.0.113.0/24'] } }], ctx({ location: { network: { ip: '198.51.100.9' } } }), false, null, [['network_not_allowed']]],
  ['IPv6 network allows', [{ actions: W, where: { source: 'network', networks: ['2001:db8::/32'] } }], ctx({ location: { network: { ip: '2001:db8:1::5' } } }), true, 0, [[]]],
  ['country and network must both pass', [{ actions: W, where: { source: 'network', countries: ['US'], networks: ['10.0.0.0/8'] } }], ctx({ location: { network: { country: 'US', ip: '11.1.1.1' } } }), false, null, [['network_not_allowed']]],
  ['device area allows (distance + accuracy within radius)', [{ actions: W, where: { source: 'device', areas: [area] } }], ctx({ location: { device: { lat: 38.63, lon: -90.2, acc_m: 100, t: WED_1500Z - 10 } } }), true, 0, [[]]],
  ['device accuracy counts against the radius', [{ actions: W, where: { source: 'device', areas: [{ ...area, radius_m: 100 }] } }], ctx({ location: { device: { lat: stl.lat, lon: stl.lon, acc_m: 150, t: WED_1500Z } } }), false, null, [['outside_location:device']]],
  ['device location without accuracy never matches', [{ actions: W, where: { source: 'device', areas: [area] } }], ctx({ location: { device: { lat: stl.lat, lon: stl.lon, t: WED_1500Z } } }), false, null, [['outside_location:device']]],
  ['stale device location denies', [{ actions: W, where: { source: 'device', areas: [area] } }], ctx({ location: { device: { lat: stl.lat, lon: stl.lon, acc_m: 5, t: WED_1500Z - 301 } } }), false, null, [['location_stale:device']]],
  ['both sources required', [{ actions: W, where: { source: 'both', areas: [area] } }], ctx({ location: { network: { lat: 38.6, lon: -90.2 } } }), false, null, [['location_unavailable:device']]],
  ['usage limit requires online offline', [{ actions: W, limits: { uses: { count: 3, per: 'day' } } }], ctx(), false, null, [['online_required']]],
  ['usage limit allowed online (counter enforced by the service)', [{ actions: W, limits: { uses: { count: 3, per: 'day' } } }], ctx({ online: true }), true, 0, [[]]],
  ['step-up requires online', [{ actions: W, require: { step_up: true } }], ctx(), false, null, [['online_required']]],
  ['require.online false does not require online', [{ actions: W, require: { online: false } }], ctx(), true, 0, [[]]],
  ['spend cap is a caveat, not a check', [{ actions: W, limits: { spend_usd_per_month: 0 } }], ctx(), true, 0, [[]]],
  ['unknown grant key denies', [{ actions: W, after_dark: true }], ctx(), false, null, [['unknown_constraint:after_dark']]],
  ['unknown nested key denies', [{ actions: W, when: { tz: 'UTC', moon: 'full' } }], ctx(), false, null, [['unknown_constraint:when.moon']]],
  ['invalid grant denies', [{ actions: ['not an action'] }], ctx(), false, null, [['invalid_grant']]],
  ['window times must be strings, not lists', [{ actions: W, when: { tz: 'UTC', windows: [{ from: ['08:00'], to: '23:00' }] } }], ctx(), false, null, [['invalid_grant']]],
  ['all failing reasons are reported', [{ actions: ['x:y'], resources: ['other'] }], ctx(), false, null, [['action_not_granted', 'resource_not_granted']]]
].map(([name, grants, context, allow, grant_index, reasons]) => ({ name, grants, context, expected: { allow, grant_index, reasons } }));
