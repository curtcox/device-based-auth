// Hand-written conformance cases for the `net` constraint (spec/evaluation.md §3.10). As in
// evaluation-cases.mjs, expectations are stated here, never computed from the implementation.
const NOW = Math.floor(Date.parse('2026-11-18T15:00:00Z') / 1000);
const W = ['hashbin:content:write'];
const ctx = (extra = {}) => ({ now: NOW, action: W[0], resource: 'doc-1', ...extra });
const peer = (ip, more = {}) => ({ location: { network: { ip, ...more } } });
const net = client => [{ actions: W, net: { client } }];
const OFFICE = 'adl_OFFICE0001'; const VPN = 'adl_VPNEXIT01';
const list = id => ({ id, uri: `https://status.devicebasedauth.org/v1/addresses/${id}` });
const HOOK = 'gate_ADDRHOOK1';
const HQ = 'dev_RELAYHQ001'; const EDGE = 'dev_RELAYEDGE1'; const ROGUE = 'dev_ROGUE0001';
const route = (relays, origin = '10.1.2.3', extra = {}) => ({ route: { relays, origin, ...extra } });

export const netCases = [
  // Addresses: each source alone.
  ['net: inline CIDR allows the peer address', net({ addresses: { cidrs: ['203.0.113.0/24'] } }), ctx(peer('203.0.113.9')), true, 0, [[]]],
  ['net: inline CIDR denies another address', net({ addresses: { cidrs: ['203.0.113.0/24'] } }), ctx(peer('198.51.100.9')), false, null, [['address_not_allowed']]],
  ['net: an IPv4 range never matches an IPv6 peer', net({ addresses: { cidrs: ['0.0.0.0/0'] } }), ctx(peer('2001:db8::1')), false, null, [['address_not_allowed']]],
  ['net: no peer address denies', net({ addresses: { cidrs: ['203.0.113.0/24'] } }), ctx(), false, null, [['address_unavailable']]],
  ['net: a named list allows', net({ addresses: { lists: [list(OFFICE)] } }), ctx({ ...peer('192.0.2.77'), address_lists: { [OFFICE]: { cidrs: ['192.0.2.0/25'], ver: 4 } } }), true, 0, [[]]],
  ['net: a named list denies an address it does not hold', net({ addresses: { lists: [list(OFFICE)] } }), ctx({ ...peer('192.0.2.200'), address_lists: { [OFFICE]: { cidrs: ['192.0.2.0/25'], ver: 4 } } }), false, null, [['address_not_allowed']]],
  ['net: an unavailable list matches nothing', net({ addresses: { lists: [list(OFFICE)] } }), ctx({ ...peer('192.0.2.77'), address_lists: { [OFFICE]: 'unavailable' } }), false, null, [['address_not_allowed', `address_list_unavailable:${OFFICE}`]]],
  ['net: a list the verifier did not resolve is unavailable', net({ addresses: { lists: [list(OFFICE)] } }), ctx(peer('192.0.2.77')), false, null, [['address_not_allowed', `address_list_unavailable:${OFFICE}`]]],
  ['net: a DNS answer allows', net({ addresses: { dns: { names: ['vpn.example.com'] } } }), ctx({ ...peer('2001:db8:42::7'), dns: { 'vpn.example.com': { addrs: ['192.0.2.1', '2001:DB8:42:0::7'], dnssec: false } } }), true, 0, [[]]],
  ['net: an unresolved DNS name matches nothing', net({ addresses: { dns: { names: ['vpn.example.com'] } } }), ctx({ ...peer('192.0.2.1'), dns: { 'vpn.example.com': 'unresolved' } }), false, null, [['address_not_allowed', 'dns_unresolved:vpn.example.com']]],
  ['net: dnssec refuses an unvalidated answer', net({ addresses: { dns: { names: ['vpn.example.com'], dnssec: true } } }), ctx({ ...peer('192.0.2.1'), dns: { 'vpn.example.com': { addrs: ['192.0.2.1'], dnssec: false } } }), false, null, [['address_not_allowed', 'dns_unvalidated:vpn.example.com']]],
  ['net: dnssec accepts a validated answer', net({ addresses: { dns: { names: ['vpn.example.com'], dnssec: true } } }), ctx({ ...peer('192.0.2.1'), dns: { 'vpn.example.com': { addrs: ['192.0.2.1'], dnssec: true } } }), true, 0, [[]]],
  // Addresses: the sources form a union.
  ['net: sources are a union (the list allows)', net({ addresses: { cidrs: ['203.0.113.0/24'], lists: [list(OFFICE), list(VPN)] } }), ctx({ ...peer('192.0.2.5'), address_lists: { [OFFICE]: 'unavailable', [VPN]: { cidrs: ['192.0.2.0/24'], ver: 1 } } }), true, 0, [[]]],
  ['net: every failing source is reported once', net({ addresses: { cidrs: ['203.0.113.0/24'], lists: [list(OFFICE), list(VPN)], dns: { names: ['a.example.com', 'b.example.com'], dnssec: true } } }), ctx({ ...peer('192.0.2.5'), address_lists: { [VPN]: { cidrs: ['10.0.0.0/8'], ver: 1 } }, dns: { 'b.example.com': { addrs: ['192.0.2.5'] } } }), false, null, [['address_not_allowed', `address_list_unavailable:${OFFICE}`, 'dns_unresolved:a.example.com', 'dns_unvalidated:b.example.com']]],
  // Addresses: the webhook source.
  ['net: offline, only the webhook could allow: online required', net({ addresses: { cidrs: ['203.0.113.0/24'], webhook: HOOK } }), ctx(peer('192.0.2.5')), false, null, [['online_required']]],
  ['net: offline, another source allows without the webhook', net({ addresses: { cidrs: ['203.0.113.0/24'], webhook: HOOK } }), ctx(peer('203.0.113.5')), true, 0, [[]]],
  ['net: online, the webhook allows', net({ addresses: { webhook: HOOK } }), ctx({ ...peer('192.0.2.5'), online: true, address_webhook: { [HOOK]: true } }), true, 0, [[]]],
  ['net: online, the webhook denies', net({ addresses: { webhook: HOOK } }), ctx({ ...peer('192.0.2.5'), online: true, address_webhook: { [HOOK]: false } }), false, null, [['address_not_allowed']]],
  ['net: online, no webhook answer denies', net({ addresses: { webhook: HOOK } }), ctx({ ...peer('192.0.2.5'), online: true }), false, null, [['address_not_allowed']]],
  // Addresses of the origin, recorded by the first relay.
  ['net: of origin checks the first relay\'s record, not the peer', net({ addresses: { of: 'origin', cidrs: ['10.0.0.0/8'] }, route: { relays: [HQ] } }), ctx({ ...peer('198.51.100.1'), ...route([HQ], '10.1.2.3') }), true, 0, [[]]],
  ['net: of origin denies an origin outside the ranges', net({ addresses: { of: 'origin', cidrs: ['10.0.0.0/8'] }, route: { relays: [HQ] } }), ctx({ ...peer('10.9.9.9'), ...route([HQ], '172.16.0.1') }), false, null, [['address_not_allowed']]],
  ['net: of origin without a route', net({ addresses: { of: 'origin', cidrs: ['10.0.0.0/8'] }, route: { relays: [HQ] } }), ctx(peer('10.9.9.9')), false, null, [['address_unavailable', 'route_required']]],
  ['net: of origin needs a route rule', net({ addresses: { of: 'origin', cidrs: ['10.0.0.0/8'] } }), ctx(peer('10.9.9.9')), false, null, [['invalid_grant']]],
  // Route.
  ['net: a route through a listed relay allows', net({ route: { relays: [HQ, EDGE] } }), ctx({ ...peer('198.51.100.1'), ...route([EDGE]) }), true, 0, [[]]],
  ['net: no route denies', net({ route: { relays: [HQ] } }), ctx(peer('198.51.100.1')), false, null, [['route_required']]],
  ['net: the verifier\'s route error is reported', net({ route: { relays: [HQ] } }), ctx({ ...peer('198.51.100.1'), ...route([HQ]), route_error: 'egress_mismatch' }), false, null, [['route_invalid:egress_mismatch']]],
  ['net: a malformed route error is reported as malformed', net({ route: { relays: [HQ] } }), ctx({ route_error: 'Bad Thing!' }), false, null, [['route_invalid:malformed']]],
  ['net: too few hops', net({ route: { relays: [HQ, EDGE], min_hops: 2 } }), ctx(route([HQ])), false, null, [['route_invalid:hop_count']]],
  ['net: too many hops', net({ route: { relays: [HQ, EDGE], max_hops: 1 } }), ctx(route([HQ, EDGE])), false, null, [['route_invalid:hop_count']]],
  ['net: a relay not listed denies', net({ route: { relays: [HQ] } }), ctx(route([HQ, ROGUE])), false, null, [['route_relay_not_allowed']]],
  ['net: attested relays required and present', net({ route: { relays: [HQ], require_attested: true } }), ctx(route([HQ], '10.1.2.3', { attested: [true] })), true, 0, [[]]],
  ['net: attested relays required and missing', net({ route: { relays: [HQ, EDGE], require_attested: true } }), ctx(route([HQ, EDGE], '10.1.2.3', { attested: [true, false] })), false, null, [['route_invalid:relay_not_attested']]],
  ['net: min_hops above max_hops is invalid', net({ route: { relays: [HQ], min_hops: 3, max_hops: 2 } }), ctx(route([HQ])), false, null, [['invalid_grant']]],
  // Latency.
  ['net: a round trip within the maximum allows', net({ latency: { max_rtt_ms: 40 } }), ctx(peer('203.0.113.9', { rtt_ms: 40 })), true, 0, [[]]],
  ['net: a round trip over the maximum denies', net({ latency: { max_rtt_ms: 40 } }), ctx(peer('203.0.113.9', { rtt_ms: 40.5 })), false, null, [['rtt_exceeded']]],
  ['net: no measurement asks for a challenge', net({ latency: { max_rtt_ms: 40, samples: 3 } }), ctx(peer('203.0.113.9')), false, null, [['rtt_required']]],
  ['net: a negative measurement is no measurement', net({ latency: { max_rtt_ms: 40 } }), ctx(peer('203.0.113.9', { rtt_ms: -1 })), false, null, [['rtt_required']]],
  ['net: max_rtt_ms out of range is invalid', net({ latency: { max_rtt_ms: 5001 } }), ctx(peer('203.0.113.9', { rtt_ms: 1 })), false, null, [['invalid_grant']]],
  // Together, and beside other constraints.
  ['net: address, route and latency all reported in order', net({ addresses: { cidrs: ['203.0.113.0/24'] }, route: { relays: [HQ] }, latency: { max_rtt_ms: 40 } }), ctx(peer('192.0.2.1', { rtt_ms: 90 })), false, null, [['address_not_allowed', 'route_required', 'rtt_exceeded']]],
  ['net: reasons come after where and before online_required', [{ actions: W, where: { source: 'network', countries: ['US'] }, net: { client: { latency: { max_rtt_ms: 40 } } }, require: { confirmation: true } }], ctx(peer('192.0.2.1', { country: 'CA', rtt_ms: 90 })), false, null, [['outside_location:network', 'rtt_exceeded', 'confirmation_required']]],
  ['net: where.networks is unchanged beside net', [{ actions: W, where: { source: 'network', networks: ['203.0.113.0/24'] }, net: { client: { addresses: { cidrs: ['192.0.2.0/24'] } } } }], ctx(peer('192.0.2.1')), false, null, [['network_not_allowed']]],
  ['net: server rules are not evaluated by verifiers', [{ actions: W, net: { server: { addresses: { cidrs: ['198.51.100.0/24'] }, latency: { max_rtt_ms: 1 } } } }], ctx(), true, 0, [[]]],
  // Shape.
  ['net: an unknown member denies', net({ latency: { max_rtt_ms: 40, jitter_ms: 5 } }), ctx(peer('203.0.113.9', { rtt_ms: 1 })), false, null, [['unknown_constraint:net.client.latency.jitter_ms']]],
  ['net: an unknown direction denies', [{ actions: W, net: { sideways: {} } }], ctx(), false, null, [['unknown_constraint:net.sideways']]],
  ['net: an empty net is invalid', [{ actions: W, net: {} }], ctx(), false, null, [['invalid_grant']]],
  ['net: a webhook on the server side is invalid', [{ actions: W, net: { server: { addresses: { webhook: HOOK } } } }], ctx(), false, null, [['invalid_grant']]],
  ['net: a host name must be lower case', net({ addresses: { dns: { names: ['VPN.example.com'] } } }), ctx(peer('192.0.2.1')), false, null, [['invalid_grant']]]
];
