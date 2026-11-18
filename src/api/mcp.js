import { assert, readJson } from '../utils/errors.js';
import { evaluateGrants, describeGrant, validateGrants } from '../../packages/verify/src/grants.js';

const object = (properties = {}, required = []) => ({ type: 'object', properties, required, additionalProperties: false });
const string = { type: 'string' };

/** MCP tools: each one calls the ordinary API with the caller's own credential. */
export const MCP_TOOLS = [
  { name: 'whoami', description: 'Describe the credential this agent is using.', inputSchema: object(), path: '/api/v1/whoami' },
  { name: 'balance', description: 'Read the prepaid balance and this month\'s spend.', inputSchema: object(), path: '/api/v1/account' },
  { name: 'list_credentials', description: 'List issued credentials (filters: status active|expired|revoked, audience, device).', inputSchema: object({ status: string, audience: string, device: string }), path: '/api/v1/credentials' },
  { name: 'get_credential', description: 'Read one credential with its grants in plain English and its history.', inputSchema: object({ cid: string }, ['cid']), path: '/api/v1/credentials/:cid' },
  { name: 'request_enrollment', description: 'Submit a device enrollment request (a JWS of typ dba-enroll+jwt signed by the new device key; the `dba enroll --print-request` CLI makes one). Returns an approval_url a human must open to approve it. Nothing is charged until a human approves.', inputSchema: object({ request: string }, ['request']), path: '/api/v1/enrollments', method: 'POST' },
  { name: 'revoke_credential', description: 'Revoke a credential immediately (free).', inputSchema: object({ cid: string }, ['cid']), path: '/api/v1/credentials/:cid', method: 'DELETE' },
  { name: 'quote', description: 'Price of an operation in micro-dollars (issue, renew, decision, read, token, login, audience).', inputSchema: object({ op: string }, ['op']), path: '/api/v1/quote' },
  { name: 'inspect_credential', description: 'Decode and verify a credential; optionally check an action.', inputSchema: object({ credential: string, action: string, resource: string }, ['credential']), path: '/api/v1/inspect', method: 'POST', body: a => ({ credential: a.credential, ...(a.action ? { check: { action: a.action, resource: a.resource } } : {}) }) },
  { name: 'evaluate_grants', description: 'Evaluate grants (JSON array) for an action at a time and location (and, for require.attestation, the credential\'s device.attestation), offline and free. Same evaluator verifiers use.', inputSchema: object({ grants: string, action: string, resource: string, now: { type: 'integer' }, location: { type: 'object' }, attestation: { type: 'object' } }, ['grants', 'action']), local: true }
];

/** Stateless Streamable HTTP MCP endpoint (ported from cronly). */
export async function mcp(request, env, auth, invoke) {
  const origin = request.headers.get('Origin'); assert(!origin || origin === env.APP_ORIGIN, 'invalid_origin', 'Origin is not allowed', 403);
  const message = await readJson(request, 65536);
  assert(message.jsonrpc === '2.0' && typeof message.method === 'string', 'invalid_rpc', 'Invalid JSON-RPC message');
  if (message.id === undefined) return new Response(null, { status: 202 });
  const reply = result => Response.json({ jsonrpc: '2.0', id: message.id, result });
  if (message.method === 'initialize') return reply({ protocolVersion: '2025-11-25', capabilities: { tools: {} }, serverInfo: { name: 'devicebasedauth', version: '0.1.0' } });
  if (message.method === 'ping') return reply({});
  if (message.method === 'tools/list') return reply({ tools: MCP_TOOLS.map(({ name, description, inputSchema }) => ({ name, description, inputSchema })) });
  if (message.method !== 'tools/call') return Response.json({ jsonrpc: '2.0', id: message.id, error: { code: -32601, message: 'Method not found' } });
  const tool = MCP_TOOLS.find(t => t.name === message.params?.name);
  if (!tool) return Response.json({ jsonrpc: '2.0', id: message.id, error: { code: -32602, message: 'Unknown tool' } });
  const text = (value, isError = false) => reply({ content: [{ type: 'text', text: JSON.stringify(value) }], isError });
  try {
    const args = message.params.arguments || {};
    for (const field of tool.inputSchema.required) assert(args[field] !== undefined, 'invalid_arguments', `Missing ${field}`);
    if (tool.local) {
      let grants; try { grants = JSON.parse(args.grants); } catch { assert(false, 'invalid_arguments', 'grants must be a JSON array'); }
      const problems = validateGrants(grants);
      const result = evaluateGrants(grants, { now: args.now ?? Math.floor(Date.now() / 1000), action: args.action, resource: args.resource, location: args.location, online: false, attestation: args.attestation });
      return text({ allow: result.allow, grant_index: result.grant_index, reasons: result.reasons, online_required: result.online_required, problems, descriptions: Array.isArray(grants) ? grants.map(describeGrant) : [] });
    }
    let path = tool.path.replace(/:([a-z_]+)/g, (_, key) => encodeURIComponent(args[key]));
    const method = tool.method || 'GET';
    if (method === 'GET') { const query = new URLSearchParams(Object.entries(args).filter(([k]) => !tool.path.includes(`:${k}`))); if (query.size) path += `?${query}`; }
    const body = method === 'GET' || method === 'DELETE' ? undefined : tool.body ? tool.body(args) : args;
    const response = await invoke(path, method, body);
    return text(await response.json(), !response.ok);
  } catch (error) { return text({ error: error.message, code: error.code }, true); }
}
