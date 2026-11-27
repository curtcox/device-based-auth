import { assert, errorResponse } from '../utils/errors.js';
import { FIRST_PARTY } from '../services/first-party.js';

export const AUDIENCE_NAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$|^localhost(?::\d{1,5})?$|^[a-z0-9-]+\.localhost(?::\d{1,5})?$/;
export const NAMESPACE = /^[a-z0-9-]{1,32}$/;
// Bump when FIRST_PARTY gains an audience or action (v3: dba:networks:read/write).
const SEED_VERSION = 'seeded:v3';
const RESERVED = new Set(['dba', 'hashbin', 'cronly', 'subetha', 'admin', 'system', 'test', 'example']);

/**
 * The global registry of audiences (relying parties): name (a domain), action namespace,
 * owner account, action catalog and OpenID Connect redirect URIs. Small and read-mostly.
 */
export class RegistryDO {
  constructor(ctx, env) { this.storage = ctx.storage; this.env = env; }

  /**
   * Adds the first-party audiences. A registry seeded before an audience joined FIRST_PARTY gets
   * it on the next version, unless its name or namespace was taken meanwhile: a customer's
   * audience is never overwritten (the owner then resolves it by hand). Existing operator-owned
   * first-party catalogs gain new actions without changing their policies or other settings.
   */
  async seed(tx) {
    if (await tx.get(SEED_VERSION)) return;
    for (const audience of FIRST_PARTY) {
      const current = await tx.get(`aud:${audience.name}`);
      const namespaceOwner = await tx.get(`ns:${audience.namespace}`);
      if (current) {
        if (current.first_party && current.owner === (this.env.OPERATOR_ACCOUNT || 'operator') && current.namespace === audience.namespace && namespaceOwner === audience.name) {
          const actions = new Set(current.catalog.map(entry => entry.action));
          const added = audience.catalog.filter(entry => !actions.has(entry.action));
          if (added.length) await tx.put(`aud:${audience.name}`, { ...current, catalog: [...current.catalog, ...added] });
        }
        continue;
      }
      if (namespaceOwner) continue;
      await tx.put(`aud:${audience.name}`, { ...audience, owner: this.env.OPERATOR_ACCOUNT || 'operator', first_party: true, verified: true, accept_access_tokens: true, created_at: 0 });
      await tx.put(`ns:${audience.namespace}`, audience.name);
    }
    await tx.put(SEED_VERSION, true);
  }

  async fetch(request) {
    try {
      const args = await request.json(); const now = args.now ?? Date.now();
      return Response.json(await this.storage.transaction(async tx => {
        await this.seed(tx);
        switch (args.op) {
          case 'get': { const a = await tx.get(`aud:${args.name}`); assert(a, 'unknown_audience', `Unknown audience ${args.name}`, 404); return a; }
          case 'get-many': {
            const found = {};
            for (const name of args.names) { const a = await tx.get(`aud:${name}`); assert(a, 'unknown_audience', `Unknown audience ${name}`, 400); found[name] = a; }
            return found;
          }
          case 'webhooks': {
            // Revocation webhook URLs for the named audiences that have one (unknown names skipped).
            const hooks = {};
            for (const name of args.names.slice(0, 100)) { const a = await tx.get(`aud:${name}`); if (a?.revocation_webhook) hooks[name] = a.revocation_webhook; }
            return hooks;
          }
          case 'list': {
            const all = [...(await tx.list({ prefix: 'aud:' })).values()];
            return { items: args.owner ? all.filter(a => a.owner === args.owner) : all.map(({ name, namespace, description, first_party }) => ({ name, namespace, description, first_party: !!first_party })) };
          }
          case 'register': {
            const { name, namespace } = args.audience;
            assert(AUDIENCE_NAME.test(name), 'invalid_audience', 'Audience name must be a lower-case domain name');
            assert(NAMESPACE.test(namespace) && !RESERVED.has(namespace), 'invalid_namespace', 'Namespace must be 1–32 of a-z, 0-9 and "-", and not reserved');
            assert(!(await tx.get(`aud:${name}`)), 'audience_exists', 'That audience is already registered', 409);
            assert(!(await tx.get(`ns:${namespace}`)), 'namespace_taken', 'That namespace is already taken', 409);
            const record = { ...args.audience, owner: args.owner, created_at: now };
            await tx.put(`aud:${name}`, record); await tx.put(`ns:${namespace}`, name);
            return record;
          }
          case 'update': {
            const current = await tx.get(`aud:${args.name}`);
            assert(current, 'unknown_audience', 'Unknown audience', 404);
            assert(current.owner === args.owner, 'forbidden', 'You do not own this audience', 403);
            const next = { ...current, ...args.changes, name: current.name, namespace: current.namespace, owner: current.owner, updated_at: now };
            await tx.put(`aud:${args.name}`, next);
            return next;
          }
          // Verified email addresses (by SHA-256 of the lower-cased address) to the one account that
          // may be recovered by email there (done/clerk_free_accounts.md §3.5).
          case 'email-get': return { account: (await tx.get(`email:${args.hash}`)) ?? null };
          case 'email-claim': {
            const holder = await tx.get(`email:${args.hash}`);
            assert(!holder || holder === args.account, 'email_in_use', 'Another account already uses this address for recovery', 409);
            if (!holder) await tx.put(`email:${args.hash}`, args.account);
            return { ok: true };
          }
          case 'email-release': {
            if ((await tx.get(`email:${args.hash}`)) === args.account) await tx.delete(`email:${args.hash}`);
            return { ok: true };
          }
          default: assert(false, 'unknown_operation', 'Unknown registry operation', 500);
        }
      }));
    } catch (error) { return errorResponse(error); }
  }
}
