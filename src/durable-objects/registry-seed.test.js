import { describe, it, expect } from 'vitest';
import { RegistryDO } from './registry-do.js';
import { MemoryStorage } from '../../test-utils/storage.js';
import { FIRST_PARTY } from '../services/first-party.js';

const make = storage => new RegistryDO({ storage }, { OPERATOR_ACCOUNT: 'acct_operator' });
const ask = async (registry, args) => (await registry.fetch(new Request('http://registry/', { method: 'POST', body: JSON.stringify(args) }))).json();

describe('first-party audience seeding', () => {
  it('seeds every first-party audience, owned by the operator', async () => {
    const registry = make(new MemoryStorage());
    for (const { name, namespace } of FIRST_PARTY) {
      const audience = await ask(registry, { op: 'get', name });
      expect(audience).toMatchObject({ name, namespace, owner: 'acct_operator', first_party: true });
    }
    expect(FIRST_PARTY.map(a => a.name)).toContain('subetha.us');
  });

  it('adds an audience that joined FIRST_PARTY to a registry seeded before it, keeping what is there', async () => {
    const storage = new MemoryStorage();
    // A registry seeded at v1 (before subetha.us), whose cronly entry its owner has since changed.
    for (const audience of FIRST_PARTY.filter(a => a.name !== 'subetha.us')) {
      await storage.put(`aud:${audience.name}`, { ...audience, owner: 'acct_operator', first_party: true, ...(audience.name === 'cronly.org' ? { revocation_webhook: 'https://cronly.org/hooks/dba' } : {}) });
      await storage.put(`ns:${audience.namespace}`, audience.name);
    }
    await storage.put('seeded:v1', true);
    const registry = make(storage);
    expect(await ask(registry, { op: 'get', name: 'subetha.us' })).toMatchObject({ namespace: 'subetha', first_party: true, owner: 'acct_operator' });
    expect((await ask(registry, { op: 'get', name: 'cronly.org' })).revocation_webhook).toBe('https://cronly.org/hooks/dba');
  });

  it('never overwrites a customer audience that took a first-party name or namespace first', async () => {
    const storage = new MemoryStorage();
    await storage.put('aud:subetha.example', { name: 'subetha.example', namespace: 'subetha', owner: 'acct_customer' });
    await storage.put('ns:subetha', 'subetha.example');
    await storage.put('seeded:v1', true);
    const registry = make(storage);
    expect((await ask(registry, { op: 'get', name: 'subetha.us' })).code).toBe('unknown_audience');
    expect(await ask(registry, { op: 'get', name: 'subetha.example' })).toMatchObject({ owner: 'acct_customer' });
  });

  it('upgrades an existing catalog once, preserving gate policies, disabled webhooks and redirects', async () => {
    const storage = new MemoryStorage();
    const audience = FIRST_PARTY.find(a => a.name === 'devicebasedauth.org');
    const current = { ...audience, catalog: audience.catalog.filter(entry => !entry.action.startsWith('dba:networks:')).map(entry => ({ ...entry, gates: { require: true, fail_open: false } })), owner: 'acct_operator', first_party: true, revocation_webhook: null, redirect_uris: ['https://devicebasedauth.org/custom'], sign_in_gates: { require: true } };
    await storage.put('aud:devicebasedauth.org', current);
    await storage.put('ns:dba', 'devicebasedauth.org');
    await storage.put('seeded:v2', true);
    const registry = make(storage);
    const upgraded = await ask(registry, { op: 'get', name: audience.name });
    expect(upgraded).toEqual({ ...current, catalog: [...current.catalog, ...audience.catalog.filter(entry => entry.action.startsWith('dba:networks:'))] });
    // An operator can remove an action after the migration; reads and restarts do not restore it.
    await ask(registry, { op: 'update', name: audience.name, owner: 'acct_operator', changes: { catalog: current.catalog } });
    expect((await ask(make(storage), { op: 'get', name: audience.name })).catalog).toEqual(current.catalog);
  });

  it.each([
    { first_party: false, owner: 'acct_operator', namespace: 'dba', namespaceOwner: 'devicebasedauth.org' },
    { first_party: true, owner: 'acct_customer', namespace: 'dba', namespaceOwner: 'devicebasedauth.org' },
    { first_party: true, owner: 'acct_operator', namespace: 'custom', namespaceOwner: 'devicebasedauth.org' },
    { first_party: true, owner: 'acct_operator', namespace: 'dba', namespaceOwner: 'other.example' }
  ])('does not upgrade a conflicting or transferred catalog: %j', async ({ namespaceOwner, ...fields }) => {
    const storage = new MemoryStorage();
    const current = { name: 'devicebasedauth.org', catalog: [], ...fields };
    await storage.put('aud:devicebasedauth.org', current);
    await storage.put('ns:dba', namespaceOwner);
    await storage.put('seeded:v2', true);
    expect(await ask(make(storage), { op: 'get', name: current.name })).toEqual(current);
  });
});
