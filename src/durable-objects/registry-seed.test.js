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
});
