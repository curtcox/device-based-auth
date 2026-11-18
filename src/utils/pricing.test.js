import { it, expect } from 'vitest';
import { PRICES, passesFloor, priceTable } from './pricing.js';
import { grossUp, COST_POLICY, OPERATIONS } from './cost-policy.js';

it('keeps every price above the cost floor', () => {
  for (const op of Object.keys(OPERATIONS)) {
    expect(Number.isSafeInteger(PRICES[op]), op).toBe(true);
    expect(passesFloor(op), `${op}: ${JSON.stringify(priceTable().find(r => r.op === op))}`).toBe(true);
  }
  expect(Object.keys(PRICES).sort()).toEqual(Object.keys(OPERATIONS).sort());
});
it('passes payment costs through without reducing the credited deposit', () => {
  for (const credit of [500, 2000, 100000]) expect(grossUp(credit) * (1 - COST_POLICY.stripeRate) - COST_POLICY.stripeFixedCents).toBeGreaterThanOrEqual(credit);
  expect(grossUp(500)).toBe(546);
});
