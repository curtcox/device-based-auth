import { worstCaseCost, COST_POLICY, OPERATIONS } from './cost-policy.js';

/** Prices in integer micro-dollars. The only place prices live. */
export const PRICES = Object.freeze({ issue: 85, renew: 25, decision: 14, read: 5, token: 5, login: 12, audience: 100, gate: 20, gate_webhook: 22 });
export const MINIMUM_DEPOSIT_CENTS = 500;
export const MAXIMUM_DEPOSIT_CENTS = 100000;

/** Price of one operation. */
export function price(op) {
  if (!Object.hasOwn(PRICES, op)) throw new Error(`unknown operation ${op}`);
  return PRICES[op];
}

/** Lowest price that keeps the required margin after payment losses. */
export function floorPrice(op) {
  return Math.ceil(COST_POLICY.minimumMargin * Math.ceil(worstCaseCost(op)) / COST_POLICY.revenueKept);
}

/** True when the price keeps the required margin after payment losses. */
export function passesFloor(op) {
  return price(op) * COST_POLICY.revenueKept >= COST_POLICY.minimumMargin * Math.ceil(worstCaseCost(op));
}

/** A table for the pricing page and /api/public/config. */
export function priceTable() {
  return Object.keys(OPERATIONS).map(op => ({ op, price_microdollars: price(op), worst_case_cost_microdollars: Math.ceil(worstCaseCost(op)), floor_microdollars: floorPrice(op) }));
}
