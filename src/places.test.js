import { describe, it, expect } from 'vitest';
import { isPreciseArea, preciseAreas, coarsenArea, coarsenGrants } from '../frontend/js/places.js';
import { evaluateGrants } from '../packages/verify/src/index.js';

const home = { lat: 38.627123, lon: -90.199456, radius_m: 150 };

describe('precise places in grants (master plan §10)', () => {
  it('flags small or precisely centered circles only', () => {
    expect(isPreciseArea(home)).toBe(true);
    expect(isPreciseArea({ lat: 38.63, lon: -90.2, radius_m: 900 })).toBe(true);
    expect(isPreciseArea({ lat: 38.6271, lon: -90.2, radius_m: 5000 })).toBe(true);
    expect(isPreciseArea({ lat: 38.627, lon: -90.2, radius_m: 5000 })).toBe(false);
    expect(isPreciseArea({ lat: 38.6, lon: -90.2, radius_m: 1000 })).toBe(false);
    expect(preciseAreas([{ actions: ['a:b'] }, { actions: ['a:b'], where: { source: 'device', areas: [{ lat: 1, lon: 2, radius_m: 50000 }, home] } }])).toEqual([{ grant: 1, area: 1 }]);
    expect(preciseAreas('nonsense')).toEqual([]);
  });

  it('coarsens to a circle that contains the original', () => {
    const coarse = coarsenArea(home);
    expect(coarse).toEqual({ lat: 38.63, lon: -90.2, radius_m: 1000 });
    expect(isPreciseArea(coarse)).toBe(false);
    // Every point of the original circle's edge is still inside, so the owner loses nothing.
    const grants = coarsenGrants([{ actions: ['a:b'], where: { source: 'device', areas: [home] } }]);
    for (let bearing = 0; bearing < 360; bearing += 15) {
      const rad = bearing * Math.PI / 180; const d = 149 / 6371008.8;
      const lat = home.lat + (d * Math.cos(rad)) * 180 / Math.PI;
      const lon = home.lon + (d * Math.sin(rad) / Math.cos(home.lat * Math.PI / 180)) * 180 / Math.PI;
      const result = evaluateGrants(grants, { now: 1795017600, action: 'a:b', location: { device: { lat, lon, acc_m: 0, t: 1795017600 } } });
      expect(result.allow, `bearing ${bearing}`).toBe(true);
    }
    const big = { lat: 38.627123, lon: -90.199456, radius_m: 20000 };
    expect(coarsenArea(big).radius_m).toBeGreaterThanOrEqual(20000 + 300);
  });
});
