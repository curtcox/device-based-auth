import { it, expect } from 'vitest';
import { describeKey } from '../frontend/js/html.js';

it('says where a device key lives, and whether anyone checked', () => {
  expect(describeKey({ key_protection: 'android-keystore' })).toBe('Android Keystore (self-reported)');
  expect(describeKey({ key_protection: 'android-keystore', attestation: { format: 'android-key', security_level: 'strongbox', verified_boot: 'verified', device_locked: true } }))
    .toBe('Android Keystore, attested by Google (StrongBox secure element, verified boot, bootloader locked)');
  expect(describeKey({ attestation: { format: 'android-key', security_level: 'tee', verified_boot: 'unverified', device_locked: false } }))
    .toBe('Android Keystore, attested by Google (trusted execution environment, unverified boot, bootloader unlocked)');
  expect(describeKey({ key_protection: 'nonsense' })).toBe('nonsense (self-reported)');
  expect(describeKey(undefined)).toBe('unknown (self-reported)');
});
