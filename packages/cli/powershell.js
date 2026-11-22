/** Running Windows PowerShell scripts without putting data on a command line (DPAPI, the TPM). */

/** PowerShell's -EncodedCommand: the script as base64 of UTF-16LE. */
export function powershellEncoded(script) {
  const bytes = new Uint8Array(script.length * 2);
  for (let i = 0; i < script.length; i++) { const code = script.charCodeAt(i); bytes[2 * i] = code & 0xff; bytes[2 * i + 1] = code >> 8; }
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}
