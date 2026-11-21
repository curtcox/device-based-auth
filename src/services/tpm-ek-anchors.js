// TPM manufacturers' endorsement-key (EK) CA certificates, trust anchors for EK credential
// activation (tpm-activation.js). From Keylime's tpm_cert_store (https://github.com/keylime/keylime,
// Apache-2.0, commit 8df08745bf81884af841c5235d8194db98d5e22e, fetched 2026-11-18), which collects
// the CAs Infineon, STMicroelectronics (via GlobalSign), Nuvoton, Intel (PTT) and Nationz publish.
// Alibaba Cloud's vTPM CA is left out: a virtual TPM is software in the host, not hardware.
// Every certificate here is an anchor, roots and intermediates alike, as in Keylime, because
// vendors' EK certificates do not always name a path to a self-signed root.
// Generated: the SHA-256 fingerprints are checked by src/tpm-activation.test.js.
// The certificates live in tpm-ek-anchors/, one module per manufacturer (Infineon's in three), to
// stay under the source file size limit. The list keeps Keylime's order (by file name), which is
// why GlobalSign's root for STMicroelectronics comes first.
import { GLOBALSIGN_TPM_ROOT, STMICRO } from './tpm-ek-anchors/stmicro.js';
import { INFINEON_IFX } from './tpm-ek-anchors/infineon-ifx.js';
import { INFINEON_IFX_RSA } from './tpm-ek-anchors/infineon-ifx-rsa.js';
import { INFINEON_INF } from './tpm-ek-anchors/infineon-inf.js';
import { INTEL } from './tpm-ek-anchors/intel.js';
import { NUVOTON } from './tpm-ek-anchors/nuvoton.js';
import { NATIONZ } from './tpm-ek-anchors/nationz.js';

export const TPM_EK_ANCHORS = Object.freeze([
  ...GLOBALSIGN_TPM_ROOT,
  ...INFINEON_IFX,
  ...INFINEON_IFX_RSA,
  ...INFINEON_INF,
  ...INTEL,
  ...NUVOTON,
  ...NATIONZ,
  ...STMICRO,
]);
