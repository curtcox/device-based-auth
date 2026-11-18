package org.devicebasedauth.sample;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.security.keystore.StrongBoxUnavailableException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.cert.Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * The device key, kept in the Android Keystore (Android only; API 26+).
 *
 * The key is generated inside the Keystore (StrongBox when the phone has one, otherwise the
 * TEE) and cannot be exported: the app holds a handle, signs through it, and only the public key
 * ever leaves the phone. Pass {@link #privateKey()} and {@link #publicKey()} to {@link DbaClient}.
 *
 * <p>To have the key attested (so the credential says "Android Keystore, attested by Google"
 * instead of "self-reported"), generate it with a challenge from devicebasedauth.org and send
 * the certificate chain with the enrollment request:
 *
 * <pre>
 * String challenge = DbaClient.attestationChallenge(origin);
 * AndroidKeystoreKeys keys = AndroidKeystoreKeys.create("dba-device", challenge);
 * DbaClient client = new DbaClient(origin, keys.privateKey(), keys.publicKey());
 * String credential = client.enroll(audiences, grants,
 *     DbaClient.map("name", Build.MODEL, "kind", "phone", "key_protection", keys.keyProtection()),
 *     keys.attestation(challenge),
 *     url -&gt; startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url))));
 * </pre>
 *
 * Later runs use {@link #load(String)}. The chain only proves the challenge it was made with, so
 * attestation happens once, when the key is created.
 */
public final class AndroidKeystoreKeys {
    private static final String PROVIDER = "AndroidKeyStore";
    private final PrivateKey privateKey;
    private final ECPublicKey publicKey;

    private AndroidKeystoreKeys(String alias, PrivateKey privateKey, ECPublicKey publicKey) {
        this.alias = alias;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    private final String alias;

    /** The existing key under this alias. */
    public static AndroidKeystoreKeys load(String alias) throws GeneralSecurityException, IOException {
        KeyStore store = keyStore();
        KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) store.getEntry(alias, null);
        if (entry == null) throw new KeyStoreException("No key named " + alias);
        return new AndroidKeystoreKeys(alias, entry.getPrivateKey(), (ECPublicKey) entry.getCertificate().getPublicKey());
    }

    /**
     * Generate a new P-256 signing key under this alias (replacing any old one), in StrongBox when
     * the phone has one. With a challenge, the Keystore also makes an attestation chain for it.
     */
    public static AndroidKeystoreKeys create(String alias, String attestationChallenge) throws GeneralSecurityException, IOException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER);
        byte[] challenge = attestationChallenge == null ? null : attestationChallenge.getBytes(StandardCharsets.US_ASCII);
        boolean done = false;
        if (Build.VERSION.SDK_INT >= 28) {
            try {
                generator.initialize(spec(alias, true, challenge));
                generator.generateKeyPair();
                done = true;
            } catch (StrongBoxUnavailableException noStrongBox) {
                // Fall through to the TEE-backed key below.
            }
        }
        if (!done) {
            generator.initialize(spec(alias, false, challenge));
            generator.generateKeyPair();
        }
        return load(alias);
    }

    private static KeyGenParameterSpec spec(String alias, boolean strongBox, byte[] challenge) {
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256);
        if (strongBox) builder.setIsStrongBoxBacked(true);
        if (challenge != null) builder.setAttestationChallenge(challenge);
        return builder.build();
    }

    private static KeyStore keyStore() throws GeneralSecurityException, IOException {
        KeyStore store = KeyStore.getInstance(PROVIDER);
        store.load(null);
        return store;
    }

    /**
     * The enrollment request's {@code attestation} member: the challenge the key was created with
     * and its certificate chain (base64 DER, leaf first, ending at a Google root).
     */
    public Map<String, Object> attestation(String challenge) throws GeneralSecurityException, IOException {
        List<Object> x5c = new ArrayList<>();
        for (Certificate certificate : keyStore().getCertificateChain(alias)) x5c.add(Base64.getEncoder().encodeToString(certificate.getEncoded()));
        return DbaClient.map("format", "android-key", "challenge", challenge, "x5c", x5c);
    }

    public PrivateKey privateKey() {
        return privateKey;
    }

    public ECPublicKey publicKey() {
        return publicKey;
    }

    /**
     * "android-keystore" when the key lives in secure hardware, otherwise "software" (some
     * emulators). It is shown to the approver and self-reported, like every key_protection.
     */
    public String keyProtection() throws GeneralSecurityException {
        KeyInfo info = KeyFactory.getInstance(privateKey.getAlgorithm(), PROVIDER).getKeySpec(privateKey, KeyInfo.class);
        boolean hardware = Build.VERSION.SDK_INT >= 31
                ? info.getSecurityLevel() == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT || info.getSecurityLevel() == KeyProperties.SECURITY_LEVEL_STRONGBOX
                : info.isInsideSecureHardware();
        return hardware ? "android-keystore" : "software";
    }
}
