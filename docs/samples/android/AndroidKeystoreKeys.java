package org.devicebasedauth.sample;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.security.keystore.StrongBoxUnavailableException;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

/**
 * The device key, kept in the Android Keystore (Android only; API 26+).
 *
 * The key is generated inside the Keystore (StrongBox when the phone has one, otherwise the
 * TEE) and cannot be exported: the app holds a handle, signs through it, and only the public key
 * ever leaves the phone. Pass {@link #privateKey()} and {@link #publicKey()} to {@link DbaClient}.
 *
 * <pre>
 * AndroidKeystoreKeys keys = AndroidKeystoreKeys.loadOrCreate("dba-device");
 * DbaClient client = new DbaClient("https://devicebasedauth.org", keys.privateKey(), keys.publicKey());
 * String credential = client.enroll(audiences, grants,
 *     DbaClient.map("name", Build.MODEL, "kind", "phone", "key_protection", keys.keyProtection()),
 *     url -&gt; startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url))));
 * </pre>
 */
public final class AndroidKeystoreKeys {
    private static final String PROVIDER = "AndroidKeyStore";
    private final PrivateKey privateKey;
    private final ECPublicKey publicKey;

    private AndroidKeystoreKeys(PrivateKey privateKey, ECPublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    /** The key under this alias, generating a P-256 signing key the first time. */
    public static AndroidKeystoreKeys loadOrCreate(String alias) throws GeneralSecurityException, java.io.IOException {
        KeyStore store = KeyStore.getInstance(PROVIDER);
        store.load(null);
        if (!store.containsAlias(alias)) generate(alias);
        KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) store.getEntry(alias, null);
        return new AndroidKeystoreKeys(entry.getPrivateKey(), (ECPublicKey) entry.getCertificate().getPublicKey());
    }

    private static void generate(String alias) throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER);
        if (Build.VERSION.SDK_INT >= 28) {
            try {
                generator.initialize(spec(alias, true));
                generator.generateKeyPair();
                return;
            } catch (StrongBoxUnavailableException noStrongBox) {
                // Fall through to the TEE-backed key below.
            }
        }
        generator.initialize(spec(alias, false));
        generator.generateKeyPair();
    }

    private static KeyGenParameterSpec spec(String alias, boolean strongBox) {
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256);
        if (strongBox) builder.setIsStrongBoxBacked(true);
        return builder.build();
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
