package android.security.keystore;

import java.security.spec.KeySpec;

/** Compile-only stub of the Android API used by AndroidKeystoreKeys (never run). */
public class KeyInfo implements KeySpec {
    /** @deprecated replaced by {@link #getSecurityLevel()} in API 31. */
    @Deprecated
    public boolean isInsideSecureHardware() { return false; }

    public int getSecurityLevel() { return 0; }
}
