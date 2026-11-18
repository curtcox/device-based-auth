package android.security.keystore;

import java.security.spec.AlgorithmParameterSpec;

/** Compile-only stub of the Android API used by AndroidKeystoreKeys (never run). */
public final class KeyGenParameterSpec implements AlgorithmParameterSpec {
    public static final class Builder {
        public Builder(String keystoreAlias, int purposes) { }

        public Builder setAlgorithmParameterSpec(AlgorithmParameterSpec spec) { return this; }

        public Builder setDigests(String... digests) { return this; }

        public Builder setIsStrongBoxBacked(boolean isStrongBoxBacked) { return this; }

        public KeyGenParameterSpec build() { return new KeyGenParameterSpec(); }
    }
}
