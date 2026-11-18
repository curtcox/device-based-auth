package org.devicebasedauth.sample;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Runs DbaClient on a plain JVM (how CI tests this sample). In an app the key comes from
 * AndroidKeystoreKeys instead and the approval link opens in the browser.
 *
 *     DBA_ORIGIN=http://localhost:8787 bash docs/samples/android/run.sh
 */
public final class Main {
    public static void main(String[] args) throws Exception {
        String origin = System.getenv().getOrDefault("DBA_ORIGIN", "https://devicebasedauth.org");
        // On a phone this challenge goes into AndroidKeystoreKeys.create(alias, challenge); a JVM
        // key cannot be attested, so here it is only fetched.
        System.out.println("Attestation challenge: " + DbaClient.attestationChallenge(origin));
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair key = generator.generateKeyPair();
        DbaClient client = new DbaClient(origin, key.getPrivate(), (ECPublicKey) key.getPublic());

        List<Object> grants = List.of(DbaClient.map("actions", List.of("hashbin:content:write")));
        Map<String, Object> device = DbaClient.map("name", "Android sample", "kind", "phone", "key_protection", "software");
        String credential = client.enroll(Collections.singletonList("hashbin.org"), grants, device, url -> {
            System.out.println("Ask the account owner to approve this device:");
            System.out.println(url);
            System.out.flush();
        });
        String payload = new String(Base64.getUrlDecoder().decode(credential.split("\\.")[1]), java.nio.charset.StandardCharsets.UTF_8);
        System.out.println("Approved. Credential id: " + DbaClient.asMap(DbaClient.Json.parse(payload)).get("cid"));

        // devicebasedauth.org is itself a relying party, so ask it who we are.
        Map<String, Object> me = DbaClient.asMap(client.call("GET", origin.replaceAll("/+$", "") + "/api/v1/whoami", credential, null));
        System.out.println("whoami: account " + me.get("account") + ", device " + me.get("device_id"));
        for (Object description : (List<?>) me.get("descriptions")) System.out.println(" - " + description);

        // Renew (same key) before expiry, e.g. at two thirds of the lifetime; keep the new credential.
        Map<String, Object> renewed = DbaClient.asMap(client.call("POST", origin.replaceAll("/+$", "") + "/api/v1/credentials/" + me.get("cid") + "/renew", credential, DbaClient.map()));
        credential = (String) renewed.get("credential");
        System.out.println("Renewed: " + renewed.get("jti"));
    }
}
