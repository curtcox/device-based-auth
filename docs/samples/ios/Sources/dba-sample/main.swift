import CryptoKit
import DbaClient
import Foundation

// Runs DbaClient from the command line (how CI tests this sample, on macOS). In an app the key comes
// from SecureEnclaveKeys.loadOrCreate(name:), AppAttest supplies the attestation, and the approval
// link opens in Safari.
//
//     DBA_ORIGIN=http://localhost:8787 bash docs/samples/ios/run.sh
let origin = ProcessInfo.processInfo.environment["DBA_ORIGIN"] ?? "https://devicebasedauth.org"
let key = P256.Signing.PrivateKey() // a software key: CI machines have no Secure Enclave
let client = DbaClient(origin: origin, key: key)

do {
    // On an iPhone this challenge goes into AppAttest.attestation(for:challenge:appId:); App Attest
    // is unavailable here, so it is only fetched.
    print("Attestation challenge: \(try await client.attestationChallenge())")
    var credential = try await client.enroll(
        audiences: ["hashbin.org"],
        grants: [["actions": ["hashbin:content:write"]]],
        device: ["name": "iOS sample", "kind": "phone", "key_protection": "software"]
    ) { url in
        print("Ask the account owner to approve this device:")
        print(url)
        fflush(stdout)
    }
    let payload = credential.split(separator: ".")[1]
    let padded = payload.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/") + String(repeating: "=", count: (4 - payload.count % 4) % 4)
    let claims = try JSONSerialization.jsonObject(with: Data(base64Encoded: padded) ?? Data()) as? [String: Any] ?? [:]
    print("Approved. Credential id: \(claims["cid"] as? String ?? "?")")

    // devicebasedauth.org is itself a relying party, so ask it who we are.
    let me = try await client.call("GET", "\(client.origin)/api/v1/whoami", credential: credential)
    print("whoami: account \(me["account"] as? String ?? "?"), device \(me["device_id"] as? String ?? "?")")
    for description in me["descriptions"] as? [String] ?? [] { print(" - \(description)") }

    // Renew (same key) before expiry, e.g. at two thirds of the lifetime; keep the new credential.
    let cid = me["cid"] as? String ?? ""
    let renewed = try await client.call("POST", "\(client.origin)/api/v1/credentials/\(cid)/renew", credential: credential, body: [:])
    credential = renewed["credential"] as? String ?? credential
    print("Renewed: \(renewed["jti"] as? String ?? "?")")
} catch {
    FileHandle.standardError.write(Data("\(error)\n".utf8))
    exit(1)
}
