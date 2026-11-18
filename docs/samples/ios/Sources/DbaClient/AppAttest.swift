import CryptoKit
import DeviceCheck
import Foundation

/// Apple App Attest for the device key. App Attest cannot vouch for an arbitrary key: it attests a
/// key of its own and says which app, on a genuine device, holds it. Binding the DBA key's
/// thumbprint into the attestation's client data lets the issuer tie the two together, so the
/// credential can say the key belongs to your app (`require.app_ids`).
public enum AppAttest {
    /// The `attestation` member for `DbaClient.enroll`, or nil where App Attest is unsupported
    /// (the simulator, Macs, old devices); enroll without one there.
    ///
    /// - Parameters:
    ///   - key: the device key being enrolled
    ///   - challenge: from `DbaClient.attestationChallenge()` (valid 10 minutes)
    ///   - appId: your team id and bundle id, e.g. "ABCDE12345.org.example.wallet"
    public static func attestation(for key: any DeviceKey, challenge: String, appId: String) async throws -> [String: Any]? {
        let service = DCAppAttestService.shared
        guard service.isSupported else { return nil }
        let keyId = try await service.generateKey()
        let clientData = Data("\(challenge).\(DbaClient.thumbprint(key.publicKey))".utf8)
        let object = try await service.attestKey(keyId, clientDataHash: Data(SHA256.hash(data: clientData)))
        return ["format": "apple-appattest", "challenge": challenge, "app_id": appId, "key_id": keyId, "object": object.base64EncodedString()]
    }
}
