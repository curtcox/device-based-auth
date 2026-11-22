import CryptoKit
import Foundation
import Security

/// A P-256 signing key the device holds. A Secure Enclave key (`SecureEnclaveKeys`) and a software
/// key (`P256.Signing.PrivateKey`, for tests and the simulator) both qualify.
public protocol DeviceKey {
    var publicKey: P256.Signing.PublicKey { get }
    /// An ES256 signature over `data`: raw r || s, 64 bytes, as JOSE wants.
    func es256(_ data: Data) throws -> Data
}

extension P256.Signing.PrivateKey: DeviceKey {
    public func es256(_ data: Data) throws -> Data { try signature(for: data).rawRepresentation }
}

extension SecureEnclave.P256.Signing.PrivateKey: DeviceKey {
    public func es256(_ data: Data) throws -> Data { try signature(for: data).rawRepresentation }
}

/// An error response from devicebasedauth.org (`{ error, code }`), or a failed enrollment.
public struct DbaError: Error, CustomStringConvertible {
    public let status: Int
    public let code: String
    public let message: String
    /// With code "use_dpop_nonce": the nonce to put in a new proof (RFC 9449 §8).
    public var dpopNonce: String? = nil
    public var description: String { "\(message) (\(code))" }
}

/// A devicebasedauth.org device client for iOS 15+ and macOS 12+ (Foundation and CryptoKit only).
///
/// The private key never leaves its `DeviceKey`: with the Secure Enclave that means it never leaves
/// the chip. Steps: send an enrollment request signed by the device key (ES256 JWS, public key in
/// the header); show the approval link to the account owner; poll until approved; then sign a DPoP
/// proof for each request.
public struct DbaClient {
    public let origin: String
    private let key: any DeviceKey
    private let session: URLSession

    /// - Parameters:
    ///   - origin: https://devicebasedauth.org (or a local server)
    ///   - key: the device key, normally `SecureEnclaveKeys.loadOrCreate(...)`
    public init(origin: String, key: any DeviceKey, session: URLSession = .shared) {
        var trimmed = origin
        while trimmed.hasSuffix("/") { trimmed.removeLast() }
        self.origin = trimmed
        self.key = key
        self.session = session
    }

    /// The public JWK the server stores and binds the credential to.
    public var publicJwk: [String: Any] { Self.publicJwk(key.publicKey) }

    /// Ask for a credential and wait for the account owner to approve it.
    ///
    /// - Parameters:
    ///   - audiences: sites the credential is for, e.g. `["hashbin.org"]`
    ///   - grants: what the device may do, e.g. `[["actions": ["hashbin:content:write"]]]`
    ///   - device: `{name, kind, key_protection}` shown to the approver
    ///   - attestation: from `AppAttest.attestation(...)`, or nil to enroll without one. A rejected
    ///     attestation fails the enrollment (`invalid_attestation`) rather than enrolling unattested.
    ///   - onApprovalUrl: show or open this link for the account owner
    /// - Returns: the credential (a compact JWS); keep it with the key, it is not secret
    public func enroll(audiences: [String], grants: [[String: Any]], device: [String: Any], attestation: [String: Any]? = nil,
                       onApprovalUrl: (String) -> Void) async throws -> String {
        var payload: [String: Any] = ["iat": Self.now(), "aud": audiences, "grants": grants, "device": device]
        if let attestation { payload["attestation"] = attestation }
        let request = try signJws(header: ["typ": "dba-enroll+jwt", "jwk": publicJwk], payload: payload)
        let start = try await send("POST", "\(origin)/api/v1/enrollments", body: ["request": request])
        guard let approvalUrl = start["approval_url"] as? String, let pollUrl = start["poll_url"] as? String,
              let expiresIn = start["expires_in"] as? Int, var interval = start["interval"] as? Int else {
            throw DbaError(status: 0, code: "bad_response", message: "Unexpected enrollment response")
        }
        onApprovalUrl(approvalUrl)

        let deadline = Date().addingTimeInterval(TimeInterval(expiresIn))
        while Date() < deadline {
            try await Task.sleep(nanoseconds: UInt64(interval) * 1_000_000_000)
            let poll = try await send("GET", pollUrl)
            let status = poll["status"] as? String ?? "unknown"
            if status == "approved", let credential = poll["credential"] as? String { return credential }
            if status != "pending" { throw DbaError(status: 0, code: "enrollment_\(status)", message: "Enrollment \(status)") }
            if let next = poll["interval"] as? Int { interval = next }
        }
        throw DbaError(status: 0, code: "enrollment_timeout", message: "Gave up waiting for approval")
    }

    /// A key attestation challenge (valid 10 minutes), for `AppAttest.attestation(...)`.
    public func attestationChallenge() async throws -> String {
        let body = try await send("POST", "\(origin)/api/v1/enrollments/attestation-challenge", body: [:])
        guard let challenge = body["challenge"] as? String else { throw DbaError(status: 0, code: "bad_response", message: "No challenge") }
        return challenge
    }

    /// Call an API with the credential: `Authorization: DBA <credential>` plus a fresh DPoP proof.
    /// An account object that started less than a minute ago answers 401 use_dpop_nonce with its
    /// nonce: the request is sent once more with a proof that carries it.
    public func call(_ method: String, _ url: String, credential: String, body: [String: Any]? = nil) async throws -> [String: Any] {
        let headers = { (nonce: String?) in ["Authorization": "DBA \(credential)", "DPoP": try dpopProof(credential: credential, method: method, url: url, nonce: nonce)] }
        do {
            return try await send(method, url, body: body, headers: try headers(nil))
        } catch let error as DbaError where error.code == "use_dpop_nonce" && error.dpopNonce != nil {
            return try await send(method, url, body: body, headers: try headers(error.dpopNonce))
        }
    }

    /// A single-use proof bound to this method, URL (without query or fragment) and credential (ath),
    /// with the server's DPoP nonce when it asked for one.
    public func dpopProof(credential: String, method: String, url: String, nonce: String? = nil) throws -> String {
        let htu = String(url.prefix { $0 != "?" && $0 != "#" })
        var jti = [UInt8](repeating: 0, count: 16)
        guard SecRandomCopyBytes(kSecRandomDefault, jti.count, &jti) == errSecSuccess else {
            throw DbaError(status: 0, code: "random_failed", message: "No randomness for the proof id")
        }
        let ath = Self.b64u(Data(SHA256.hash(data: Data(credential.utf8))))
        var payload: [String: Any] = ["jti": Self.b64u(Data(jti)), "htm": method.uppercased(), "htu": htu, "iat": Self.now(), "ath": ath]
        if let nonce { payload["nonce"] = nonce }
        return try signJws(header: ["typ": "dpop+jwt", "jwk": publicJwk], payload: payload)
    }

    /// Compact JWS with ES256.
    func signJws(header: [String: Any], payload: [String: Any]) throws -> String {
        var protected = header
        protected["alg"] = "ES256"
        let input = "\(Self.b64u(try Self.json(protected))).\(Self.b64u(try Self.json(payload)))"
        return "\(input).\(Self.b64u(try key.es256(Data(input.utf8))))"
    }

    /// The JWK for a P-256 public key: x and y from the uncompressed point (0x04 || x || y).
    public static func publicJwk(_ key: P256.Signing.PublicKey) -> [String: Any] {
        let point = key.x963Representation
        return ["kty": "EC", "crv": "P-256", "x": b64u(point[1..<33]), "y": b64u(point[33..<65])]
    }

    /// RFC 7638 JWK thumbprint: SHA-256 of the required members in lexicographic order, no spaces.
    public static func thumbprint(_ key: P256.Signing.PublicKey) -> String {
        let point = key.x963Representation
        let canonical = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"\(b64u(point[1..<33]))\",\"y\":\"\(b64u(point[33..<65]))\"}"
        return b64u(Data(SHA256.hash(data: Data(canonical.utf8))))
    }

    private func send(_ method: String, _ url: String, body: [String: Any]? = nil, headers: [String: String] = [:]) async throws -> [String: Any] {
        guard let target = URL(string: url) else { throw DbaError(status: 0, code: "bad_url", message: "Bad URL \(url)") }
        var request = URLRequest(url: target, timeoutInterval: 30)
        request.httpMethod = method
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        for (name, value) in headers { request.setValue(value, forHTTPHeaderField: name) }
        if let body {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try Self.json(body)
        }
        let (data, response) = try await session.data(for: request)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
        if !(200..<300).contains(status) {
            throw DbaError(status: status, code: json["code"] as? String ?? "http_\(status)", message: "\(method) \(url): \(json["error"] as? String ?? "HTTP \(status)")", dpopNonce: json["dpop_nonce"] as? String)
        }
        return json
    }

    static func json(_ value: Any) throws -> Data {
        try JSONSerialization.data(withJSONObject: value, options: [.withoutEscapingSlashes])
    }

    public static func b64u<D: DataProtocol>(_ bytes: D) -> String {
        Data(bytes).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    private static func now() -> Int { Int(Date().timeIntervalSince1970) }
}
