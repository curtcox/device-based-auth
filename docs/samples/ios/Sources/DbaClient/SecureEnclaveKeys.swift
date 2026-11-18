import CryptoKit
import Foundation
import Security

/// The device key in the Secure Enclave: generated inside it and never exported. What the app keeps
/// is `dataRepresentation`, a blob only this device's Secure Enclave can use, stored in the Keychain
/// (this device only, never in backups or iCloud).
public enum SecureEnclaveKeys {
    static let service = "org.devicebasedauth.device-key"

    /// The key saved under `name`, or a new Secure Enclave key saved under it.
    public static func loadOrCreate(name: String) throws -> SecureEnclave.P256.Signing.PrivateKey {
        if let key = try load(name: name) { return key }
        let key = try create()
        try save(key, name: name)
        return key
    }

    /// A new key in the Secure Enclave, usable while the device is unlocked. Add `.biometryCurrentSet`
    /// to the flags to ask for Face ID / Touch ID on every signature.
    public static func create(flags: SecAccessControlCreateFlags = [.privateKeyUsage]) throws -> SecureEnclave.P256.Signing.PrivateKey {
        guard SecureEnclave.isAvailable else { throw DbaError(status: 0, code: "no_secure_enclave", message: "This device has no Secure Enclave") }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &error) else {
            throw error.map { $0.takeRetainedValue() as Error } ?? DbaError(status: 0, code: "access_control", message: "Could not create access control")
        }
        return try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
    }

    public static func load(name: String) throws -> SecureEnclave.P256.Signing.PrivateKey? {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                                    kSecAttrAccount as String: name, kSecReturnData as String: true]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let blob = item as? Data else { throw keychainError(status) }
        return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
    }

    public static func save(_ key: SecureEnclave.P256.Signing.PrivateKey, name: String) throws {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                                    kSecAttrAccount as String: name, kSecValueData as String: key.dataRepresentation,
                                    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw keychainError(status) }
    }

    /// Forget the key (after revoking its credential, or to re-enroll).
    public static func delete(name: String) {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: name]
        SecItemDelete(query as CFDictionary)
    }

    private static func keychainError(_ status: OSStatus) -> DbaError {
        DbaError(status: 0, code: "keychain_\(status)", message: "Keychain error \(status)")
    }
}
