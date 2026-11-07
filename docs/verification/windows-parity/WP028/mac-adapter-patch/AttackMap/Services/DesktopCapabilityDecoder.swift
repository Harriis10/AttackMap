// SPDX-License-Identifier: MIT
// Prepared against AttackMap-mac 5f2e8b4d84f9dff06e0f87c69c861a434981bd6a.
import Foundation
import CoreFoundation

/// Inert desktop negotiation. Legacy analyze flags are a separate contract.
struct DesktopCapabilityResult: Sendable {
    enum Status: String, Sendable {
        case compatible, malformed
        case legacy = "legacy_engine_unsupported"
        case capabilitiesSchema = "incompatible_capabilities_schema"
        case runSchema = "incompatible_run_schema"
        case commands = "missing_desktop_commands"
    }
    let status: Status
    let snapshot: DesktopCapabilitySnapshot?
    var supported: Bool { status == .compatible && snapshot != nil }
}

struct DesktopCapabilitySnapshot: Sendable {
    static let knownSchemas: Set<String> = ["1.0", "1.1", "1.2", "1.3", "1.4"]
    let schemaVersions: Set<String>
    let scanOptions: [String: Set<String>]
    let providerOptions: [String: Set<String>]
    let modes: [String: Set<String>]
    let providers: Set<String>
    /// Complete producer identity, including unknown additive identity fields.
    /// It is a content/cache identity, not publisher authentication.
    let expectedIdentityJSON: Data
    let fleetSchemas: Set<String>

    func advertisesSingleRepository(schema: String, scanFields: Set<String>,
                                    providerFields: Set<String>, mode: String, provider: String) -> Bool {
        guard schema != "1.4", Self.knownSchemas.contains(schema), schemaVersions.contains(schema),
              let scan = scanOptions[schema], let fields = providerOptions[schema], let allowedModes = modes[schema]
        else { return false }
        return scanFields.isSubset(of: scan) && providerFields.isSubset(of: fields)
            && allowedModes.contains(mode) && providers.contains(provider)
    }

    /// Builds an action payload only; does not start a process or validate all
    /// core option values. A real desktop adapter must await engine preflight.
    func preflightPayload(request: Data) throws -> Data {
        let requestObject = try DesktopCapabilityDecoder.object(request, limit: 4 * 1024 * 1024)
        let identity = try DesktopCapabilityDecoder.object(expectedIdentityJSON, limit: 4 * 1024 * 1024)
        return try JSONSerialization.data(withJSONObject: ["request": requestObject, "expected_identity": identity], options: [.sortedKeys])
    }
}

struct DesktopPreflightResult: Sendable {
    let supported: Bool
    let status: String
}

enum DesktopCapabilityDecoder {
    private enum Invalid: Error { case malformed }

    static func decode(_ data: Data) -> DesktopCapabilityResult {
        do {
            let root = try object(data, limit: 4 * 1024 * 1024)
            guard let schema = integer(root["schema"]) else { throw Invalid.malformed }
            guard schema == 1 else { return .init(status: .capabilitiesSchema, snapshot: nil) }
            guard let rawDesktop = root["desktop"] else { return .init(status: .legacy, snapshot: nil) }
            guard let desktop = rawDesktop as? [String: Any], let identity = root["engine_identity"] as? [String: Any],
                  let path = identity["path"] as? String, !path.isEmpty, !path.contains("\0"),
                  path.hasPrefix("/") || path.range(of: #"^[A-Za-z]:[/\\]"#, options: .regularExpression) != nil,
                  let size = integer(identity["size_bytes"]), size > 0,
                  let kind = identity["runtime_kind"] as? String, ["Python", "Frozen"].contains(kind),
                  let hash = identity["sha256"] as? String, validHash(hash)
            else { throw Invalid.malformed }
            for key in ["source_sha256", "modules_sha256"] where identity[key] != nil {
                guard let hash = identity[key] as? String, validHash(hash) else { throw Invalid.malformed }
            }
            let commands = try strings(root["commands"])
            let actionSchemas = try strings(desktop["actions_schema_versions"])
            let operations = try strings(desktop["operations"])
            let schemas = try strings(desktop["schema_versions"])
            let commonScan = try strings(desktop["scan_options"])
            let commonProvider = try strings(desktop["provider_options"])
            let commonModes = try strings(desktop["modes"])
            let providers = try strings(desktop["providers"])
            guard commands.isSuperset(of: ["desktop-worker", "desktop-action"]),
                  actionSchemas.contains("1.1"), operations.isSuperset(of: ["capabilities", "preflight"])
            else { return .init(status: .commands, snapshot: nil) }
            guard !schemas.isDisjoint(with: DesktopCapabilitySnapshot.knownSchemas) else { return .init(status: .runSchema, snapshot: nil) }
            var scan = try schemaMap(desktop["scan_options_by_schema"])
            var provider = try schemaMap(desktop["provider_options_by_schema"])
            var modes = try schemaMap(desktop["modes_by_schema"])
            for version in schemas {
                if scan[version] == nil { scan[version] = commonScan }
                // Never infer advanced AI support from global provider/mode lists.
                if version != "1.3" {
                    if provider[version] == nil { provider[version] = commonProvider }
                    if modes[version] == nil { modes[version] = commonModes }
                }
            }
            var fleet = Set<String>()
            if let raw = desktop["fleet_by_schema"] {
                guard let bySchema = raw as? [String: Any] else { throw Invalid.malformed }
                if let raw14 = bySchema["1.4"] {
                    guard let fields = raw14 as? [String: Any], fields["kind"] as? String == "fleet_request",
                          boolean(fields["multi_repo"]) == true,
                          integer(fields["minimum_repositories"]) == 2, integer(fields["maximum_repositories"]) == 16,
                          integer(fields["maximum_workers"]) == 4,
                          try strings(fields["modes"]) == ["none"],
                          try strings(fields["request_fields"]).isSuperset(of: ["repositories", "max_workers"]),
                          try strings(fields["events"]).isSuperset(of: ["fleet_child", "fleet_terminal"])
                    else { throw Invalid.malformed }
                    if schemas.contains("1.4") { fleet.insert("1.4") }
                }
            }
            let snapshot = DesktopCapabilitySnapshot(schemaVersions: schemas, scanOptions: scan, providerOptions: provider,
                modes: modes, providers: providers,
                expectedIdentityJSON: try JSONSerialization.data(withJSONObject: identity, options: [.sortedKeys]), fleetSchemas: fleet)
            return .init(status: .compatible, snapshot: snapshot)
        } catch { return .init(status: .malformed, snapshot: nil) }
    }

    /// Decodes the inert payload of a matched completed action envelope. An
    /// arbitrary JSON file is not proof that any engine preflight executed.
    static func decodePreflight(_ data: Data) -> DesktopPreflightResult {
        do {
            let value = try object(data, limit: 1024 * 1024)
            let known: Set<String> = ["compatible", "malformed", "incompatible_capabilities_schema", "legacy_engine_unsupported",
                "engine_changed", "missing_desktop_commands", "incompatible_run_schema", "unsupported_request"]
            guard let supported = boolean(value["supported"]), let status = value["status"] as? String,
                  known.contains(status), supported == (status == "compatible") else { throw Invalid.malformed }
            return .init(supported: supported, status: status)
        } catch { return .init(supported: false, status: "malformed") }
    }

    fileprivate static func object(_ data: Data, limit: Int) throws -> [String: Any] {
        guard !data.isEmpty, data.count <= limit else { throw Invalid.malformed }
        var scanner = UniqueKeys(bytes: Array(data))
        try scanner.value(depth: 0)
        scanner.whitespace()
        guard scanner.position == scanner.bytes.count,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw Invalid.malformed }
        return object
    }
    private static func integer(_ value: Any?) -> Int64? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
              let exact = Int64(number.stringValue) else { return nil }
        return exact
    }
    private static func boolean(_ value: Any?) -> Bool? {
        guard let number = value as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else { return nil }
        return number.boolValue
    }
    private static func validHash(_ value: String) -> Bool {
        value.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    private static func strings(_ value: Any?) throws -> Set<String> {
        guard let values = value as? [String], values.count <= 1024,
              values.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 4096 && !$0.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) }),
              Set(values).count == values.count else { throw Invalid.malformed }
        return Set(values)
    }
    private static func schemaMap(_ value: Any?) throws -> [String: Set<String>] {
        guard let value else { return [:] }
        guard let object = value as? [String: Any], object.count <= 1024 else { throw Invalid.malformed }
        return try object.mapValues { try strings($0) }
    }

    /// Foundation otherwise accepts duplicate JSON keys. Inspect syntax without
    /// keeping values; JSONSerialization remains the authoritative JSON parser.
    private struct UniqueKeys {
        let bytes: [UInt8]
        var position = 0
        mutating func whitespace() { while position < bytes.count && [9, 10, 13, 32].contains(bytes[position]) { position += 1 } }
        mutating func string() throws -> String {
            whitespace()
            guard position < bytes.count, bytes[position] == 34 else { throw Invalid.malformed }
            let start = position
            position += 1
            while position < bytes.count {
                let byte = bytes[position]; position += 1
                if byte == 92 { guard position < bytes.count else { throw Invalid.malformed }; position += 1 }
                else if byte == 34 { return try JSONDecoder().decode(String.self, from: Data(bytes[start..<position])) }
            }
            throw Invalid.malformed
        }
        mutating func value(depth: Int) throws {
            whitespace()
            guard depth <= 64, position < bytes.count else { throw Invalid.malformed }
            let first = bytes[position]
            if first == 34 { _ = try string(); return }
            if first == 123 {
                position += 1; whitespace(); var keys = Set<String>()
                if position < bytes.count && bytes[position] == 125 { position += 1; return }
                while true {
                    let key = try string()
                    guard keys.insert(key).inserted else { throw Invalid.malformed }
                    whitespace(); guard position < bytes.count && bytes[position] == 58 else { throw Invalid.malformed }
                    position += 1; try value(depth: depth + 1); whitespace()
                    guard position < bytes.count else { throw Invalid.malformed }
                    let delimiter = bytes[position]; position += 1
                    if delimiter == 125 { return }
                    guard delimiter == 44 else { throw Invalid.malformed }
                }
            }
            if first == 91 {
                position += 1; whitespace()
                if position < bytes.count && bytes[position] == 93 { position += 1; return }
                while true {
                    try value(depth: depth + 1); whitespace(); guard position < bytes.count else { throw Invalid.malformed }
                    let delimiter = bytes[position]; position += 1
                    if delimiter == 93 { return }
                    guard delimiter == 44 else { throw Invalid.malformed }
                }
            }
            let start = position
            while position < bytes.count && ![9, 10, 13, 32, 44, 93, 125].contains(bytes[position]) { position += 1 }
            guard position > start else { throw Invalid.malformed }
        }
    }
}
