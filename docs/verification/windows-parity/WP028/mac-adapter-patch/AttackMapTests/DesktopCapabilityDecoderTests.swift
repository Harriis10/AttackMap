import XCTest
@testable import AttackMap

final class DesktopCapabilityDecoderTests: XCTestCase {
    private func document(_ edit: (inout [String: Any]) -> Void = { _ in }) throws -> Data {
        var value: [String: Any] = [
            "schema": 1, "commands": ["desktop-worker", "desktop-action"],
            "engine_identity": ["path": "/usr/local/bin/python3", "size_bytes": 123,
                "runtime_kind": "Python", "sha256": String(repeating: "a", count: 64),
                "source_sha256": String(repeating: "b", count: 64), "future_identity": "retained"],
            "desktop": ["schema_versions": ["1.0", "1.1", "1.2", "1.3", "1.4"],
                "actions_schema_versions": ["1.1"], "operations": ["capabilities", "preflight"],
                "scan_options": ["cve"], "provider_options": ["model"],
                "modes": ["none", "review", "hunt", "hunt_verify", "remediate", "triage"],
                "providers": ["openai", "claude"], "multi_repo": false,
                "provider_options_by_schema": ["1.3": ["model", "max_calls"]],
                "modes_by_schema": ["1.3": ["none", "review", "hunt", "hunt_verify", "remediate", "triage"]],
                "fleet_by_schema": ["1.4": ["kind": "fleet_request", "multi_repo": true,
                    "minimum_repositories": 2, "maximum_repositories": 16, "maximum_workers": 4,
                    "modes": ["none"], "request_fields": ["repositories", "max_workers"],
                    "events": ["fleet_child", "fleet_terminal"]]]]]
        edit(&value)
        return try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
    }

    func testCurrentCapabilitiesKeepFleetSeparateAndAdvancedFieldsExplicit() throws {
        let result = DesktopCapabilityDecoder.decode(try document())
        XCTAssertTrue(result.supported)
        let snapshot = try XCTUnwrap(result.snapshot)
        XCTAssertEqual(snapshot.fleetSchemas, ["1.4"])
        XCTAssertTrue(snapshot.advertisesSingleRepository(schema: "1.3", scanFields: ["cve"], providerFields: ["max_calls"], mode: "hunt_verify", provider: "openai"))
        XCTAssertFalse(snapshot.advertisesSingleRepository(schema: "1.2", scanFields: [], providerFields: ["max_calls"], mode: "review", provider: "openai"))
        XCTAssertFalse(snapshot.advertisesSingleRepository(schema: "1.4", scanFields: [], providerFields: [], mode: "none", provider: "openai"))
        XCTAssertFalse(snapshot.advertisesSingleRepository(schema: "1.3", scanFields: ["invented"], providerFields: [], mode: "review", provider: "openai"))
    }

    func testAdvancedModesAreNotInferredFromGlobalLists() throws {
        let data = try document { root in
            var desktop = root["desktop"] as! [String: Any]
            desktop.removeValue(forKey: "modes_by_schema")
            root["desktop"] = desktop
        }
        let snapshot = try XCTUnwrap(DesktopCapabilityDecoder.decode(data).snapshot)
        XCTAssertFalse(snapshot.advertisesSingleRepository(schema: "1.3", scanFields: [], providerFields: [], mode: "hunt", provider: "openai"))
    }

    func testLegacyUnknownSchemaMissingCommandsAndMalformedIdentityFailClosed() throws {
        XCTAssertEqual(DesktopCapabilityDecoder.decode(try document { $0.removeValue(forKey: "desktop") }).status, .legacy)
        XCTAssertEqual(DesktopCapabilityDecoder.decode(try document { $0["schema"] = 2 }).status, .capabilitiesSchema)
        XCTAssertEqual(DesktopCapabilityDecoder.decode(try document { $0["commands"] = [] }).status, .commands)
        XCTAssertEqual(DesktopCapabilityDecoder.decode(try document { $0["engine_identity"] = ["path": "relative"] }).status, .malformed)
        XCTAssertEqual(DesktopCapabilityDecoder.decode(Data(#"{"schema":1,"schema":1}"#.utf8)).status, .malformed)
        XCTAssertEqual(DesktopCapabilityDecoder.decode(Data(#"{"schema":1,"\u0073chema":1}"#.utf8)).status, .malformed)
        XCTAssertEqual(DesktopCapabilityDecoder.decode(Data(repeating: 32, count: 4 * 1024 * 1024 + 1)).status, .malformed)
    }

    func testSharedRequestBytesAndCompleteIdentityAreRetainedInInertPreflight() throws {
        let snapshot = try XCTUnwrap(DesktopCapabilityDecoder.decode(try document()).snapshot)
        for name in ["request-current", "request-previous"] {
            let fixture = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
                .appendingPathComponent("Fixtures/DesktopParity/\(name).json")
            let request = try Data(contentsOf: fixture)
            let payload = try JSONSerialization.jsonObject(with: snapshot.preflightPayload(request: request)) as! [String: Any]
            let captured = payload["request"] as! NSDictionary
            XCTAssertEqual(captured, try JSONSerialization.jsonObject(with: request) as? NSDictionary)
            XCTAssertEqual((payload["expected_identity"] as? [String: Any])?["future_identity"] as? String, "retained")
        }
    }

    func testPreflightTruthIsExplicitAndNotAnExecutionAttestation() {
        XCTAssertTrue(DesktopCapabilityDecoder.decodePreflight(Data(#"{"supported":true,"status":"compatible"}"#.utf8)).supported)
        for text in [#"{"supported":false,"status":"engine_changed"}"#,
                     #"{"supported":true,"status":"engine_changed"}"#,
                     #"{"supported":1,"status":"compatible"}"#,
                     #"{"supported":true,"status":"future_status"}"#] {
            XCTAssertFalse(DesktopCapabilityDecoder.decodePreflight(Data(text.utf8)).supported)
        }
    }

    func testDesktopFailureDoesNotRewriteLegacyCLIProjection() {
        let legacy = CLILocator.StructuredCapabilities(schema: 1,
            analyze: .init(options: ["--triage", "--baseline"], multiRepo: true))
        let result = CLILocator.capabilities(from: legacy, desktopDocument: Data("{}".utf8))
        XCTAssertTrue(result.triage)
        XCTAssertTrue(result.baseline)
        XCTAssertTrue(result.fleet)
        XCTAssertFalse(result.progressJSON)
        XCTAssertEqual(result.desktop?.status, .malformed)
        XCTAssertNil(CLILocator.capabilities(from: legacy).desktop)
    }
}
