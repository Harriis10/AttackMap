import XCTest
@testable import AttackMap

final class SelectionTestFixture {
    let root: URL
    let generation: URL
    let report: URL
    static let repository = "C:/synthetic/team-a/sample"
    static let run = "wp028-owned-generation"

    init() throws {
        root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
            .appendingPathComponent("attackmap-selection-\(UUID().uuidString)", isDirectory: true)
        generation = root.appendingPathComponent("generation", isDirectory: true)
        report = generation.appendingPathComponent("attackmap-report.json")
        try FileManager.default.createDirectory(at: generation, withIntermediateDirectories: true)
        let fixtures = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .appendingPathComponent("Fixtures/SelectedGeneration/current", isDirectory: true)
        for source in try FileManager.default.contentsOfDirectory(at: fixtures, includingPropertiesForKeys: nil) {
            try FileManager.default.copyItem(at: source, to: generation.appendingPathComponent(source.lastPathComponent))
        }
    }
    func close() throws {
        guard root.lastPathComponent.hasPrefix("attackmap-selection-"),
              UUID(uuidString: String(root.lastPathComponent.dropFirst("attackmap-selection-".count))) != nil
        else { throw SelectedGenerationError.unsafePath }
        try FileManager.default.removeItem(at: root)
    }
    func capture(expectedRepository: String? = SelectionTestFixture.repository,
                 expectedGeneration: String? = SelectionTestFixture.run) throws -> SelectedGeneration {
        try SelectedGenerationReader.capture(reportURL: report, displayedReport: Data(contentsOf: report),
            expectedRepository: expectedRepository, expectedGeneration: expectedGeneration)
    }
    func changeManifest(_ edit: (inout [String: Any]) -> Void) throws {
        let url = generation.appendingPathComponent("artifact-manifest.json")
        var value = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
        edit(&value)
        try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]).write(to: url)
    }
    func markdown(_ selection: SelectedGeneration) throws -> SelectedArtifact {
        try XCTUnwrap(selection.artifacts.first { $0.path == "defensive-review.md" })
    }
}

final class SelectedGenerationTests: XCTestCase {
    func testProducerFixtureBindsExactReportIdentityAndPreservesOrder() throws {
        let fixture = try SelectionTestFixture(); defer { try? fixture.close() }
        let selected = try fixture.capture()
        XCTAssertEqual(selected.provenance, .manifestVerified)
        XCTAssertEqual(selected.generationID, SelectionTestFixture.run)
        XCTAssertEqual(selected.repositoryRoot, SelectionTestFixture.repository)
        XCTAssertEqual(Array(selected.artifacts.prefix(6).map(\.path)),
            ["scan.json", "findings.json", "attack_paths.json", "attack_surfaces.json", "exploitability.json", "suppressed_findings.json"])
        XCTAssertEqual(try SelectedGenerationReader.read(try fixture.markdown(selected), from: selected),
            Data("# Synthetic defensive review\n\nFixture only; no scan or provider executed.\n".utf8))
    }
    func testAbsentManifestIsExplicitLegacyReportOnly() throws {
        let fixture = try SelectionTestFixture(); defer { try? fixture.close() }
        try FileManager.default.removeItem(at: fixture.generation.appendingPathComponent("artifact-manifest.json"))
        let selected = try fixture.capture(expectedRepository: nil, expectedGeneration: nil)
        XCTAssertEqual(selected.provenance, .legacyUnverified)
        XCTAssertNil(selected.generationID)
        XCTAssertEqual(selected.artifacts.map(\.path), ["attackmap-report.json"])
        XCTAssertEqual(try SelectedGenerationReader.read(selected.artifacts[0], from: selected), try Data(contentsOf: fixture.report))
        XCTAssertThrowsError(try fixture.capture()) // live expected generation cannot downgrade
    }
    func testInvalidPresentManifestNeverDowngrades() throws {
        for content in ["{}", "not JSON", #"{"schema_version":"1.0.0","schema_version":"1.0.0"}"#,
                        #"{"schema_version":"1.0.0","\u0073chema_version":"1.0.0"}"#] {
            let fixture = try SelectionTestFixture(); defer { try? fixture.close() }
            try Data(content.utf8).write(to: fixture.generation.appendingPathComponent("artifact-manifest.json"))
            XCTAssertThrowsError(try fixture.capture(expectedRepository: nil, expectedGeneration: nil))
        }
    }
    func testUnknownSchemaGenerationRepositoryAndDisplayedByteMismatchFail() throws {
        let fixture = try SelectionTestFixture(); defer { try? fixture.close() }
        XCTAssertThrowsError(try fixture.capture(expectedRepository: "another"))
        XCTAssertThrowsError(try fixture.capture(expectedGeneration: "another"))
        XCTAssertThrowsError(try SelectedGenerationReader.capture(reportURL: fixture.report,
            displayedReport: Data("{}".utf8), expectedRepository: nil, expectedGeneration: nil))
        try fixture.changeManifest { $0["schema_version"] = "2.0.0" }
        XCTAssertThrowsError(try fixture.capture())
    }
    func testDuplicateAndUnsafeManifestPathsFail() throws {
        for path in ["../outside.json", "/outside.json", "folder/file.json", "folder\\file.json", "artifact-manifest.json", ".", ".."] {
            let fixture = try SelectionTestFixture(); defer { try? fixture.close() }
            try fixture.changeManifest { root in
                var exports = root["compatibility_exports"] as! [[String: Any]]
                exports[0]["path"] = path; root["compatibility_exports"] = exports
            }
            XCTAssertThrowsError(try fixture.capture())
        }
        let fixture = try SelectionTestFixture(); defer { try? fixture.close() }
        try fixture.changeManifest { root in
            var exports = root["compatibility_exports"] as! [[String: Any]]
            exports.append(exports[0]); root["compatibility_exports"] = exports
        }
        XCTAssertThrowsError(try fixture.capture())
    }
    func testManifestAndReportChangesInvalidateCapturedSelection() throws {
        for target in ["artifact-manifest.json", "attackmap-report.json"] {
            let fixture = try SelectionTestFixture(); defer { try? fixture.close() }
            let selected = try fixture.capture(); let markdown = try fixture.markdown(selected)
            try Data("changed".utf8).write(to: fixture.generation.appendingPathComponent(target))
            XCTAssertThrowsError(try SelectedGenerationReader.read(markdown, from: selected))
        }
    }
    func testSameBytesAtReplacedArtifactPathAreStale() throws {
        let fixture = try SelectionTestFixture(); defer { try? fixture.close() }
        let selected = try fixture.capture(); let artifact = try fixture.markdown(selected)
        let path = fixture.generation.appendingPathComponent(artifact.path)
        let bytes = try Data(contentsOf: path)
        try FileManager.default.moveItem(at: path, to: fixture.root.appendingPathComponent("old.md"))
        try bytes.write(to: path)
        XCTAssertThrowsError(try SelectedGenerationReader.read(artifact, from: selected))
    }
    func testArtifactTamperMissingAndUnlistedAdjacentFilesAreRejected() throws {
        let first = try SelectionTestFixture(); defer { try? first.close() }
        let other = try SelectionTestFixture(); defer { try? other.close() }
        let selected = try first.capture(); let artifact = try first.markdown(selected)
        XCTAssertThrowsError(try SelectedGenerationReader.read(try other.markdown(other.capture()), from: selected))
        let url = first.generation.appendingPathComponent(artifact.path)
        try Data("tampered".utf8).write(to: url)
        XCTAssertThrowsError(try SelectedGenerationReader.read(artifact, from: selected))
        try FileManager.default.removeItem(at: url)
        XCTAssertThrowsError(try first.capture())
    }
    func testSymlinkLeafAncestorBrokenManifestAndSourceHardlinkRejected() throws {
        let fixture = try SelectionTestFixture(); defer { try? fixture.close() }
        let selected = try fixture.capture(); let artifact = try fixture.markdown(selected)
        let leaf = fixture.generation.appendingPathComponent(artifact.path)
        let moved = fixture.root.appendingPathComponent("original.md")
        try FileManager.default.moveItem(at: leaf, to: moved)
        try FileManager.default.createSymbolicLink(at: leaf, withDestinationURL: moved)
        XCTAssertThrowsError(try SelectedGenerationReader.read(artifact, from: selected))
        let alias = fixture.root.appendingPathComponent("alias")
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: fixture.generation)
        XCTAssertThrowsError(try SelectedGenerationReader.capture(reportURL: alias.appendingPathComponent("attackmap-report.json"),
            displayedReport: Data(contentsOf: fixture.report), expectedRepository: nil, expectedGeneration: nil))
        try FileManager.default.removeItem(at: leaf)
        try FileManager.default.linkItem(at: moved, to: leaf)
        XCTAssertThrowsError(try fixture.capture())
        let manifest = fixture.generation.appendingPathComponent("artifact-manifest.json")
        try FileManager.default.removeItem(at: manifest)
        try FileManager.default.createSymbolicLink(at: manifest, withDestinationURL: fixture.root.appendingPathComponent("absent"))
        XCTAssertThrowsError(try fixture.capture(expectedRepository: nil, expectedGeneration: nil))
    }
    func testManifestSizeBoundAndNewManifestInvalidateLegacySelection() throws {
        let fixture = try SelectionTestFixture(); defer { try? fixture.close() }
        let manifest = fixture.generation.appendingPathComponent("artifact-manifest.json")
        let original = try Data(contentsOf: manifest)
        try Data(repeating: 32, count: SelectedGenerationReader.manifestLimit + 1).write(to: manifest)
        XCTAssertThrowsError(try fixture.capture())
        try FileManager.default.removeItem(at: manifest)
        let legacy = try fixture.capture(expectedRepository: nil, expectedGeneration: nil)
        try original.write(to: manifest)
        XCTAssertThrowsError(try SelectedGenerationReader.read(legacy.artifacts[0], from: legacy))
    }

    func testNonregularAndOversizedArtifactsAreRejected() throws {
        let fixture = try SelectionTestFixture(); defer { try? fixture.close() }
        let leaf = fixture.generation.appendingPathComponent("defensive-review.md")
        try FileManager.default.removeItem(at: leaf)
        try FileManager.default.createDirectory(at: leaf, withIntermediateDirectories: false)
        XCTAssertThrowsError(try fixture.capture())
        try FileManager.default.removeItem(at: leaf)
        XCTAssertTrue(FileManager.default.createFile(atPath: leaf.path, contents: Data()))
        let handle = try FileHandle(forWritingTo: leaf)
        try handle.truncate(atOffset: UInt64(SelectedGenerationReader.reportLimit + 1))
        try handle.close()
        let selected = try fixture.capture()
        XCTAssertThrowsError(try SelectedGenerationReader.read(try fixture.markdown(selected), from: selected)) { error in
            guard let typed = error as? SelectedGenerationError, case .oversized = typed else { return XCTFail("Expected bounded read rejection") }
        }
    }
}
