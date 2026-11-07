import XCTest
@testable import AttackMap

final class SelectedGenerationExportTests: XCTestCase {
    func testVerifiedCopyAndAtomicReplacementAreByteExact() throws {
        let fixture = try SelectionTestFixture(); defer { try? fixture.close() }
        let selected = try fixture.capture(); let artifact = try fixture.markdown(selected)
        let destination = fixture.root.appendingPathComponent("export.md")
        let expected = try SelectedGenerationReader.read(artifact, from: selected)
        try SelectedGenerationExport.copy(artifact, from: selected, to: destination)
        XCTAssertEqual(try Data(contentsOf: destination), expected)
        try Data("old export".utf8).write(to: destination)
        try SelectedGenerationExport.copy(artifact, from: selected, to: destination)
        XCTAssertEqual(try Data(contentsOf: destination), expected)
        XCTAssertFalse(try FileManager.default.contentsOfDirectory(atPath: fixture.root.path).contains { $0.hasPrefix(".attackmap-export-") })
    }
    func testSelfAndGenerationDestinationsAreRejectedWithoutMutation() throws {
        let fixture = try SelectionTestFixture(); defer { try? fixture.close() }
        let selected = try fixture.capture(); let artifact = try fixture.markdown(selected)
        let reportBytes = try Data(contentsOf: fixture.report)
        for destination in [fixture.report, fixture.generation.appendingPathComponent(artifact.path), fixture.generation.appendingPathComponent("new.md")] {
            XCTAssertThrowsError(try SelectedGenerationExport.copy(artifact, from: selected, to: destination))
        }
        XCTAssertEqual(try Data(contentsOf: fixture.report), reportBytes)
        XCTAssertFalse(FileManager.default.fileExists(atPath: fixture.generation.appendingPathComponent("new.md").path))
    }
    func testSymlinkAndHardlinkDestinationsPreserveTargets() throws {
        let fixture = try SelectionTestFixture(); defer { try? fixture.close() }
        let selected = try fixture.capture(); let artifact = try fixture.markdown(selected)
        let target = fixture.root.appendingPathComponent("keep.txt")
        try Data("preserve".utf8).write(to: target)
        let symlink = fixture.root.appendingPathComponent("symlink.md")
        try FileManager.default.createSymbolicLink(at: symlink, withDestinationURL: target)
        XCTAssertThrowsError(try SelectedGenerationExport.copy(artifact, from: selected, to: symlink))
        let hardlink = fixture.root.appendingPathComponent("hardlink.md")
        try FileManager.default.linkItem(at: target, to: hardlink)
        XCTAssertThrowsError(try SelectedGenerationExport.copy(artifact, from: selected, to: hardlink))
        XCTAssertEqual(try Data(contentsOf: target), Data("preserve".utf8))
    }
    func testSymlinkDestinationAncestorRejected() throws {
        let fixture = try SelectionTestFixture(); defer { try? fixture.close() }
        let selected = try fixture.capture(); let artifact = try fixture.markdown(selected)
        let real = fixture.root.appendingPathComponent("real", isDirectory: true)
        try FileManager.default.createDirectory(at: real, withIntermediateDirectories: true)
        let alias = fixture.root.appendingPathComponent("alias")
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: real)
        XCTAssertThrowsError(try SelectedGenerationExport.copy(artifact, from: selected, to: alias.appendingPathComponent("new.md")))
        XCTAssertFalse(FileManager.default.fileExists(atPath: real.appendingPathComponent("new.md").path))
    }
    func testTamperedSelectionPreservesExistingDestination() throws {
        let fixture = try SelectionTestFixture(); defer { try? fixture.close() }
        let selected = try fixture.capture(); let artifact = try fixture.markdown(selected)
        let destination = fixture.root.appendingPathComponent("keep.md")
        try Data("keep destination".utf8).write(to: destination)
        try Data("changed".utf8).write(to: fixture.generation.appendingPathComponent("artifact-manifest.json"))
        XCTAssertThrowsError(try SelectedGenerationExport.copy(artifact, from: selected, to: destination))
        XCTAssertEqual(try Data(contentsOf: destination), Data("keep destination".utf8))
        XCTAssertFalse(try FileManager.default.contentsOfDirectory(atPath: fixture.root.path).contains { $0.hasPrefix(".attackmap-export-") })
    }
    func testLegacySelectionCopiesOnlyCapturedJSONOutsideSourceDirectory() throws {
        let fixture = try SelectionTestFixture(); defer { try? fixture.close() }
        try FileManager.default.removeItem(at: fixture.generation.appendingPathComponent("artifact-manifest.json"))
        let selected = try fixture.capture(expectedRepository: nil, expectedGeneration: nil)
        let destination = fixture.root.appendingPathComponent("legacy-unverified.json")
        try SelectedGenerationExport.copy(selected.artifacts[0], from: selected, to: destination)
        XCTAssertEqual(try Data(contentsOf: destination), try Data(contentsOf: fixture.report))
        XCTAssertEqual(selected.provenance, .legacyUnverified)
    }
}
