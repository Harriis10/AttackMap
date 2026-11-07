// SPDX-License-Identifier: MIT
// Additive preparation against AttackMap-mac 5f2e8b4d84f9dff06e0f87c69c861a434981bd6a.
import Foundation
import CryptoKit
import Darwin

enum SelectedGenerationError: Error {
    case unsafePath, unavailable, changed, malformedManifest, unsupportedManifest, oversized, unlistedArtifact
}

struct SelectedArtifact: Sendable, Equatable {
    let name: String
    let path: String
    let format: String
    let role: String
    let checksum: String
    fileprivate let identity: SelectionFileIdentity
}

struct SelectedGeneration: Sendable {
    enum Provenance: Sendable, Equatable { case legacyUnverified, manifestVerified }
    let reportURL: URL
    let reportSHA256: String
    let manifestURL: URL?
    let manifestSHA256: String?
    let generationID: String?
    let repositoryRoot: String?
    let artifacts: [SelectedArtifact]
    let provenance: Provenance
    fileprivate let directoryIdentity: SelectionFileIdentity
    fileprivate let reportIdentity: SelectionFileIdentity
    fileprivate let manifestIdentity: SelectionFileIdentity?

    fileprivate init(reportURL: URL, reportSHA256: String, manifestURL: URL?, manifestSHA256: String?,
        generationID: String?, repositoryRoot: String?, artifacts: [SelectedArtifact], provenance: Provenance,
        directoryIdentity: SelectionFileIdentity, reportIdentity: SelectionFileIdentity,
        manifestIdentity: SelectionFileIdentity?) {
        self.reportURL = reportURL; self.reportSHA256 = reportSHA256
        self.manifestURL = manifestURL; self.manifestSHA256 = manifestSHA256
        self.generationID = generationID; self.repositoryRoot = repositoryRoot
        self.artifacts = artifacts; self.provenance = provenance
        self.directoryIdentity = directoryIdentity; self.reportIdentity = reportIdentity
        self.manifestIdentity = manifestIdentity
    }
}

enum SelectedGenerationReader {
    static let reportLimit = 64 * 1024 * 1024
    static let manifestLimit = 1024 * 1024

    /// displayedReport must be the exact bytes passed to the report decoder.
    /// Manifest integrity is content identity, not producer authentication.
    static func capture(reportURL: URL, displayedReport: Data,
        expectedRepository: String?, expectedGeneration: String?) throws -> SelectedGeneration {
        guard displayedReport.count <= reportLimit else { throw SelectedGenerationError.oversized }
        let reportName = try SelectionFiles.basename(reportURL.lastPathComponent)
        guard reportURL.pathExtension == "json" else { throw SelectedGenerationError.unsafePath }
        let directory = try SelectionFiles.directory(reportURL.deletingLastPathComponent())
        defer { Darwin.close(directory.fd) }
        let report = try SelectionFiles.read(directory.fd, reportName, limit: reportLimit)
        guard report.data == displayedReport else { throw SelectedGenerationError.changed }
        let checksum = SelectionFiles.hash(displayedReport)
        let manifestName = "artifact-manifest.json"
        // Only ENOENT for this leaf permits legacy import. Invalid/present,
        // unreadable, redirected and unsupported manifests never downgrade.
        guard let manifest = try SelectionFiles.readOptional(directory.fd, manifestName, limit: manifestLimit) else {
            guard expectedGeneration == nil else { throw SelectedGenerationError.unavailable }
            let artifact = SelectedArtifact(name: "legacy_report", path: reportName, format: "json",
                role: "monolithic-legacy-report", checksum: checksum, identity: report.identity)
            return SelectedGeneration(reportURL: reportURL, reportSHA256: checksum, manifestURL: nil,
                manifestSHA256: nil, generationID: nil, repositoryRoot: nil, artifacts: [artifact],
                provenance: .legacyUnverified, directoryIdentity: directory.identity,
                reportIdentity: report.identity, manifestIdentity: nil)
        }
        let root = try SelectionJSON.object(manifest.data)
        guard root["schema_version"] as? String == "1.0.0",
              root["artifact_type"] as? String == "attackmap_artifact_manifest"
        else { throw SelectedGenerationError.unsupportedManifest }
        let generation = try text(root["generation_id"], max: 256)
        guard let run = root["run_identity"] as? [String: Any] else { throw SelectedGenerationError.malformedManifest }
        let repository = try text(run["repo_root"], max: 32768)
        guard expectedGeneration == nil || expectedGeneration == generation,
              expectedRepository == nil || expectedRepository == repository else { throw SelectedGenerationError.changed }
        guard let sections = root["sections"] as? [[String: Any]],
              let exports = root["compatibility_exports"] as? [[String: Any]],
              sections.count + exports.count <= 512 else { throw SelectedGenerationError.malformedManifest }
        var names = Set<String>(), paths = Set<String>(), identities = Set<SelectionNodeID>()
        var artifacts: [SelectedArtifact] = []
        let formats: Set<String> = ["json", "md", "sarif", "dot", "html", "txt", "svg"]
        for entry in sections + exports {
            let name = try text(entry["name"], max: 256)
            let path = try SelectionFiles.basename(text(entry["path"], max: 255))
            let format = try text(entry["format"], max: 16)
            let role = try text(entry["role"], max: 128)
            let hash = try text(entry["checksum"], max: 64)
            guard names.insert(name).inserted, paths.insert(path).inserted,
                  path != manifestName, formats.contains(format), URL(fileURLWithPath: path).pathExtension == format,
                  role.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 }),
                  hash.count == 64, hash.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) })
            else { throw SelectedGenerationError.malformedManifest }
            let identity = try SelectionFiles.metadata(directory.fd, path)
            guard identities.insert(identity.node).inserted else { throw SelectedGenerationError.unsafePath }
            artifacts.append(SelectedArtifact(name: name, path: path, format: format, role: role,
                checksum: hash, identity: identity))
        }
        let reportExports = exports.filter { $0["path"] as? String == reportName }
        guard reportExports.count == 1, let bound = artifacts.first(where: { $0.path == reportName }),
              bound.format == "json", bound.checksum == checksum, bound.identity == report.identity
        else { throw SelectedGenerationError.malformedManifest }
        // Catch replacement or mutation during metadata collection.
        try SelectionFiles.require(directory.fd, reportName, identity: report.identity, hash: checksum, limit: reportLimit)
        try SelectionFiles.require(directory.fd, manifestName, identity: manifest.identity,
            hash: SelectionFiles.hash(manifest.data), limit: manifestLimit)
        return SelectedGeneration(reportURL: reportURL, reportSHA256: checksum,
            manifestURL: reportURL.deletingLastPathComponent().appendingPathComponent(manifestName),
            manifestSHA256: SelectionFiles.hash(manifest.data), generationID: generation,
            repositoryRoot: repository, artifacts: artifacts, provenance: .manifestVerified,
            directoryIdentity: directory.identity, reportIdentity: report.identity, manifestIdentity: manifest.identity)
    }

    static func read(_ artifact: SelectedArtifact, from selection: SelectedGeneration) throws -> Data {
        guard selection.artifacts.contains(artifact) else { throw SelectedGenerationError.unlistedArtifact }
        let directory = try checkedDirectory(selection)
        defer { Darwin.close(directory.fd) }
        try validate(selection, directory: directory.fd)
        let result = try SelectionFiles.read(directory.fd, artifact.path, limit: reportLimit)
        guard result.identity == artifact.identity, SelectionFiles.hash(result.data) == artifact.checksum
        else { throw SelectedGenerationError.changed }
        try validate(selection, directory: directory.fd)
        return result.data
    }

    static func validate(_ selection: SelectedGeneration) throws {
        let directory = try checkedDirectory(selection)
        defer { Darwin.close(directory.fd) }
        try validate(selection, directory: directory.fd)
    }

    private static func checkedDirectory(_ selection: SelectedGeneration) throws -> SelectionDirectory {
        let directory = try SelectionFiles.directory(selection.reportURL.deletingLastPathComponent())
        guard directory.identity.node == selection.directoryIdentity.node else {
            Darwin.close(directory.fd); throw SelectedGenerationError.changed
        }
        return directory
    }
    private static func validate(_ selection: SelectedGeneration, directory: Int32) throws {
        try SelectionFiles.require(directory, selection.reportURL.lastPathComponent,
            identity: selection.reportIdentity, hash: selection.reportSHA256, limit: reportLimit)
        if let manifestIdentity = selection.manifestIdentity, let hash = selection.manifestSHA256 {
            try SelectionFiles.require(directory, "artifact-manifest.json", identity: manifestIdentity, hash: hash, limit: manifestLimit)
        } else if try SelectionFiles.metadataOptional(directory, "artifact-manifest.json") != nil {
            throw SelectedGenerationError.changed
        }
    }
    private static func text(_ value: Any?, max: Int) throws -> String {
        guard let value = value as? String, !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, value.utf8.count <= max,
              !value.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
        else { throw SelectedGenerationError.malformedManifest }
        return value
    }
}

// Internal descriptor helpers shared by the independent export primitive.
struct SelectionNodeID: Sendable, Hashable { let device: Int64; let inode: UInt64 }
struct SelectionFileIdentity: Sendable, Equatable {
    let node: SelectionNodeID
    let size: Int64
    let modifiedSeconds: Int64; let modifiedNanos: Int64
    let changedSeconds: Int64; let changedNanos: Int64
}
struct SelectionDirectory { let fd: Int32; let identity: SelectionFileIdentity; let ancestors: [SelectionNodeID] }

enum SelectionFiles {
    static func hash(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    static func basename(_ value: String) throws -> String {
        guard !value.isEmpty, value.utf8.count <= 255, value != ".", value != "..",
              value.last != ".", value.last != " ",
              !value.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains),
              !value.contains(where: { "\\/:*?\"<>|".contains($0) }) else { throw SelectedGenerationError.unsafePath }
        return value
    }
    static func directory(_ url: URL) throws -> SelectionDirectory {
        guard url.isFileURL, url.host == nil || url.host == "" || url.host == "localhost",
              url.path.hasPrefix("/"), !url.path.contains("\0") else { throw SelectedGenerationError.unsafePath }
        let parts = url.path.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
        guard !parts.contains("."), !parts.contains("..") else { throw SelectedGenerationError.unsafePath }
        var fd = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard fd >= 0 else { throw SelectedGenerationError.unavailable }
        do {
            var ancestors = [try identity(fd, directory: true).node]
            for part in parts {
                let next = Darwin.openat(fd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard next >= 0 else { throw SelectedGenerationError.unsafePath }
                Darwin.close(fd); fd = next
                ancestors.append(try identity(fd, directory: true).node)
            }
            return SelectionDirectory(fd: fd, identity: try identity(fd, directory: true), ancestors: ancestors)
        } catch { Darwin.close(fd); throw error }
    }
    static func identity(_ fd: Int32, directory: Bool = false) throws -> SelectionFileIdentity {
        var info = stat()
        guard Darwin.fstat(fd, &info) == 0 else { throw SelectedGenerationError.unavailable }
        let kind = info.st_mode & mode_t(S_IFMT)
        guard kind == mode_t(directory ? S_IFDIR : S_IFREG), directory || info.st_nlink == 1,
              info.st_size >= 0 else { throw SelectedGenerationError.unsafePath }
        return SelectionFileIdentity(node: SelectionNodeID(device: Int64(info.st_dev), inode: UInt64(info.st_ino)),
            size: Int64(info.st_size), modifiedSeconds: Int64(info.st_mtimespec.tv_sec), modifiedNanos: Int64(info.st_mtimespec.tv_nsec),
            changedSeconds: Int64(info.st_ctimespec.tv_sec), changedNanos: Int64(info.st_ctimespec.tv_nsec))
    }
    static func metadataOptional(_ directory: Int32, _ name: String) throws -> SelectionFileIdentity? {
        let fd = Darwin.openat(directory, try basename(name), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        if fd < 0 { if errno == ENOENT { return nil }; throw SelectedGenerationError.unsafePath }
        defer { Darwin.close(fd) }
        return try identity(fd)
    }
    static func metadata(_ directory: Int32, _ name: String) throws -> SelectionFileIdentity {
        guard let result = try metadataOptional(directory, name) else { throw SelectedGenerationError.unavailable }
        return result
    }
    static func readOptional(_ directory: Int32, _ name: String, limit: Int) throws -> (data: Data, identity: SelectionFileIdentity)? {
        let fd = Darwin.openat(directory, try basename(name), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        if fd < 0 { if errno == ENOENT { return nil }; throw SelectedGenerationError.unsafePath }
        defer { Darwin.close(fd) }
        let before = try identity(fd)
        guard before.size <= Int64(limit) else { throw SelectedGenerationError.oversized }
        var data = Data(); var buffer = [UInt8](repeating: 0, count: 16384)
        while true {
            let count = buffer.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
            if count < 0 { if errno == EINTR { continue }; throw SelectedGenerationError.unavailable }
            if count == 0 { break }
            guard data.count + count <= limit else { throw SelectedGenerationError.oversized }
            data.append(contentsOf: buffer.prefix(count))
        }
        guard try identity(fd) == before, Int64(data.count) == before.size,
              try metadata(directory, name) == before else { throw SelectedGenerationError.changed }
        return (data, before)
    }
    static func read(_ directory: Int32, _ name: String, limit: Int) throws -> (data: Data, identity: SelectionFileIdentity) {
        guard let result = try readOptional(directory, name, limit: limit) else { throw SelectedGenerationError.unavailable }
        return result
    }
    static func require(_ directory: Int32, _ name: String, identity: SelectionFileIdentity, hash: String, limit: Int) throws {
        let result = try read(directory, name, limit: limit)
        guard result.identity == identity, Self.hash(result.data) == hash else { throw SelectedGenerationError.changed }
    }
}

/// Bounded duplicate-key check before Foundation decoding. All unknown additive
/// fields remain inert; no caller can deserialize a forged selection record.
private enum SelectionJSON {
    static func object(_ data: Data) throws -> [String: Any] {
        guard !data.isEmpty, data.count <= SelectedGenerationReader.manifestLimit else { throw SelectedGenerationError.oversized }
        var keys = Keys(bytes: Array(data)); try keys.value(depth: 0); keys.space()
        guard keys.offset == keys.bytes.count,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { throw SelectedGenerationError.malformedManifest }
        return object
    }
    private struct Keys {
        let bytes: [UInt8]; var offset = 0
        mutating func space() { while offset < bytes.count && [9, 10, 13, 32].contains(bytes[offset]) { offset += 1 } }
        mutating func string() throws -> String {
            space(); guard offset < bytes.count, bytes[offset] == 34 else { throw SelectedGenerationError.malformedManifest }
            let start = offset; offset += 1
            while offset < bytes.count {
                let byte = bytes[offset]; offset += 1
                if byte == 92 { guard offset < bytes.count else { throw SelectedGenerationError.malformedManifest }; offset += 1 }
                else if byte == 34 { return try JSONDecoder().decode(String.self, from: Data(bytes[start..<offset])) }
            }
            throw SelectedGenerationError.malformedManifest
        }
        mutating func value(depth: Int) throws {
            space(); guard depth <= 64, offset < bytes.count else { throw SelectedGenerationError.malformedManifest }
            let first = bytes[offset]
            if first == 34 { _ = try string(); return }
            if first == 123 {
                offset += 1; space(); var seen = Set<String>()
                if offset < bytes.count && bytes[offset] == 125 { offset += 1; return }
                while true {
                    let key = try string(); guard seen.insert(key).inserted else { throw SelectedGenerationError.malformedManifest }
                    space(); guard offset < bytes.count, bytes[offset] == 58 else { throw SelectedGenerationError.malformedManifest }
                    offset += 1; try value(depth: depth + 1); space()
                    guard offset < bytes.count else { throw SelectedGenerationError.malformedManifest }
                    let delimiter = bytes[offset]; offset += 1
                    if delimiter == 125 { return }; guard delimiter == 44 else { throw SelectedGenerationError.malformedManifest }
                }
            }
            if first == 91 {
                offset += 1; space(); if offset < bytes.count && bytes[offset] == 93 { offset += 1; return }
                while true {
                    try value(depth: depth + 1); space(); guard offset < bytes.count else { throw SelectedGenerationError.malformedManifest }
                    let delimiter = bytes[offset]; offset += 1
                    if delimiter == 93 { return }; guard delimiter == 44 else { throw SelectedGenerationError.malformedManifest }
                }
            }
            let start = offset
            while offset < bytes.count && ![9, 10, 13, 32, 44, 93, 125].contains(bytes[offset]) { offset += 1 }
            guard offset > start else { throw SelectedGenerationError.malformedManifest }
        }
    }
}
