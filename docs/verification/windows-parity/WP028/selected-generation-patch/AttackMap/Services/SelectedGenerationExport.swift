// SPDX-License-Identifier: MIT
import Foundation
import Darwin

/// Synchronous byte export only. The future native picker host must capture and
/// recheck its own selection epoch before invoking this primitive.
enum SelectedGenerationExport {
    static func copy(_ artifact: SelectedArtifact, from selection: SelectedGeneration, to destination: URL) throws {
        // Complete source verification occurs before any destination write.
        let content = try SelectedGenerationReader.read(artifact, from: selection)
        let name = try SelectionFiles.basename(destination.lastPathComponent)
        let directory = try SelectionFiles.directory(destination.deletingLastPathComponent())
        defer { Darwin.close(directory.fd) }
        let sourceDirectory = try SelectionFiles.directory(selection.reportURL.deletingLastPathComponent())
        defer { Darwin.close(sourceDirectory.fd) }
        guard !directory.ancestors.contains(sourceDirectory.identity.node) else { throw SelectedGenerationError.unsafePath }
        let previous = try SelectionFiles.metadataOptional(directory.fd, name)
        let temporary = ".attackmap-export-\(UUID().uuidString).tmp"
        let stage = Darwin.openat(directory.fd, temporary,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard stage >= 0 else { throw SelectedGenerationError.unavailable }
        var committed = false
        defer {
            Darwin.close(stage)
            if !committed { _ = Darwin.unlinkat(directory.fd, temporary, 0) }
        }
        let stageIdentity = try SelectionFiles.identity(stage)
        try content.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let written = Darwin.write(stage, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if written < 0 { if errno == EINTR { continue }; throw SelectedGenerationError.unavailable }
                guard written > 0 else { throw SelectedGenerationError.unavailable }
                offset += written
            }
        }
        guard Darwin.fsync(stage) == 0 else { throw SelectedGenerationError.unavailable }
        let finished = try SelectionFiles.identity(stage)
        guard finished.node == stageIdentity.node, finished.size == Int64(content.count),
              try SelectionFiles.metadata(directory.fd, temporary) == finished else { throw SelectedGenerationError.changed }
        // Verify that the original destination directory is still addressed by
        // its URL; all writes/rename remain anchored to the opened descriptor.
        let current = try SelectionFiles.directory(destination.deletingLastPathComponent())
        defer { Darwin.close(current.fd) }
        guard current.identity.node == directory.identity.node,
              try SelectionFiles.metadataOptional(directory.fd, name) == previous else { throw SelectedGenerationError.changed }
        let recheckedContent = try SelectedGenerationReader.read(artifact, from: selection)
        guard content == recheckedContent else { throw SelectedGenerationError.changed }
        let staged = try SelectionFiles.read(directory.fd, temporary, limit: SelectedGenerationReader.reportLimit)
        guard staged.identity == finished, staged.data == content else { throw SelectedGenerationError.changed }
        guard Darwin.renameat(directory.fd, temporary, directory.fd, name) == 0 else { throw SelectedGenerationError.unavailable }
        committed = true
        // This guarantees atomic visibility, not power-loss durability of the
        // directory entry; no post-commit error is reported as preserved output.
    }
}
