//
//  Copyright 2026 Readium Foundation. All rights reserved.
//  Use of this source code is governed by the BSD-style license
//  available in the top-level LICENSE file of the project.
//

@testable import ReadiumShared
import XCTest

/// Reads ZIP entries from a source that is not a local file, the way a
/// streamed (HTTP) package is read. Archives above 5 MB are not cached whole,
/// so entry reads reach the source.
class ZIPFoundationStreamedSourceTests: XCTestCase {
    private let entryLength = 10 * 1024 * 1024
    private var archiveURL: FileURL!

    override func setUpWithError() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("streamed-\(UUID().uuidString).zip")
        let entry = Data((0 ..< entryLength).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ $0 >> 8) })
        try StoredZIP.make(entryName: "big.bin", data: entry).write(to: url)
        archiveURL = FileURL(url: url)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: archiveURL.url)
    }

    /// A source that delivers fewer bytes than it reported must surface an
    /// error, not a silently shortened entry.
    func testReadFailsWhenSourceEndsBeforeItsReportedLength() async throws {
        // Past the 6 MB read-ahead filled when the archive is opened, so the
        // read below is fetched from the source rather than the buffer.
        let cutOff = UInt64(7 * 1024 * 1024)
        let source = CutOffResource(file: archiveURL, cutOff: cutOff)
        let container = try await ZIPFoundationContainer.make(resource: source).get()
        let entry = try XCTUnwrap(container[XCTUnwrap(AnyURL(path: "big.bin"))])

        let result = await entry.read(range: 6_500_000 ..< 7_500_000)

        guard
            case let .failure(.decoding(error)) = result,
            case let .shortRead(expected, received) = error as? ResourceDataSourceError
        else {
            return XCTFail("Expected a short-read decoding error, got \(result)")
        }
        XCTAssertGreaterThan(expected, received)
    }

    /// Reads reaching the real end of the source keep the clamping behavior
    /// the `Streamable` contract requires.
    func testReadOverlappingEntryEndIsClampedForStreamedSource() async throws {
        let source = CutOffResource(file: archiveURL, cutOff: nil)
        let container = try await ZIPFoundationContainer.make(resource: source).get()
        let entry = try XCTUnwrap(container[XCTUnwrap(AnyURL(path: "big.bin"))])
        let length = UInt64(entryLength)

        let data = try await entry.read(range: length - 10 ..< length + 100).get()

        XCTAssertEqual(data.count, 10)
    }
}

/// Serves a local file without exposing it as a file, and stops every read at
/// `cutOff` while still reporting the full length, as a server whose body
/// ends early would.
private final class CutOffResource: Resource {
    private let file: FileResource
    private let cutOff: UInt64?

    init(file: FileURL, cutOff: UInt64?) {
        self.file = FileResource(file: file)
        self.cutOff = cutOff
    }

    let sourceURL: AbsoluteURL? = nil

    func properties() async -> ReadResult<ResourceProperties> {
        .success(ResourceProperties())
    }

    func estimatedLength() async -> ReadResult<UInt64?> {
        await file.estimatedLength()
    }

    func stream(range: Range<UInt64>?, consume: @escaping (Data) -> Void) async -> ReadResult<Void> {
        guard let range, let cutOff, range.lowerBound < cutOff, range.upperBound > cutOff else {
            return await file.stream(range: range, consume: consume)
        }
        return await file.stream(range: range.lowerBound ..< cutOff, consume: consume)
    }
}

/// Builds a single-entry ZIP archive with a stored (uncompressed) entry.
private enum StoredZIP {
    static func make(entryName: String, data: Data) -> Data {
        let name = Data(entryName.utf8)
        let crc = crc32(data)
        var zip = Data()

        zip.append(le32: 0x0403_4B50)
        zip.append(le16: 20) // version needed
        zip.append(le16: 0) // flags
        zip.append(le16: 0) // stored
        zip.append(le16: 0) // time
        zip.append(le16: 0x21) // date
        zip.append(le32: crc)
        zip.append(le32: UInt32(data.count))
        zip.append(le32: UInt32(data.count))
        zip.append(le16: UInt16(name.count))
        zip.append(le16: 0) // extra length
        zip.append(name)
        zip.append(data)

        let centralDirectoryOffset = UInt32(zip.count)
        zip.append(le32: 0x0201_4B50)
        zip.append(le16: 20) // version made by
        zip.append(le16: 20) // version needed
        zip.append(le16: 0)
        zip.append(le16: 0)
        zip.append(le16: 0)
        zip.append(le16: 0x21)
        zip.append(le32: crc)
        zip.append(le32: UInt32(data.count))
        zip.append(le32: UInt32(data.count))
        zip.append(le16: UInt16(name.count))
        zip.append(le16: 0) // extra length
        zip.append(le16: 0) // comment length
        zip.append(le16: 0) // disk number
        zip.append(le16: 0) // internal attributes
        zip.append(le32: 0) // external attributes
        zip.append(le32: 0) // local header offset
        zip.append(name)
        let centralDirectorySize = UInt32(zip.count) - centralDirectoryOffset

        zip.append(le32: 0x0605_4B50)
        zip.append(le16: 0)
        zip.append(le16: 0)
        zip.append(le16: 1)
        zip.append(le16: 1)
        zip.append(le32: centralDirectorySize)
        zip.append(le32: centralDirectoryOffset)
        zip.append(le16: 0) // comment length
        return zip
    }

    private static func crc32(_ data: Data) -> UInt32 {
        let table: [UInt32] = (0 ..< 256).map { n in
            (0 ..< 8).reduce(UInt32(n)) { c, _ in c & 1 == 1 ? 0xEDB8_8320 ^ (c >> 1) : c >> 1 }
        }
        return ~data.reduce(~UInt32(0)) { c, byte in table[Int((c ^ UInt32(byte)) & 0xFF)] ^ (c >> 8) }
    }
}

private extension Data {
    mutating func append(le16 value: UInt16) {
        Swift.withUnsafeBytes(of: value.littleEndian) { append(contentsOf: $0) }
    }

    mutating func append(le32 value: UInt32) {
        Swift.withUnsafeBytes(of: value.littleEndian) { append(contentsOf: $0) }
    }
}
