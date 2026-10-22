//
//  Copyright 2026 Readium Foundation. All rights reserved.
//  Use of this source code is governed by the BSD-style license
//  available in the top-level LICENSE file of the project.
//

import CommonCrypto
import Foundation
@testable import ReadiumLCP
import ReadiumShared
import Testing

/// A CBC resource reads its last encrypted blocks to learn the plaintext
/// length, unless the caller supplies that length.
struct CBCKnownLengthTests {
    private let key = Data((0 ..< 32).map { UInt8($0) })
    private let iv = Data((0 ..< 16).map { UInt8(0xA0 + $0) })
    private let href = AnyURL(string: "track.mp3")!
    /// Larger than the 256 KB read buffer the decryptor reads through, so a
    /// read at the start cannot reach the end by buffering alone. Not a
    /// multiple of 16, so the last block carries real padding.
    private let clearData = Data((0 ..< 600_003).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ 7) })
    private let encryptedData: Data

    init() throws {
        encryptedData = try AESTestLicense.encrypt(clearData, key: key, iv: iv)
    }

    /// Start of the last two encrypted blocks, which hold the padding size.
    private var tailStart: UInt64 {
        UInt64(encryptedData.count) - 32
    }

    private func cbcResource(over source: Resource) throws -> KnownLengthAcceptingResource {
        let encryption = Encryption(
            algorithm: "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
            scheme: "http://readium.org/2014/01/lcp"
        )
        let decrypted = LCPDecryptor(license: AESTestLicense(key: key), encryptionData: [href: encryption])
            .decrypt(at: href, resource: source)
        return try #require(decrypted as? KnownLengthAcceptingResource)
    }

    /// Without a supplied length, reading the start of the content also reads
    /// the last encrypted blocks: the cost a supplied length removes.
    @Test func unknownLengthReadsTheTail() async throws {
        let source = ReadRecordingResource(data: encryptedData)
        let resource = try cbcResource(over: source)

        let head = try await resource.read(range: 0 ..< 2048).get()

        #expect(head == clearData[0 ..< 2048])
        #expect(await source.reads.contains { $0.upperBound > tailStart })
    }

    /// With the length supplied, reading the start of the content decrypts it
    /// without reading the last encrypted blocks.
    @Test func knownLengthSkipsTheTailRead() async throws {
        let source = ReadRecordingResource(data: encryptedData)
        let resource = try cbcResource(over: source).withKnownLength(UInt64(clearData.count))

        let head = try await resource.read(range: 0 ..< 2048).get()

        #expect(head == clearData[0 ..< 2048])
        #expect(await source.reads.allSatisfy { $0.upperBound <= tailStart })
    }

    /// The supplied length is the one reported, not a recomputed one.
    @Test func knownLengthIsTheReportedLength() async throws {
        let supplied = UInt64(clearData.count - 1)
        let resource = try cbcResource(over: ReadRecordingResource(data: encryptedData))
            .withKnownLength(supplied)

        #expect(try await resource.estimatedLength().get() == supplied)
    }

    /// The end of the content decrypts without its padding when the length is
    /// supplied rather than read from the last block.
    @Test func knownLengthDecryptsTheEnd() async throws {
        let resource = try cbcResource(over: ReadRecordingResource(data: encryptedData))
            .withKnownLength(UInt64(clearData.count))

        let whole = try await resource.read().get()
        let end = try await resource.read(
            range: UInt64(clearData.count - 100) ..< UInt64(clearData.count + 17)
        ).get()

        #expect(whole == clearData)
        #expect(end == clearData.suffix(100))
    }
}

/// Deciphers AES-256-CBC with a fixed key the way the LCP client does: the
/// first block is the IV and padding is left for the caller to remove.
private final class AESTestLicense: LCPLicense {
    private let key: Data

    init(key: Data) {
        self.key = key
    }

    static func encrypt(_ data: Data, key: Data, iv: Data) throws -> Data {
        try iv + crypt(CCOperation(kCCEncrypt), CCOptions(kCCOptionPKCS7Padding), data, key: key, iv: iv)
    }

    func decipher(_ data: Data) throws -> Data? {
        try Self.crypt(CCOperation(kCCDecrypt), 0, data.dropFirst(16), key: key, iv: data.prefix(16))
    }

    private static func crypt(_ operation: CCOperation, _ options: CCOptions, _ input: Data, key: Data, iv: Data) throws -> Data {
        let input = Data(input)
        let iv = Data(iv)
        var output = Data(count: input.count + kCCBlockSizeAES128)
        let capacity = output.count
        var written = 0
        let status = output.withUnsafeMutableBytes { out in
            input.withUnsafeBytes { inBytes in
                key.withUnsafeBytes { keyBytes in
                    iv.withUnsafeBytes { ivBytes in
                        CCCrypt(
                            operation, CCAlgorithm(kCCAlgorithmAES), options,
                            keyBytes.baseAddress, key.count, ivBytes.baseAddress,
                            inBytes.baseAddress, input.count,
                            out.baseAddress, capacity, &written
                        )
                    }
                }
            }
        }
        guard status == kCCSuccess else {
            throw AESTestError.cryptFailed(status)
        }
        return output.prefix(written)
    }

    var license: LicenseDocument {
        fatalError("Not read by the decryptor")
    }

    var status: StatusDocument? {
        nil
    }

    var isRestricted: Bool {
        false
    }

    var error: LCPError? {
        nil
    }

    var canRenewLoan: Bool {
        false
    }

    var maxRenewDate: Date? {
        nil
    }

    var canReturnPublication: Bool {
        false
    }

    func charactersToCopyLeft() async -> Int? {
        nil
    }

    func pagesToPrintLeft() async -> Int? {
        nil
    }

    func canCopy(text: String) async -> Bool {
        false
    }

    func copy(text: String) async -> Bool {
        false
    }

    func canPrint(pageCount: Int) async -> Bool {
        false
    }

    func print(pageCount: Int) async -> Bool {
        false
    }

    func renewLoan(with delegate: LCPRenewDelegate, prefersWebPage: Bool) async -> Result<Void, LCPError> {
        .success(())
    }

    func returnPublication() async -> Result<Void, LCPError> {
        .success(())
    }
}

private enum AESTestError: Error {
    case cryptFailed(CCCryptorStatus)
}

/// Serves `data` and records every range read from it.
private actor ReadRecordingResource: Resource {
    let sourceURL: AbsoluteURL? = nil
    private let data: Data
    private(set) var reads: [Range<UInt64>] = []

    init(data: Data) {
        self.data = data
    }

    func properties() async -> ReadResult<ResourceProperties> {
        .success(ResourceProperties())
    }

    func estimatedLength() async -> ReadResult<UInt64?> {
        .success(UInt64(data.count))
    }

    func stream(range: Range<UInt64>?, consume: @escaping (Data) -> Void) async -> ReadResult<Void> {
        let size = UInt64(data.count)
        let requested = range ?? 0 ..< size
        reads.append(requested)
        let lower = Int(min(requested.lowerBound, size))
        let upper = Int(min(requested.upperBound, size))
        consume(data.subdata(in: lower ..< upper))
        return .success(())
    }
}
