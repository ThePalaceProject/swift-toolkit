//
//  Copyright 2026 Readium Foundation. All rights reserved.
//  Use of this source code is governed by the BSD-style license
//  available in the top-level LICENSE file of the project.
//

@testable import ReadiumShared
import XCTest

class HTTPResourceTests: XCTestCase {
    private let url = HTTPURL(string: "https://example.com/book.lcpa")!
    private let content = Data((0 ..< 1000).map { UInt8($0 % 251) })

    /// A body that ends before its Content-Length is resumed from the first
    /// missing byte, so callers receive every byte exactly once.
    func testReadResumesWhenBodyEndsBeforeContentLength() async throws {
        let client = ScriptedHTTPClient(url: url, replies: [
            .init(status: .partialContent, headers: ["Content-Length": "1000"], body: content[0 ..< 600]),
            .init(status: .partialContent, headers: ["Content-Length": "400"], body: content[600 ..< 1000]),
        ])
        let resource = HTTPResource(url: url, client: client)

        let data = try await resource.read(range: 0 ..< 1000).get()

        XCTAssertEqual(data, content)
        XCTAssertEqual(client.ranges, ["bytes=0-999", "bytes=600-999"])
    }

    /// A resource read without a range resumes with a range starting at the
    /// number of bytes already delivered.
    func testFullReadResumesFromDeliveredOffset() async throws {
        let client = ScriptedHTTPClient(url: url, replies: [
            .init(status: .ok, headers: ["Content-Length": "1000"], body: content[0 ..< 600]),
            .init(status: .partialContent, headers: ["Content-Length": "400"], body: content[600 ..< 1000]),
        ])
        let resource = HTTPResource(url: url, client: client)

        let data = try await resource.read().get()

        XCTAssertEqual(data, content)
        XCTAssertEqual(client.ranges, [nil, "bytes=600-999"])
    }

    /// A body that is still short after one resume fails with a truncation
    /// error instead of handing a short read to the caller.
    func testReadFailsWhenResumedBodyIsAlsoShort() async throws {
        let client = ScriptedHTTPClient(url: url, replies: [
            .init(status: .partialContent, headers: ["Content-Length": "1000"], body: content[0 ..< 600]),
            .init(status: .partialContent, headers: ["Content-Length": "400"], body: content[600 ..< 700]),
            .init(status: .partialContent, headers: ["Content-Length": "300"], body: content[700 ..< 1000]),
        ])
        let resource = HTTPResource(url: url, client: client)

        let result = await resource.read(range: 0 ..< 1000)

        let error = try XCTUnwrap(truncation(in: result))
        XCTAssertEqual(error.expected, 400)
        XCTAssertEqual(error.received, 100)
        XCTAssertEqual(client.ranges.count, 2)
    }

    /// A resume answered with the whole resource instead of the requested
    /// range is rejected, so earlier bytes are never delivered twice.
    func testReadFailsWhenResumeIgnoresRange() async throws {
        let client = ScriptedHTTPClient(url: url, replies: [
            .init(status: .partialContent, headers: ["Content-Length": "1000"], body: content[0 ..< 600]),
            .init(status: .ok, headers: ["Content-Length": "1000"], body: content),
        ])
        let resource = HTTPResource(url: url, client: client)
        var delivered = Data()

        let result = await resource.stream(range: 0 ..< 1000) { delivered.append($0) }

        XCTAssertNotNil(truncation(in: result))
        XCTAssertEqual(delivered, content[0 ..< 600])
    }

    /// Only a 206 response carries the requested range, even when another
    /// response happens to have the expected length.
    func testReadFailsWhenResumeIsNotAPartialResponse() async throws {
        let client = ScriptedHTTPClient(url: url, replies: [
            .init(status: .partialContent, headers: ["Content-Length": "1000"], body: content[0 ..< 600]),
            .init(status: .ok, headers: ["Content-Length": "400"], body: content[0 ..< 400]),
        ])
        let resource = HTTPResource(url: url, client: client)

        let result = await resource.read(range: 0 ..< 1000)

        XCTAssertNotNil(truncation(in: result))
    }

    /// A read cancelled while its body was arriving is not resumed.
    func testReadIsNotResumedAfterCancellation() async throws {
        let client = ScriptedHTTPClient(url: url, replies: [
            .init(status: .partialContent, headers: ["Content-Length": "1000"], body: content[0 ..< 600], cancelsReader: true),
            .init(status: .partialContent, headers: ["Content-Length": "400"], body: content[600 ..< 1000]),
        ])
        let resource = HTTPResource(url: url, client: client)

        let result = await Task { await resource.read(range: 0 ..< 1000) }.value

        guard case .failure(.cancelled) = result else {
            return XCTFail("Expected a cancellation, got \(result)")
        }
        XCTAssertEqual(client.ranges.count, 1)
    }

    func testCompleteBodyIsReadWithOneRequest() async throws {
        let client = ScriptedHTTPClient(url: url, replies: [
            .init(status: .partialContent, headers: ["Content-Length": "1000"], body: content),
        ])
        let resource = HTTPResource(url: url, client: client)

        let data = try await resource.read(range: 0 ..< 1000).get()

        XCTAssertEqual(data, content)
        XCTAssertEqual(client.ranges.count, 1)
    }

    /// A server may answer a range overlapping the end of the resource with
    /// fewer bytes; its Content-Length says so, and that is not a truncation.
    func testRangeClampedByServerIsNotATruncation() async throws {
        let client = ScriptedHTTPClient(url: url, replies: [
            .init(status: .partialContent, headers: ["Content-Length": "100"], body: content[900 ..< 1000]),
        ])
        let resource = HTTPResource(url: url, client: client)

        let data = try await resource.read(range: 900 ..< 1100).get()

        XCTAssertEqual(data, content[900 ..< 1000])
        XCTAssertEqual(client.ranges.count, 1)
    }

    /// URLSession decodes a compressed body, so its length legitimately
    /// differs from the Content-Length of the encoded body.
    func testEncodedBodyIsNotCheckedAgainstContentLength() async throws {
        let client = ScriptedHTTPClient(url: url, replies: [
            .init(status: .ok, headers: ["Content-Length": "1000", "Content-Encoding": "gzip"], body: content[0 ..< 600]),
        ])
        let resource = HTTPResource(url: url, client: client)

        let data = try await resource.read().get()

        XCTAssertEqual(data, content[0 ..< 600])
        XCTAssertEqual(client.ranges.count, 1)
    }

    private func truncation<T>(in result: ReadResult<T>) -> HTTPTruncatedResponseError? {
        guard
            case let .failure(.access(.http(.malformedResponse(error)))) = result,
            let truncation = error as? HTTPTruncatedResponseError
        else {
            return nil
        }
        return truncation
    }
}

/// Answers GET requests from a script, one reply per request, and records the
/// Range header each request carried.
private final class ScriptedHTTPClient: HTTPClient {
    struct Reply {
        let status: HTTPStatus
        let headers: [String: String]
        let body: Data
        /// Cancels the reading task once this reply's body is delivered.
        var cancelsReader = false
    }

    private let url: HTTPURL
    private var replies: [Reply]
    private(set) var ranges: [String?] = []

    init(url: HTTPURL, replies: [Reply]) {
        self.url = url
        self.replies = replies
    }

    func stream(
        request: HTTPRequestConvertible,
        consume: @escaping (Data, Double?) -> HTTPResult<Void>
    ) async -> HTTPResult<HTTPResponse> {
        guard case let .success(request) = request.httpRequest() else {
            return .failure(.malformedRequest(url: nil))
        }
        ranges.append(request.headers["Range"])
        guard !replies.isEmpty else {
            return .failure(.other(URLError(.resourceUnavailable)))
        }
        let reply = replies.removeFirst()
        if case let .failure(error) = consume(reply.body, nil) {
            return .failure(error)
        }
        if reply.cancelsReader {
            withUnsafeCurrentTask { $0?.cancel() }
        }
        return .success(HTTPResponse(
            request: request,
            url: url,
            status: reply.status,
            headers: reply.headers,
            mediaType: nil,
            body: nil
        ))
    }
}
