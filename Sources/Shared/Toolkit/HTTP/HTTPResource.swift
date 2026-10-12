//
//  Copyright 2026 Readium Foundation. All rights reserved.
//  Use of this source code is governed by the BSD-style license
//  available in the top-level LICENSE file of the project.
//

import Foundation

/// ``HTTPResource`` provides access to an external URL through HTTP.
public actor HTTPResource: Resource {
    public let url: HTTPURL

    private let client: HTTPClient

    init(url: HTTPURL, client: HTTPClient) {
        self.url = url
        self.client = client
    }

    public nonisolated var sourceURL: AbsoluteURL? {
        url
    }

    public func properties() async -> ReadResult<ResourceProperties> {
        await headResponse()
            .map { response in
                ResourceProperties {
                    if let response = response {
                        $0.filename = response.filename ?? url.lastPathSegment
                        $0.mediaType = response.mediaType
                    }
                }
            }
    }

    public func estimatedLength() async -> ReadResult<UInt64?> {
        await headResponse().flatMap {
            if let length = $0?.contentLength {
                return .success(UInt64(length))
            } else {
                return .success(nil)
            }
        }
    }

    private var _headResponse: ReadResult<HTTPResponse?>?

    /// Cached HEAD response to get the expected content length and other
    /// metadata.
    private func headResponse() async -> ReadResult<HTTPResponse?> {
        if _headResponse == nil {
            _headResponse = await client.fetch(HTTPRequest(url: url, method: .head))
                .map { $0 as HTTPResponse? }
                .flatMapError { error in
                    switch error {
                    case let .errorResponse(response) where response.status == .methodNotAllowed:
                        return .success(nil)
                    default:
                        return .failure(.access(.http(error)))
                    }
                }
        }
        return _headResponse!
    }

    public func stream(range: Range<UInt64>?, consume: @escaping (Data) -> Void) async -> ReadResult<Void> {
        var request = HTTPRequest(url: url)
        if let range = range {
            request.setRange(range)
        }

        var received: UInt64 = 0
        let result = await client.stream(
            request: request,
            consume: { data, _ in
                received += UInt64(data.count)
                consume(data)
                return .success(())
            }
        )

        switch result {
        case let .failure(error):
            return .failure(.access(.http(error)))

        case let .success(response):
            // A connection can end before the body is complete without the
            // transport reporting an error. The missing bytes are requested
            // once more before the read fails.
            guard let expected = response.expectedBodyLength, received < expected else {
                return .success(())
            }
            let start = (range?.lowerBound ?? 0) + received
            let end = (range?.lowerBound ?? 0) + expected
            return await resume(start ..< end, consume: consume)
        }
    }

    /// Reads the remaining `range` of an interrupted body, delivering it only
    /// if the server returned exactly that range.
    private func resume(_ range: Range<UInt64>, consume: @escaping (Data) -> Void) async -> ReadResult<Void> {
        guard !Task.isCancelled else {
            return .failure(.cancelled)
        }

        var request = HTTPRequest(url: url)
        request.setRange(range)

        var data = Data()
        let result = await client.stream(
            request: request,
            consume: { chunk, _ in
                data.append(chunk)
                return .success(())
            }
        )

        switch result {
        case let .failure(error):
            return .failure(.access(.http(error)))

        case let .success(response):
            guard response.status == .partialContent, UInt64(data.count) == UInt64(range.count) else {
                let error = HTTPTruncatedResponseError(expected: UInt64(range.count), received: UInt64(data.count))
                return .failure(.access(.http(.malformedResponse(error))))
            }
            consume(data)
            return .success(())
        }
    }
}

/// The server ended a response body before delivering the bytes it announced.
public struct HTTPTruncatedResponseError: Error {
    /// Number of bytes announced by the response.
    public let expected: UInt64
    /// Number of bytes actually received.
    public let received: UInt64
}

private extension HTTPResponse {
    /// Length of the body the client will receive, when it can be known.
    ///
    /// URLSession decodes compressed bodies, whose Content-Length counts the
    /// encoded bytes, so their decoded length cannot be checked against it.
    var expectedBodyLength: UInt64? {
        if let encoding = valueForHeader("Content-Encoding"), encoding.lowercased() != "identity" {
            return nil
        }
        return contentLength.map { UInt64($0) }
    }
}
