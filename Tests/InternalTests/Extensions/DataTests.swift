//
//  Copyright 2026 Readium Foundation. All rights reserved.
//  Use of this source code is governed by the BSD-style license
//  available in the top-level LICENSE file of the project.
//

import Foundation
@testable import ReadiumInternal
import Testing

struct DataBytesInRangeTests {
    private let data = Data(0 ..< 32)

    @Test func returnsTheBytesInRange() {
        #expect(data.bytes(in: 4 ..< 8) == Data(4 ..< 8))
    }

    @Test func returnsAllBytesForTheFullRange() {
        #expect(data.bytes(in: 0 ..< 32) == data)
    }

    /// A range ending past the data is refused rather than trapping.
    @Test func returnsNilWhenRangeEndsPastTheData() {
        #expect(data.bytes(in: 16 ..< 33) == nil)
    }

    @Test func returnsNilWhenRangeStartsPastTheData() {
        #expect(data.bytes(in: 40 ..< 48) == nil)
    }

    /// Offsets count from the first byte, also for a slice whose
    /// `startIndex` is not zero.
    @Test func countsFromTheFirstByteOfASlice() {
        let slice = data[16 ..< 32]
        #expect(slice.bytes(in: 0 ..< 4) == Data(16 ..< 20))
        #expect(slice.bytes(in: 12 ..< 16) == Data(28 ..< 32))
        #expect(slice.bytes(in: 12 ..< 17) == nil)
    }
}
