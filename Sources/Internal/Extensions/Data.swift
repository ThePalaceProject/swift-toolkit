//
//  Copyright 2026 Readium Foundation. All rights reserved.
//  Use of this source code is governed by the BSD-style license
//  available in the top-level LICENSE file of the project.
//

import Foundation

public extension Data {
    /// Reads a sub-range of `self` after shifting the given absolute range
    /// to be relative to `self`.
    subscript(_ range: Range<UInt64>, offsetBy dataStartOffset: UInt64) -> Data? {
        let range = range.clampedToInt()

        let lower = Int(range.lowerBound) - Int(dataStartOffset) + startIndex
        let upper = lower + range.count
        guard lower >= 0, upper <= count else {
            return nil
        }
        assert(indices.contains(lower))
        assert(indices.contains(upper - 1))
        return self[lower ..< upper]
    }

    /// Returns the bytes at `range`, counted from the first byte of `self`
    /// whatever its `startIndex`, or nil if `range` extends past the end.
    func bytes(in range: Range<Int>) -> Data? {
        guard range.lowerBound >= 0, range.upperBound <= count else {
            return nil
        }
        return self[(startIndex + range.lowerBound) ..< (startIndex + range.upperBound)]
    }
}
