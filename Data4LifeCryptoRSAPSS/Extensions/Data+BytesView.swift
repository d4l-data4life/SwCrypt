//  Copyright (c) 2021 D4L data4life gGmbH
//  All rights reserved.
//
//  D4L owns all legal rights, title and interest in and to the Software Development Kit ("SDK"),
//  including any intellectual property rights that subsist in the SDK.
//
//  The SDK and its documentation may be accessed and used for viewing/review purposes only.
//  Any usage of the SDK for other purposes, including usage for the development of
//  applications/third-party applications shall require the conclusion of a license agreement
//  between you and D4L.
//
//  If you are interested in licensing the SDK for your own applications/third-party
//  applications and/or if you’d like to contribute to the development of the SDK, please
//  contact D4L by email to help@data4life.care.
//

import Foundation


extension Data {
    /// Create hexadecimal string representation of Data object.
    ///
    /// - returns: String representation of this Data object.

    func hexadecimalString() -> String {
        var hexstr = String()
        self.withUnsafeBytes {data in
            for i in UnsafeBufferPointer<UInt8>(start: data.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                                count: count) {
                hexstr += String(format: "%02X", i)
            }
        }
        return hexstr
    }

    func arrayOfBytes() -> [UInt8] {
        let count = self.count / MemoryLayout<UInt8>.size
        var bytesArray = [UInt8](repeating: 0, count: count)
        self.copyBytes(to: &bytesArray, count: count * MemoryLayout<UInt8>.size)
        return bytesArray
    }

    var bytesView: BytesView { return BytesView(self) }

    func bytesViewRange(_ range: NSRange) -> BytesView {
        return BytesView(self, range: range)
    }

    struct BytesView: Collection {
        // The view retains the Data. That's on purpose.
        // Data doesn't retain the view, so there's no loop.
        let data: Data
        init(_ data: Data) {
            self.data = data
            self.startIndex = 0
            self.endIndex = data.count
        }

        init(_ data: Data, range: NSRange ) {
            self.data = data
            self.startIndex = range.location
            self.endIndex = range.location + range.length
        }

        subscript (position: Int) -> UInt8 {
            var value: UInt8 = 0
            data.withUnsafeBytes { dataBytes in
                value = UnsafeBufferPointer<UInt8>(start: dataBytes.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                                   count: data.count)[position]
            }
            return value
        }
        subscript (bounds: Range<Int>) -> Data {
            return data.subdata(in: bounds)
        }
        func formIndex(after i: inout Int) {
            i += 1
        }
        func index(after i: Int) -> Int {
            return i + 1
        }
        var startIndex: Int
        var endIndex: Int
        var length: Int { return endIndex - startIndex }
    }
}
