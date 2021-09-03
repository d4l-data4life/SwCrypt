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

func withUnsafePointers<A0, A1, Result>(
    _ arg0: Data,
    _ arg1: Data,
    _ body: (UnsafePointer<A0>, UnsafePointer<A1>) throws -> Result) rethrows -> Result {

    return try arg0.withUnsafeBytes { p0 in
        return try arg1.withUnsafeBytes { p1 in
            return try body(p0.baseAddress!.assumingMemoryBound(to: A0.self),
                            p1.baseAddress!.assumingMemoryBound(to: A1.self))
        }
    }
}

func withUnsafePointers<A0, A1, Result>(
    _ arg0: Data,
    _ arg1: inout Data,
    _ body: (UnsafePointer<A0>, UnsafeMutablePointer<A1>) throws -> Result) rethrows -> Result {

    return try arg0.withUnsafeBytes { p0 in
        return try arg1.withUnsafeMutableBytes { p1 in
            return try body(p0.baseAddress!.assumingMemoryBound(to: A0.self),
                            p1.baseAddress!.assumingMemoryBound(to: A1.self))
        }
    }
}

func withUnsafePointers<A0, A1, A2, Result>(
    _ arg0: Data,
    _ arg1: Data,
    _ arg2: inout Data,
    _ body: (
        UnsafePointer<A0>,
        UnsafePointer<A1>,
        UnsafeMutablePointer<A2>) throws -> Result) rethrows -> Result {

    return try arg0.withUnsafeBytes { p0 in
        return try arg1.withUnsafeBytes { p1 in
            return try arg2.withUnsafeMutableBytes { p2 in
                return try body(p0.baseAddress!.assumingMemoryBound(to: A0.self),
                                p1.baseAddress!.assumingMemoryBound(to: A1.self),
                                p2.baseAddress!.assumingMemoryBound(to: A2.self))
            }
        }
    }
}

func withUnsafePointers<A0, A1, A2, Result>(
    _ arg0: inout Data,
    _ arg1: inout Data,
    _ arg2: inout Data,
    _ body: (
        UnsafeMutablePointer<A0>,
        UnsafeMutablePointer<A1>,
        UnsafeMutablePointer<A2>) throws -> Result) rethrows -> Result {

    return try arg0.withUnsafeMutableBytes { p0 in
        return try arg1.withUnsafeMutableBytes { p1 in
            return try arg2.withUnsafeMutableBytes { p2 in
                return try body(p0.baseAddress!.assumingMemoryBound(to: A0.self),
                                p1.baseAddress!.assumingMemoryBound(to: A1.self),
                                p2.baseAddress!.assumingMemoryBound(to: A2.self))
            }
        }
    }
}

func withUnsafePointers<A0, A1, A2, A3, Result>(
    _ arg0: Data,
    _ arg1: Data,
    _ arg2: Data,
    _ arg3: inout Data,
    _ body: (
        UnsafePointer<A0>,
        UnsafePointer<A1>,
        UnsafePointer<A2>,
        UnsafeMutablePointer<A3>) throws -> Result) rethrows -> Result {

    return try arg0.withUnsafeBytes { p0 in
        return try arg1.withUnsafeBytes { p1 in
            return try arg2.withUnsafeBytes { p2 in
                return try arg3.withUnsafeMutableBytes { p3 in
                    return try body(p0.baseAddress!.assumingMemoryBound(to: A0.self),
                                    p1.baseAddress!.assumingMemoryBound(to: A1.self),
                                    p2.baseAddress!.assumingMemoryBound(to: A2.self),
                                    p3.baseAddress!.assumingMemoryBound(to: A3.self))
                }
            }
        }
    }
}

func withUnsafePointers<A0, A1, A2, A3, A4, A5, Result>(
    _ arg0: Data,
    _ arg1: Data,
    _ arg2: Data,
    _ arg3: Data,
    _ arg4: inout Data,
    _ arg5: inout Data,
    _ body: (
        UnsafePointer<A0>,
        UnsafePointer<A1>,
        UnsafePointer<A2>,
        UnsafePointer<A3>,
        UnsafeMutablePointer<A4>,
        UnsafeMutablePointer<A5>) throws -> Result) rethrows -> Result {

    return try arg0.withUnsafeBytes { p0 in
        return try arg1.withUnsafeBytes { p1 in
            return try arg2.withUnsafeBytes { p2 in
                return try arg3.withUnsafeBytes { p3 in
                    return try arg4.withUnsafeMutableBytes { p4 in
                        return try arg5.withUnsafeMutableBytes { p5 in
                            return try body(p0.baseAddress!.assumingMemoryBound(to: A0.self),
                                            p1.baseAddress!.assumingMemoryBound(to: A1.self),
                                            p2.baseAddress!.assumingMemoryBound(to: A2.self),
                                            p3.baseAddress!.assumingMemoryBound(to: A3.self),
                                            p4.baseAddress!.assumingMemoryBound(to: A4.self),
                                            p5.baseAddress!.assumingMemoryBound(to: A5.self))
                        }
                    }
                }
            }
        }
    }
}
