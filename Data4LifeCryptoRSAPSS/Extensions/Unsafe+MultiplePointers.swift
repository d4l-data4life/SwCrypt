//
//  Unsafe+Extension.swift
//  SwCrypt
//
//  Created by Alessio Borraccino on 03.09.21.
//  Copyright © 2021 irl. All rights reserved.
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
