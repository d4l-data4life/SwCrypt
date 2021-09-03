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

class PKCS8 {

    class PrivateKey {

        // https://lapo.it/asn1js/
        static func getPKCS1DEROffset(_ derKey: Data) -> Int? {
            let bytes = derKey.bytesView

            var offset = 0
            guard bytes.length > offset else { return nil }
            guard bytes[offset] == 0x30 else { return nil }

            offset += 1

            guard bytes.length > offset else { return nil }
            if bytes[offset] > 0x80 {
                offset += Int(bytes[offset]) - 0x80
            }
            offset += 1

            guard bytes.length > offset else { return nil }
            guard bytes[offset] == 0x02 else { return nil }

            offset += 3

            // without PKCS8 header
            guard bytes.length > offset else { return nil }
            if bytes[offset] == 0x02 {
                return 0
            }

            let OID: [UInt8] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
                                0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]

            guard bytes.length > offset + OID.count else { return nil }
            let slice = derKey.bytesViewRange(NSRange(location: offset, length: OID.count))

            guard OID.elementsEqual(slice) else { return nil }

            offset += OID.count

            guard bytes.length > offset else { return nil }
            guard bytes[offset] == 0x04 else { return nil }

            offset += 1

            guard bytes.length > offset else { return nil }
            if bytes[offset] > 0x80 {
                offset += Int(bytes[offset]) - 0x80
            }
            offset += 1

            guard bytes.length > offset else { return nil }
            guard bytes[offset] == 0x30 else { return nil }

            return offset
        }

        static func stripHeaderIfAny(_ derKey: Data) -> Data? {
            guard let offset = getPKCS1DEROffset(derKey) else {
                return nil
            }
            return derKey.subdata(in: offset..<derKey.count)
        }

        static func hasCorrectHeader(_ derKey: Data) -> Bool {
            return getPKCS1DEROffset(derKey) != nil
        }

    }

    class PublicKey {

        static func addHeader(_ derKey: Data) -> Data {
            var result = Data()

            let encodingLength: Int = encodedOctets(derKey.count + 1).count
            let OID: [UInt8] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
                                0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]

            var builder: [UInt8] = []

            // ASN.1 SEQUENCE
            builder.append(0x30)

            // Overall size, made of OID + bitstring encoding + actual key
            let size = OID.count + 2 + encodingLength + derKey.count
            let encodedSize = encodedOctets(size)
            builder.append(contentsOf: encodedSize)
            result.append(builder, count: builder.count)
            result.append(OID, count: OID.count)
            builder.removeAll(keepingCapacity: false)

            builder.append(0x03)
            builder.append(contentsOf: encodedOctets(derKey.count + 1))
            builder.append(0x00)
            result.append(builder, count: builder.count)

            // Actual key bytes
            result.append(derKey)

            return result
        }

        // https://lapo.it/asn1js/
        static func getPKCS1DEROffset(_ derKey: Data) -> Int? {
            let bytes = derKey.bytesView

            var offset = 0
            guard bytes.length > offset else { return nil }
            guard bytes[offset] == 0x30 else { return nil }

            offset += 1

            guard bytes.length > offset else { return nil }
            if bytes[offset] > 0x80 {
                offset += Int(bytes[offset]) - 0x80
            }
            offset += 1

            // without PKCS8 header
            guard bytes.length > offset else { return nil }
            if bytes[offset] == 0x02 {
                return 0
            }

            let OID: [UInt8] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
                                0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]

            guard bytes.length > offset + OID.count else { return nil }
            let slice = derKey.bytesViewRange(NSRange(location: offset, length: OID.count))

            guard OID.elementsEqual(slice) else { return nil }
            offset += OID.count

            // Type
            guard bytes.length > offset else { return nil }
            guard bytes[offset] == 0x03 else { return nil }

            offset += 1

            guard bytes.length > offset else { return nil }
            if bytes[offset] > 0x80 {
                offset += Int(bytes[offset]) - 0x80
            }
            offset += 1

            // Contents should be separated by a null from the header
            guard bytes.length > offset else { return nil }
            guard bytes[offset] == 0x00 else { return nil }

            offset += 1
            guard bytes.length > offset else { return nil }

            return offset
        }

        static func stripHeaderIfAny(_ derKey: Data) -> Data? {
            guard let offset = getPKCS1DEROffset(derKey) else {
                return nil
            }
            return derKey.subdata(in: offset..<derKey.count)
        }

        static func hasCorrectHeader(_ derKey: Data) -> Bool {
            return getPKCS1DEROffset(derKey) != nil
        }

        fileprivate static func encodedOctets(_ int: Int) -> [UInt8] {
            // Short form
            if int < 128 {
                return [UInt8(int)]
            }

            // Long form
            let i = (int / 256) + 1
            var len = int
            var result: [UInt8] = [UInt8(i + 0x80)]

            for _ in 0..<i {
                result.insert(UInt8(len & 0xFF), at: 1)
                len = len >> 8
            }

            return result
        }
    }
}
