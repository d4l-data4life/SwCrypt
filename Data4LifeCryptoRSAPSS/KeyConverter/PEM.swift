//
//  File.swift
//  
//
//  Created by Alessio Borraccino on 03.09.21.
//

import Foundation

class PEM {

    enum SwError: Error {
        case parse(String)
        case badPassphrase
        case keyNotEncrypted

        static var debugLevel = 1

        init(_ type: SwError, function: String = #function, file: String = #file, line: Int = #line) {
            self = type
            if SwError.debugLevel > 0 {
                print("\(file):\(line): [\(function)] \(self._domain): \(self)")
            }
        }
    }

    class PrivateKey {

        static func toDER(_ pemKey: String) throws -> Data {
            guard let strippedKey = stripHeader(pemKey) else {
                throw SwError(.parse("header"))
            }
            guard let data = PEM.base64Decode(strippedKey) else {
                throw SwError(.parse("base64decode"))
            }
            return data
        }

        static func toPEM(_ derKey: Data) -> String {
            let base64 = PEM.base64Encode(derKey)
            return addRSAHeader(base64)
        }

        fileprivate static let prefix = "-----BEGIN PRIVATE KEY-----\n"
        fileprivate static let suffix = "\n-----END PRIVATE KEY-----"
        fileprivate static let rsaPrefix = "-----BEGIN RSA PRIVATE KEY-----\n"
        fileprivate static let rsaSuffix = "\n-----END RSA PRIVATE KEY-----"

        fileprivate static func addHeader(_ base64: String) -> String {
            return prefix + base64 + suffix
        }

        fileprivate static func addRSAHeader(_ base64: String) -> String {
            return rsaPrefix + base64 + rsaSuffix
        }

        fileprivate static func stripHeader(_ pemKey: String) -> String? {
            return PEM.stripHeaderFooter(pemKey, header: prefix, footer: suffix) ??
                PEM.stripHeaderFooter(pemKey, header: rsaPrefix, footer: rsaSuffix)
        }
    }

    class PublicKey {

        static func toDER(_ pemKey: String) throws -> Data {
            guard let strippedKey = stripHeader(pemKey) else {
                throw SwError(.parse("header"))
            }
            guard let data = PEM.base64Decode(strippedKey) else {
                throw SwError(.parse("base64decode"))
            }
            return data
        }

        static func toPEM(_ derKey: Data) -> String {
            let base64 = PEM.base64Encode(derKey)
            return addHeader(base64)
        }

        fileprivate static let pemPrefix = "-----BEGIN KEY-----\n"
        fileprivate static let pemSuffix = "\n-----END KEY-----"

        fileprivate static func addHeader(_ base64: String) -> String {
            return pemPrefix + base64 + pemSuffix
        }

        fileprivate static func stripHeader(_ pemKey: String) -> String? {
            return PEM.stripHeaderFooter(pemKey, header: pemPrefix, footer: pemSuffix)
        }
    }

    fileprivate static func stripHeaderFooter(_ data: String, header: String, footer: String) -> String? {
        guard data.hasPrefix(header) else {
            return nil
        }
        guard let r = data.range(of: footer) else {
            return nil
        }
        return String(data[header.endIndex ..< r.lowerBound])
    }

    fileprivate static func base64Decode(_ base64Data: String) -> Data? {
        return Data(base64Encoded: base64Data, options: [.ignoreUnknownCharacters])
    }

    fileprivate static func base64Encode(_ key: Data) -> String {
        return key.base64EncodedString(
            options: [.lineLength64Characters, .endLineWithLineFeed])
    }

}

