//
//  File.swift
//  
//
//  Created by Alessio Borraccino on 03.09.21.
//

import Foundation

class KeyConverter {

    enum SwError: Error {
        case invalidKey
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

        static func pemToPKCS1DER(_ pemKey: String) throws -> Data {
            guard let derKey = try? PEM.PrivateKey.toDER(pemKey) else {
                throw SwError(.invalidKey)
            }
            guard let pkcs1DERKey = PKCS8.PrivateKey.stripHeaderIfAny(derKey) else {
                throw SwError(.invalidKey)
            }
            return pkcs1DERKey
        }

        static func derToPKCS1PEM(_ derKey: Data) -> String {
            return PEM.PrivateKey.toPEM(derKey)
        }
    }

    class PublicKey {

        static func pemToPKCS1DER(_ pemKey: String) throws -> Data {
            guard let derKey = try? PEM.PublicKey.toDER(pemKey) else {
                throw SwError(.invalidKey)
            }
            guard let pkcs1DERKey = PKCS8.PublicKey.stripHeaderIfAny(derKey) else {
                throw SwError(.invalidKey)
            }
            return pkcs1DERKey
        }

        static func pemToPKCS8DER(_ pemKey: String) throws -> Data {
            guard let derKey = try? PEM.PublicKey.toDER(pemKey) else {
                throw SwError(.invalidKey)
            }
            return derKey
        }

        static func derToPKCS1PEM(_ derKey: Data) -> String {
            return PEM.PublicKey.toPEM(derKey)
        }

        static func derToPKCS8PEM(_ derKey: Data) -> String {
            let pkcs8Key = PKCS8.PublicKey.addHeader(derKey)
            return PEM.PublicKey.toPEM(pkcs8Key)
        }
    }
}
