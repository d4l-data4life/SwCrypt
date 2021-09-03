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

public enum D4L {
    public enum RSAPSS {
        public static func sign(data: Data, privateKey: SecKey, saltType: SaltType) throws -> Data {
            do {
                switch saltType {
                case .unsalted:
                    return try signUnsalted(data: data, privateKey: privateKey)
                case .salted:
                    return try signSalted(data: data, privateKey: privateKey)
                }
            } catch {
                throw Data4LifeCryptoRSAPSSError.couldNotCreateSignature(error: error)
            }
        }

        public static func verify(data: Data, against signature: Data, publicKey: SecKey, saltType: SaltType) throws -> Bool {
            do {
                switch saltType {
                case .unsalted:
                    return try verifyUnsalted(data: data, against: signature, publicKey: publicKey)
                case .salted:
                    return try verifySalted(data: data, against: signature, publicKey: publicKey)
                }
            } catch {
                throw Data4LifeCryptoRSAPSSError.couldNotVerifySignature(error: error)
            }
        }
    }
}

public enum SaltType: Int {
    case unsalted  = 0
    case salted = 32
}

public enum Data4LifeCryptoRSAPSSError: Error {
    case couldNotCreateSignature(error: Error?)
    case couldNotVerifySignature(error: Error?)
}

// MARK: Salted (using CommonCrypto)
private extension D4L.RSAPSS {

    static func signSalted(data: Data, privateKey: SecKey) throws -> Data {
        var error: Unmanaged<CFError>?
        let signedMessage = SecKeyCreateSignature(privateKey,
                                                  .rsaSignatureMessagePSSSHA256,
                                                  data as CFData,
                                                  &error) as Data?

        if let error = error?.takeRetainedValue() {
            throw error
        }

        guard let signedMessage = signedMessage else {
            throw Data4LifeCryptoRSAPSSError.couldNotCreateSignature(error: nil)
        }

        return signedMessage
    }

    static func verifySalted(data: Data,
                             against signature: Data,
                             publicKey: SecKey) throws -> Bool {
        var error: Unmanaged<CFError>?
        let isVerified = SecKeyVerifySignature(publicKey,
                                               .rsaSignatureMessagePSSSHA256,
                                               data as NSData,
                                               signature as NSData,
                                               &error)
        if let error = error?.takeRetainedValue() {
            throw Data4LifeCryptoRSAPSSError.couldNotVerifySignature(error: error)
        }

        return isVerified
    }
}

// MARK: Unsalted (using SwCrypt)
private extension D4L.RSAPSS {

    static func signUnsalted(data: Data, privateKey: SecKey) throws -> Data {
        let keyString = """
            -----BEGIN PRIVATE KEY-----
            \(try privateKey.asBase64EncodedString())
            -----END PRIVATE KEY-----
            """
        let derPrivateKey = try KeyConverter.PrivateKey.pemToPKCS1DER(keyString)
        let signature = try Cryptor.RSA.sign(data,
                                             derKey: derPrivateKey,
                                             padding: .pss,
                                             digest: .sha256,
                                             saltLen: 0)
        return signature
    }

    static func verifyUnsalted(data: Data,
                               against signature: Data,
                               publicKey: SecKey) throws -> Bool {
        let keyString = """
            -----BEGIN KEY-----
            \(try publicKey.asBase64EncodedString())
            -----END KEY-----
            """
        let derPublicKey = try KeyConverter.PublicKey.pemToPKCS1DER(keyString)
        let isVerified = try Cryptor.RSA.verify(data,
                                                derKey: derPublicKey,
                                                padding: .pss,
                                                digest: .sha256,
                                                saltLen: 0,
                                                signedData: signature)
        return isVerified
    }
}
