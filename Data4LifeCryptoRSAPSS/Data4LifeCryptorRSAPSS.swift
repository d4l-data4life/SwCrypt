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

public final class Data4LifeCryptorRSAPSS {

    public static func signUnsalted(data: Data, privateKey: SecKey) throws -> Data {
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

    public static func verifyUnsalted(data: Data,
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
