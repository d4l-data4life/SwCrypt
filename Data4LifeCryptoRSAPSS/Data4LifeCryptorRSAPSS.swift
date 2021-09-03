//
//  File.swift
//  
//
//  Created by Alessio Borraccino on 03.09.21.
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
