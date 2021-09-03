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

func getFunc<T>(_ from: UnsafeMutableRawPointer, f: String) -> T? {
    let sym = dlsym(from, f)
    guard sym != nil else {
        return nil
    }
    return unsafeBitCast(sym, to: T.self)
}

extension Cryptor {

    typealias CCRandomGenerateBytesT = @convention(c) (
        _ bytes: UnsafeMutableRawPointer,
        _ count: size_t) -> CCRNGStatus
    typealias CCDigestGetOutputSizeT = @convention(c) (
        _ algorithm: CCDigestAlgorithm) -> size_t
    typealias CCDigestT = @convention(c) (
        _ algorithm: CCDigestAlgorithm,
        _ data: UnsafeRawPointer,
        _ dataLen: size_t,
        _ output: UnsafeMutableRawPointer) -> CInt

    typealias CCCryptorCreateWithModeT = @convention(c)(
        _ op: CCOperation,
        _ mode: CCMode,
        _ alg: CCAlgorithm,
        _ padding: CCPadding,
        _ iv: UnsafeRawPointer?,
        _ key: UnsafeRawPointer, _ keyLength: Int,
        _ tweak: UnsafeRawPointer?, _ tweakLength: Int,
        _ numRounds: Int32, _ options: CCModeOptions,
        _ cryptorRef: UnsafeMutablePointer<CCCryptorRef?>) -> CCCryptorStatus
    typealias CCCryptorGetOutputLengthT = @convention(c)(
        _ cryptorRef: CCCryptorRef,
        _ inputLength: size_t,
        _ final: Bool) -> size_t
    typealias CCCryptorUpdateT = @convention(c)(
        _ cryptorRef: CCCryptorRef,
        _ dataIn: UnsafeRawPointer,
        _ dataInLength: Int,
        _ dataOut: UnsafeMutableRawPointer,
        _ dataOutAvailable: Int,
        _ dataOutMoved: UnsafeMutablePointer<Int>) -> CCCryptorStatus
    typealias CCCryptorFinalT = @convention(c)(
        _ cryptorRef: CCCryptorRef,
        _ dataOut: UnsafeMutableRawPointer,
        _ dataOutAvailable: Int,
        _ dataOutMoved: UnsafeMutablePointer<Int>) -> CCCryptorStatus
    typealias CCCryptorReleaseT = @convention(c)
        (_ cryptorRef: CCCryptorRef) -> CCCryptorStatus


    static let dl = dlopen("/usr/lib/system/libcommonCrypto.dylib", RTLD_NOW)
    static let CCRandomGenerateBytes: CCRandomGenerateBytesT? =
        getFunc(dl!, f: "CCRandomGenerateBytes")
    static let CCDigestGetOutputSize: CCDigestGetOutputSizeT? =
        getFunc(dl!, f: "CCDigestGetOutputSize")
    static let CCDigest: CCDigestT? = getFunc(dl!, f: "CCDigest")
    static let CCCryptorCreateWithMode: CCCryptorCreateWithModeT? =
        getFunc(dl!, f: "CCCryptorCreateWithMode")
    static let CCCryptorGetOutputLength: CCCryptorGetOutputLengthT? =
        getFunc(dl!, f: "CCCryptorGetOutputLength")
    static let CCCryptorUpdate: CCCryptorUpdateT? =
        getFunc(dl!, f: "CCCryptorUpdate")
    static let CCCryptorFinal: CCCryptorFinalT? =
        getFunc(dl!, f: "CCCryptorFinal")
    static let CCCryptorRelease: CCCryptorReleaseT? =
        getFunc(dl!, f: "CCCryptorRelease")

}

extension Cryptor.RSA {

    typealias CCRSACryptorGeneratePairT = @convention(c) (
        _ keySize: Int,
        _ e: UInt32,
        _ publicKey: UnsafeMutablePointer<CCRSACryptorRef?>,
        _ privateKey: UnsafeMutablePointer<CCRSACryptorRef?>) -> Cryptor.CCCryptorStatus
    static let CCRSACryptorGeneratePair: CCRSACryptorGeneratePairT? =
        getFunc(Cryptor.dl!, f: "CCRSACryptorGeneratePair")

    typealias CCRSACryptorGetPublicKeyFromPrivateKeyT = @convention(c) (CCRSACryptorRef) -> CCRSACryptorRef
    static let CCRSACryptorGetPublicKeyFromPrivateKey: CCRSACryptorGetPublicKeyFromPrivateKeyT? =
        getFunc(Cryptor.dl!, f: "CCRSACryptorGetPublicKeyFromPrivateKey")

    typealias CCRSACryptorReleaseT = @convention(c) (CCRSACryptorRef) -> Void
    static let CCRSACryptorRelease: CCRSACryptorReleaseT? =
        getFunc(Cryptor.dl!, f: "CCRSACryptorRelease")

    typealias CCRSAGetKeyTypeT = @convention(c) (CCRSACryptorRef) -> CCRSAKeyType
    static let CCRSAGetKeyType: CCRSAGetKeyTypeT? = getFunc(Cryptor.dl!, f: "CCRSAGetKeyType")

    typealias CCRSAGetKeySizeT = @convention(c) (CCRSACryptorRef) -> Int32
    static let CCRSAGetKeySize: CCRSAGetKeySizeT? = getFunc(Cryptor.dl!, f: "CCRSAGetKeySize")

    typealias CCRSACryptorExportT = @convention(c) (
        _ key: CCRSACryptorRef,
        _ out: UnsafeMutableRawPointer,
        _ outLen: UnsafeMutablePointer<Int>) -> Cryptor.CCCryptorStatus
    static let CCRSACryptorExport: CCRSACryptorExportT? =
        getFunc(Cryptor.dl!, f: "CCRSACryptorExport")

    typealias CCRSACryptorImportT = @convention(c) (
        _ keyPackage: UnsafeRawPointer,
        _ keyPackageLen: Int,
        _ key: UnsafeMutablePointer<CCRSACryptorRef?>) -> Cryptor.CCCryptorStatus
    static let CCRSACryptorImport: CCRSACryptorImportT? =
        getFunc(Cryptor.dl!, f: "CCRSACryptorImport")

    typealias CCRSACryptorSignT = @convention(c) (
        _ privateKey: CCRSACryptorRef,
        _ hashToSign: UnsafeRawPointer,
        _ hashSignLen: size_t,
        _ digestType: Cryptor.CCDigestAlgorithm,
        _ saltLen: size_t,
        _ signedData: UnsafeMutableRawPointer,
        _ signedDataLen: UnsafeMutablePointer<Int>) -> Cryptor.CCCryptorStatus
    static let CCRSACryptorSign: CCRSACryptorSignT? =
        getFunc(Cryptor.dl!, f: "CCRSACryptorSign")

    typealias CCRSACryptorVerifyT = @convention(c) (
        _ publicKey: CCRSACryptorRef,
        _ hash: UnsafeRawPointer,
        _ hashLen: size_t,
        _ digestType: Cryptor.CCDigestAlgorithm,
        _ saltLen: size_t,
        _ signedData: UnsafeRawPointer,
        _ signedDataLen: size_t) -> Cryptor.CCCryptorStatus
    static let CCRSACryptorVerify: CCRSACryptorVerifyT? =
        getFunc(Cryptor.dl!, f: "CCRSACryptorVerify")

    typealias CCRSACryptorCryptT = @convention(c) (
        _ rsaKey: CCRSACryptorRef,
        _ data: UnsafeRawPointer, _ dataLength: size_t,
        _ out: UnsafeMutableRawPointer,
        _ outLength: UnsafeMutablePointer<size_t>) -> Cryptor.CCCryptorStatus
    static let CCRSACryptorCrypt: CCRSACryptorCryptT? =
        getFunc(Cryptor.dl!, f: "CCRSACryptorCrypt")
}

