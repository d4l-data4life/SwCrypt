import Foundation

final class Cryptor {

    typealias CCCryptorStatus = Int32
    enum CCError: CCCryptorStatus, Error {
        case paramError = -4300
        case bufferTooSmall = -4301
        case memoryFailure = -4302
        case alignmentError = -4303
        case decodeError = -4304
        case unimplemented = -4305
        case overflow = -4306
        case rngFailure = -4307
        case unspecifiedError = -4308
        case callSequenceError = -4309
        case keySizeError = -4310
        case invalidKey = -4311

        static var debugLevel = 1

        init(_ status: CCCryptorStatus, function: String = #function,
             file: String = #file, line: Int = #line) {
            self = CCError(rawValue: status)!
            if CCError.debugLevel > 0 {
                print("\(file):\(line): [\(function)] \(self._domain): \(self) (\(self.rawValue))")
            }
        }
        init(_ type: CCError, function: String = #function, file: String = #file, line: Int = #line) {
            self = type
            if CCError.debugLevel > 0 {
                print("\(file):\(line): [\(function)] \(self._domain): \(self) (\(self.rawValue))")
            }
        }
    }

    static func generateRandom(_ size: Int) -> Data {
        var data = Data(count: size)
        data.withUnsafeMutableBytes { dataBytes in
            _ = CCRandomGenerateBytes!(dataBytes.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                       size)
        }
        return data
    }

    typealias CCDigestAlgorithm = UInt32
    enum DigestAlgorithm: CCDigestAlgorithm {
        case sha256 = 10

        var length: Int {
            return CCDigestGetOutputSize!(self.rawValue)
        }
    }

    static func digest(_ data: Data, alg: DigestAlgorithm) -> Data {
        var output = Data(count: alg.length)
        withUnsafePointers(data, &output, { dataBytes, outputBytes in
            _ = CCDigest!(alg.rawValue,
                          dataBytes,
                          data.count,
                          outputBytes)
        })
        return output
    }

    typealias CCOperation = UInt32
    enum OpMode: CCOperation {
        case encrypt = 0, decrypt
    }

    typealias CCMode = UInt32
    enum BlockMode: CCMode {
        case ecb = 1, cbc, cfb, ctr, f8, lrw, ofb, xts, rc4, cfb8
        var needIV: Bool {
            switch self {
            case .cbc, .cfb, .ctr, .ofb, .cfb8: return true
            default: return false
            }
        }
    }

    enum AuthBlockMode: CCMode {
        case gcm = 11, ccm
    }

    typealias CCAlgorithm = UInt32
    enum Algorithm: CCAlgorithm {
        case aes = 0, des, threeDES, cast, rc4, rc2, blowfish

        var blockSize: Int? {
            switch self {
            case .aes: return 16
            case .des: return 8
            case .threeDES: return 8
            case .cast: return 8
            case .rc2: return 8
            case .blowfish: return 8
            default: return nil
            }
        }
    }

    typealias CCPadding = UInt32
    enum Padding: CCPadding {
        case noPadding = 0, pkcs7Padding
    }

    static func crypt(_ opMode: OpMode, blockMode: BlockMode,
                      algorithm: Algorithm, padding: Padding,
                      data: Data, key: Data, iv: Data) throws -> Data {
        if blockMode.needIV {
            guard iv.count == algorithm.blockSize else { throw CCError(.paramError) }
        }

        var cryptor: CCCryptorRef? = nil
        var status = withUnsafePointers(iv, key, { ivBytes, keyBytes in
            return CCCryptorCreateWithMode!(
                opMode.rawValue, blockMode.rawValue,
                algorithm.rawValue, padding.rawValue,
                ivBytes, keyBytes, key.count,
                nil, 0, 0,
                CCModeOptions(), &cryptor)
        })

        guard status == noErr else { throw CCError(status) }

        defer { _ = CCCryptorRelease!(cryptor!) }

        let needed = CCCryptorGetOutputLength!(cryptor!, data.count, true)
        var result = Data(count: needed)
        let rescount = result.count
        var updateLen: size_t = 0
        status = withUnsafePointers(data, &result, { dataBytes, resultBytes in
            return CCCryptorUpdate!(
                cryptor!,
                dataBytes, data.count,
                resultBytes, rescount,
                &updateLen)
        })
        guard status == noErr else { throw CCError(status) }


        var finalLen: size_t = 0
        status = result.withUnsafeMutableBytes { resultBytes in
            let resultBytesPointer = resultBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
            return CCCryptorFinal!(
                cryptor!,
                resultBytesPointer + updateLen,
                rescount - updateLen,
                &finalLen)
        }
        guard status == noErr else { throw CCError(status) }


        result.count = updateLen + finalLen
        return result
    }

    static func digestAvailable() -> Bool {
        return CCDigest != nil &&
            CCDigestGetOutputSize != nil
    }

    static func randomAvailable() -> Bool {
        return CCRandomGenerateBytes != nil
    }

    static func cryptorAvailable() -> Bool {
        return CCCryptorCreateWithMode != nil &&
            CCCryptorGetOutputLength != nil &&
            CCCryptorUpdate != nil &&
            CCCryptorFinal != nil &&
            CCCryptorRelease != nil
    }

    static func available() -> Bool {
        return digestAvailable() &&
            randomAvailable() &&
            cryptorAvailable() &&
            RSA.available()
    }

    typealias CCCryptorRef = UnsafeRawPointer
    typealias CCRNGStatus = CCCryptorStatus
    typealias CC_LONG = UInt32
    typealias CCModeOptions = UInt32

    class RSA {

        enum AsymmetricSAPadding: UInt32 {
            case pss = 1002
        }

        static func generateKeyPair(_ keySize: Int = 4096) throws -> (Data, Data) {
            var privateKey: CCRSACryptorRef? = nil
            var publicKey: CCRSACryptorRef? = nil
            let status = CCRSACryptorGeneratePair!(
                keySize,
                65537,
                &publicKey,
                &privateKey)
            guard status == noErr else { throw CCError(status) }

            defer {
                CCRSACryptorRelease!(privateKey!)
                CCRSACryptorRelease!(publicKey!)
            }

            let privDERKey = try exportToDERKey(privateKey!)
            let pubDERKey = try exportToDERKey(publicKey!)

            return (privDERKey, pubDERKey)
        }

        static func getPublicKeyFromPrivateKey(_ derKey: Data) throws -> Data {
            let key = try importFromDERKey(derKey)
            defer { CCRSACryptorRelease!(key) }

            guard getKeyType(key) == .privateKey else { throw CCError(.paramError) }

            let publicKey = CCRSACryptorGetPublicKeyFromPrivateKey!(key)
            defer { CCRSACryptorRelease!(publicKey) }

            let pubDERKey = try exportToDERKey(publicKey)

            return pubDERKey
        }

        static func importFromDERKey(_ derKey: Data) throws -> CCRSACryptorRef {
            var key: CCRSACryptorRef? = nil
            let status = derKey.withUnsafeBytes { derKeyBytes in
                return CCRSACryptorImport!(
                    derKeyBytes.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    derKey.count,
                    &key)
            }
            guard status == noErr else { throw CCError(status) }

            return key!
        }

        static func exportToDERKey(_ key: CCRSACryptorRef) throws -> Data {
            var derKeyLength = 8192
            var derKey = Data(count: derKeyLength)
            let status = derKey.withUnsafeMutableBytes { derKeyBytes in
                return CCRSACryptorExport!(key,
                                           derKeyBytes.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                           &derKeyLength)
            }
            guard status == noErr else { throw CCError(status) }

            derKey.count = derKeyLength
            return derKey
        }

        static func getKeyType(_ key: CCRSACryptorRef) -> KeyType {
            return KeyType(rawValue: CCRSAGetKeyType!(key))!
        }

        static func getKeySize(_ key: CCRSACryptorRef) -> Int {
            return Int(CCRSAGetKeySize!(key)/8)
        }

        static func sign(_ message: Data,
                         derKey: Data,
                         padding: AsymmetricSAPadding,
                         digest: DigestAlgorithm, saltLen: Int) throws -> Data {
            let key = try importFromDERKey(derKey)
            defer { CCRSACryptorRelease!(key) }
            guard getKeyType(key) == .privateKey else { throw CCError(.paramError) }

            let keySize = getKeySize(key)

            switch padding {
            case .pss:
                let encMessage = try add_pss_padding(
                    digest,
                    saltLength: saltLen,
                    keyLength: keySize,
                    message: message)
                return try crypt(encMessage, key: key)
            }
        }

        static func verify(_ message: Data, derKey: Data, padding: AsymmetricSAPadding,
                           digest: DigestAlgorithm, saltLen: Int,
                           signedData: Data) throws -> Bool {
            let key = try importFromDERKey(derKey)
            defer { CCRSACryptorRelease!(key) }
            guard getKeyType(key) == .publicKey else { throw CCError(.paramError) }

            let keySize = getKeySize(key)

            switch padding {
            case .pss:
                let encoded = try crypt(signedData, key:key)
                return try verify_pss_padding(
                    digest,
                    saltLength: saltLen,
                    keyLength: keySize,
                    message: message,
                    encMessage: encoded)
            }
        }

        static func crypt(_ data: Data, key: CCRSACryptorRef) throws -> Data {
            var outLength = data.count
            var out = Data(count: outLength)

            let status = withUnsafePointers(data, &out, { dataBytes, outBytes in
                return CCRSACryptorCrypt!(
                    key,
                    dataBytes, data.count,
                    outBytes, &outLength)
            })

            guard status == noErr else { throw CCError(status) }
            out.count = outLength

            return out
        }

        static func mgf1(_ digest: DigestAlgorithm,
                         seed: Data, maskLength: Int) -> Data {
            var tseed = seed
            tseed.append(contentsOf: [0,0,0,0] as [UInt8])

            var interval = maskLength / digest.length
            if maskLength % digest.length != 0 {
                interval += 1
            }

            func pack(_ n: Int) -> [UInt8] {
                return [
                    UInt8(n>>24 & 0xff),
                    UInt8(n>>16 & 0xff),
                    UInt8(n>>8 & 0xff),
                    UInt8(n>>0 & 0xff)
                ]
            }

            var mask = Data()
            for counter in 0 ..< interval {
                tseed.replaceSubrange((tseed.count - 4) ..< tseed.count, with: pack(counter))
                mask.append(Cryptor.digest(tseed, alg: digest))
            }
            mask.count = maskLength
            return mask
        }

        static func xorData(_ data1: Data, _ data2: Data) -> Data {
            precondition(data1.count == data2.count)

            var ret = Data(count: data1.count)
            let retcount = ret.count
            withUnsafePointers(data1, data2, &ret, {(
                b1: UnsafePointer<UInt8>,
                b2: UnsafePointer<UInt8>,
                r: UnsafeMutablePointer<UInt8>) in
                for i in 0 ..< retcount {
                    r[i] = b1[i] ^ b2[i]
                }
            })
            return ret
        }

        static func add_pss_padding(_ digest: DigestAlgorithm,
                                    saltLength: Int,
                                    keyLength: Int,
                                    message: Data) throws -> Data {

            if keyLength < 16 || saltLength < 0 {
                throw CCError(.paramError)
            }

            // The maximal bit size of a non-negative integer is one less than the bit
            // size of the key since the first bit is used to store sign
            let emBits = keyLength * 8 - 1
            var emLength = emBits / 8
            if emBits % 8 != 0 {
                emLength += 1
            }

            let hash = Cryptor.digest(message, alg: digest)

            if emLength < hash.count + saltLength + 2 {
                throw CCError(.paramError)
            }

            let salt = Cryptor.generateRandom(saltLength)

            var mPrime = Data(count: 8)
            mPrime.append(hash)
            mPrime.append(salt)
            let mPrimeHash = Cryptor.digest(mPrime, alg: digest)

            let padding = Data(count: emLength - saltLength - hash.count - 2)
            var db = padding
            db.append([0x01] as [UInt8], count: 1)
            db.append(salt)
            let dbMask = mgf1(digest, seed: mPrimeHash, maskLength: emLength - hash.count - 1)
            var maskedDB = xorData(db, dbMask)

            let zeroBits = 8 * emLength - emBits

            maskedDB.withUnsafeMutableBytes { maskedDBBytes in
                let maskedDBPointer: UnsafeMutablePointer<UInt8> = maskedDBBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
                maskedDBPointer[0] &= 0xff >> UInt8(zeroBits)
            }

            var ret = maskedDB
            ret.append(mPrimeHash)
            ret.append([0xBC] as [UInt8], count: 1)
            return ret
        }

        static func verify_pss_padding(_ digest: DigestAlgorithm,
                                       saltLength: Int,
                                       keyLength: Int,
                                       message: Data,
                                       encMessage: Data) throws -> Bool {
            if keyLength < 16 || saltLength < 0 {
                throw CCError(.paramError)
            }

            guard encMessage.count > 0 else {
                return false
            }

            let emBits = keyLength * 8 - 1
            var emLength = emBits / 8
            if emBits % 8 != 0 {
                emLength += 1
            }

            let hash = Cryptor.digest(message, alg: digest)

            if emLength < hash.count + saltLength + 2 {
                return false
            }
            if encMessage.bytesView[encMessage.count-1] != 0xBC {
                return false
            }
            let zeroBits = 8 * emLength - emBits
            let zeroBitsM = 8 - zeroBits
            let maskedDBLength = emLength - hash.count - 1
            let maskedDB = encMessage.subdata(in: 0..<maskedDBLength)
            if Int(maskedDB.bytesView[0]) >> zeroBitsM != 0 {
                return false
            }
            let mPrimeHash = encMessage.subdata(in: maskedDBLength ..< maskedDBLength + hash.count)
            let dbMask = mgf1(digest, seed: mPrimeHash, maskLength: emLength - hash.count - 1)
            var db = xorData(maskedDB, dbMask)
            db.withUnsafeMutableBytes { dbBytes in
                let dbPointer: UnsafeMutablePointer<UInt8> = dbBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
                dbPointer[0] &= 0xff >> UInt8(zeroBits)
            }

            let zeroLength = emLength - hash.count - saltLength - 2
            let zeroString = Data(count:zeroLength)
            if db.subdata(in: 0 ..< zeroLength) != zeroString {
                return false
            }
            if db.bytesView[zeroLength] != 0x01 {
                return false
            }
            let salt = db.subdata(in: (db.count - saltLength) ..< db.count)
            var mPrime = Data(count:8)
            mPrime.append(hash)
            mPrime.append(salt)
            let mPrimeHash2 = Cryptor.digest(mPrime, alg: digest)
            if mPrimeHash != mPrimeHash2 {
                return false
            }
            return true
        }

        static func available() -> Bool {
            return CCRSACryptorGeneratePair != nil &&
                CCRSACryptorGetPublicKeyFromPrivateKey != nil &&
                CCRSACryptorRelease != nil &&
                CCRSAGetKeyType != nil &&
                CCRSAGetKeySize != nil &&
                CCRSACryptorExport != nil &&
                CCRSACryptorImport != nil &&
                CCRSACryptorSign != nil &&
                CCRSACryptorVerify != nil &&
                CCRSACryptorCrypt != nil
        }

        typealias CCRSACryptorRef = UnsafeRawPointer
        typealias CCRSAKeyType = UInt32
        enum KeyType: CCRSAKeyType {
            case publicKey = 0, privateKey
            case blankPublicKey = 97, blankPrivateKey
            case badKey = 99
        }
    }
}
