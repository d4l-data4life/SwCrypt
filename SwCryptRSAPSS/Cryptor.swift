import Foundation

public class SwKeyConvert {

	public enum SwError: Error {
		case invalidKey
		case badPassphrase
		case keyNotEncrypted

		public static var debugLevel = 1

		init(_ type: SwError, function: String = #function, file: String = #file, line: Int = #line) {
			self = type
			if SwError.debugLevel > 0 {
				print("\(file):\(line): [\(function)] \(self._domain): \(self)")
			}
		}
	}

	open class PrivateKey {

		public static func pemToPKCS1DER(_ pemKey: String) throws -> Data {
			guard let derKey = try? PEM.PrivateKey.toDER(pemKey) else {
				throw SwError(.invalidKey)
			}
			guard let pkcs1DERKey = PKCS8.PrivateKey.stripHeaderIfAny(derKey) else {
				throw SwError(.invalidKey)
			}
			return pkcs1DERKey
		}

		public static func derToPKCS1PEM(_ derKey: Data) -> String {
			return PEM.PrivateKey.toPEM(derKey)
		}

		public typealias EncMode = PEM.EncryptedPrivateKey.EncMode

		public static func encryptPEM(_ pemKey: String, passphrase: String,
									mode: EncMode) throws -> String {
			do {
				let derKey = try PEM.PrivateKey.toDER(pemKey)
				return PEM.EncryptedPrivateKey.toPEM(derKey, passphrase: passphrase, mode: mode)
			} catch {
				throw SwError(.invalidKey)
			}
		}

		public static func decryptPEM(_ pemKey: String, passphrase: String) throws -> String {
			do {
				let derKey = try PEM.EncryptedPrivateKey.toDER(pemKey, passphrase: passphrase)
				return PEM.PrivateKey.toPEM(derKey)
			} catch PEM.SwError.badPassphrase {
				throw SwError(.badPassphrase)
			} catch PEM.SwError.keyNotEncrypted {
				throw SwError(.keyNotEncrypted)
			} catch {
				throw SwError(.invalidKey)
			}
		}
	}

	open class PublicKey {

		public static func pemToPKCS1DER(_ pemKey: String) throws -> Data {
			guard let derKey = try? PEM.PublicKey.toDER(pemKey) else {
				throw SwError(.invalidKey)
			}
			guard let pkcs1DERKey = PKCS8.PublicKey.stripHeaderIfAny(derKey) else {
				throw SwError(.invalidKey)
			}
			return pkcs1DERKey
		}

		public static func pemToPKCS8DER(_ pemKey: String) throws -> Data {
			guard let derKey = try? PEM.PublicKey.toDER(pemKey) else {
				throw SwError(.invalidKey)
			}
			return derKey
		}

		public static func derToPKCS1PEM(_ derKey: Data) -> String {
			return PEM.PublicKey.toPEM(derKey)
		}

		public static func derToPKCS8PEM(_ derKey: Data) -> String {
			let pkcs8Key = PKCS8.PublicKey.addHeader(derKey)
			return PEM.PublicKey.toPEM(pkcs8Key)
		}
	}
}

open class PKCS8 {

	open class PrivateKey {

		// https://lapo.it/asn1js/
		public static func getPKCS1DEROffset(_ derKey: Data) -> Int? {
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

		public static func stripHeaderIfAny(_ derKey: Data) -> Data? {
			guard let offset = getPKCS1DEROffset(derKey) else {
				return nil
			}
			return derKey.subdata(in: offset..<derKey.count)
		}

		public static func hasCorrectHeader(_ derKey: Data) -> Bool {
			return getPKCS1DEROffset(derKey) != nil
		}

	}

	open class PublicKey {

		public static func addHeader(_ derKey: Data) -> Data {
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
		public static func getPKCS1DEROffset(_ derKey: Data) -> Int? {
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

		public static func stripHeaderIfAny(_ derKey: Data) -> Data? {
			guard let offset = getPKCS1DEROffset(derKey) else {
				return nil
			}
			return derKey.subdata(in: offset..<derKey.count)
		}

		public static func hasCorrectHeader(_ derKey: Data) -> Bool {
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

open class PEM {

	public enum SwError: Error {
		case parse(String)
		case badPassphrase
		case keyNotEncrypted

		public static var debugLevel = 1

		init(_ type: SwError, function: String = #function, file: String = #file, line: Int = #line) {
			self = type
			if SwError.debugLevel > 0 {
				print("\(file):\(line): [\(function)] \(self._domain): \(self)")
			}
		}
	}

	open class PrivateKey {

		public static func toDER(_ pemKey: String) throws -> Data {
			guard let strippedKey = stripHeader(pemKey) else {
				throw SwError(.parse("header"))
			}
			guard let data = PEM.base64Decode(strippedKey) else {
				throw SwError(.parse("base64decode"))
			}
			return data
		}

		public static func toPEM(_ derKey: Data) -> String {
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

	open class PublicKey {

		public static func toDER(_ pemKey: String) throws -> Data {
			guard let strippedKey = stripHeader(pemKey) else {
				throw SwError(.parse("header"))
			}
			guard let data = PEM.base64Decode(strippedKey) else {
				throw SwError(.parse("base64decode"))
			}
			return data
		}

		public static func toPEM(_ derKey: Data) -> String {
			let base64 = PEM.base64Encode(derKey)
			return addHeader(base64)
		}

		fileprivate static let pemPrefix = "-----BEGIN PUBLIC KEY-----\n"
		fileprivate static let pemSuffix = "\n-----END PUBLIC KEY-----"

		fileprivate static func addHeader(_ base64: String) -> String {
			return pemPrefix + base64 + pemSuffix
		}

		fileprivate static func stripHeader(_ pemKey: String) -> String? {
			return PEM.stripHeaderFooter(pemKey, header: pemPrefix, footer: pemSuffix)
		}
	}

	// OpenSSL PKCS#1 compatible encrypted private key
	open class EncryptedPrivateKey {

		public enum EncMode {
			case aes128CBC, aes256CBC
		}

		public static func toDER(_ pemKey: String, passphrase: String) throws -> Data {
			guard let strippedKey = PrivateKey.stripHeader(pemKey) else {
				throw SwError(.parse("header"))
			}
			guard let mode = getEncMode(strippedKey) else {
				throw SwError(.keyNotEncrypted)
			}
			guard let iv = getIV(strippedKey) else {
				throw SwError(.parse("iv"))
			}
			let aesKey = getAESKey(mode, passphrase: passphrase, iv: iv)
			let base64Data = String(strippedKey[strippedKey.index(strippedKey.startIndex, offsetBy: aesHeaderLength)...])
			guard let data = PEM.base64Decode(base64Data) else {
				throw SwError(.parse("base64decode"))
			}
			guard let decrypted = try? decryptKey(data, key: aesKey, iv: iv) else {
				throw SwError(.badPassphrase)
			}
			guard PKCS8.PrivateKey.hasCorrectHeader(decrypted) else {
				throw SwError(.badPassphrase)
			}
			return decrypted
		}

		public static func toPEM(_ derKey: Data, passphrase: String, mode: EncMode) -> String {
			let iv = Cryptor.generateRandom(16)
			let aesKey = getAESKey(mode, passphrase: passphrase, iv: iv)
			let encrypted = encryptKey(derKey, key: aesKey, iv: iv)
			let encryptedDERKey = addEncryptHeader(encrypted, iv: iv, mode: mode)
			return PrivateKey.addRSAHeader(encryptedDERKey)
		}

		fileprivate static let aes128CBCInfo = "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,"
		fileprivate static let aes256CBCInfo = "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,"
		fileprivate static let aesInfoLength = aes128CBCInfo.count
		fileprivate static let aesIVInHexLength = 32
		fileprivate static let aesHeaderLength = aesInfoLength + aesIVInHexLength

		fileprivate static func addEncryptHeader(_ key: Data, iv: Data, mode: EncMode) -> String {
			return getHeader(mode) + iv.hexadecimalString() + "\n\n" + PEM.base64Encode(key)
		}

		fileprivate static func getHeader(_ mode: EncMode) -> String {
			switch mode {
			case .aes128CBC: return aes128CBCInfo
			case .aes256CBC: return aes256CBCInfo
			}
		}

		fileprivate static func getEncMode(_ strippedKey: String) -> EncMode? {
			if strippedKey.hasPrefix(aes128CBCInfo) {
				return .aes128CBC
			}
			if strippedKey.hasPrefix(aes256CBCInfo) {
				return .aes256CBC
			}
			return nil
		}

		fileprivate static func getIV(_ strippedKey: String) -> Data? {
			let ivInHex = String(strippedKey[strippedKey.index(strippedKey.startIndex, offsetBy: aesInfoLength) ..< strippedKey.index(strippedKey.startIndex, offsetBy: aesHeaderLength)])
			return ivInHex.dataFromHexadecimalString()
		}

		fileprivate static func getAESKey(_ mode: EncMode, passphrase: String, iv: Data) -> Data {
			switch mode {
			case .aes128CBC: return getAES128Key(passphrase, iv: iv)
			case .aes256CBC: return getAES256Key(passphrase, iv: iv)
			}
		}

		fileprivate static func getAES128Key(_ passphrase: String, iv: Data) -> Data {
			// 128bit_Key = MD5(Passphrase + Salt)
			let pass = passphrase.data(using: String.Encoding.utf8)!
			let salt = iv.subdata(in: 0..<8)

			var key = pass
			key.append(salt)
			return Cryptor.digest(key, alg: .md5)
		}

		fileprivate static func getAES256Key(_ passphrase: String, iv: Data) -> Data {
			// 128bit_Key = MD5(Passphrase + Salt)
			// 256bit_Key = 128bit_Key + MD5(128bit_Key + Passphrase + Salt)
			let pass = passphrase.data(using: String.Encoding.utf8)!
			let salt = iv.subdata(in: 0 ..< 8)

			var first = pass
			first.append(salt)
			let aes128Key = Cryptor.digest(first, alg: .md5)

			var sec = aes128Key
			sec.append(pass)
			sec.append(salt)

			var aes256Key = aes128Key
			aes256Key.append(Cryptor.digest(sec, alg: .md5))
			return aes256Key
		}

		fileprivate static func encryptKey(_ data: Data, key: Data, iv: Data) -> Data {
			return try! Cryptor.crypt(
				.encrypt, blockMode: .cbc, algorithm: .aes, padding: .pkcs7Padding,
				data: data, key: key, iv: iv)
		}

		fileprivate static func decryptKey(_ data: Data, key: Data, iv: Data) throws -> Data {
			return try Cryptor.crypt(
				.decrypt, blockMode: .cbc, algorithm: .aes, padding: .pkcs7Padding,
				data: data, key: key, iv: iv)
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


public final class Cryptor {

	public typealias CCCryptorStatus = Int32
	public enum CCError: CCCryptorStatus, Error {
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

		public static var debugLevel = 1

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

	public static func generateRandom(_ size: Int) -> Data {
		var data = Data(count: size)
		data.withUnsafeMutableBytes { dataBytes in
            _ = CCRandomGenerateBytes!(dataBytes.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                       size)
		}
		return data
	}

	public typealias CCDigestAlgorithm = UInt32
	public enum DigestAlgorithm: CCDigestAlgorithm {
		case none = 0
		case md5 = 3
		case rmd128 = 4, rmd160 = 5, rmd256 = 6, rmd320 = 7
		case sha1 = 8
		case sha224 = 9, sha256 = 10, sha384 = 11, sha512 = 12

		var length: Int {
			return CCDigestGetOutputSize!(self.rawValue)
		}
	}

	public static func digest(_ data: Data, alg: DigestAlgorithm) -> Data {
		var output = Data(count: alg.length)
		withUnsafePointers(data, &output, { dataBytes, outputBytes in
			_ = CCDigest!(alg.rawValue,
						  dataBytes,
						  data.count,
						  outputBytes)
		})
		return output
	}

	public typealias CCHmacAlgorithm = UInt32
	public enum HMACAlg: CCHmacAlgorithm {
		case sha1, md5, sha256, sha384, sha512, sha224

		var digestLength: Int {
			switch self {
			case .sha1: return 20
			case .md5: return 16
			case .sha256: return 32
			case .sha384: return 48
			case .sha512: return 64
			case .sha224: return 28
			}
		}
	}

	public static func HMAC(_ data: Data, alg: HMACAlg, key: Data) -> Data {
		var buffer = Data(count: alg.digestLength)
		withUnsafePointers(key, data, &buffer, { keyBytes, dataBytes, bufferBytes in
			CCHmac!(alg.rawValue,
					keyBytes, key.count,
					dataBytes, data.count,
					bufferBytes)
		})
		return buffer
	}

	public typealias CCOperation = UInt32
	public enum OpMode: CCOperation {
		case encrypt = 0, decrypt
	}

	public typealias CCMode = UInt32
	public enum BlockMode: CCMode {
		case ecb = 1, cbc, cfb, ctr, f8, lrw, ofb, xts, rc4, cfb8
		var needIV: Bool {
			switch self {
			case .cbc, .cfb, .ctr, .ofb, .cfb8: return true
			default: return false
			}
		}
	}

	public enum AuthBlockMode: CCMode {
		case gcm = 11, ccm
	}

	public typealias CCAlgorithm = UInt32
	public enum Algorithm: CCAlgorithm {
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

	public typealias CCPadding = UInt32
	public enum Padding: CCPadding {
		case noPadding = 0, pkcs7Padding
	}

	public static func crypt(_ opMode: OpMode, blockMode: BlockMode,
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

	public static func digestAvailable() -> Bool {
		return CCDigest != nil &&
			CCDigestGetOutputSize != nil
	}

	public static func randomAvailable() -> Bool {
		return CCRandomGenerateBytes != nil
	}

	public static func hmacAvailable() -> Bool {
		return CCHmac != nil
	}

	public static func cryptorAvailable() -> Bool {
		return CCCryptorCreateWithMode != nil &&
			CCCryptorGetOutputLength != nil &&
			CCCryptorUpdate != nil &&
			CCCryptorFinal != nil &&
			CCCryptorRelease != nil
	}

	public static func available() -> Bool {
		return digestAvailable() &&
			randomAvailable() &&
			hmacAvailable() &&
			cryptorAvailable() &&
			RSA.available() 
	}

	fileprivate typealias CCCryptorRef = UnsafeRawPointer
	fileprivate typealias CCRNGStatus = CCCryptorStatus
	fileprivate typealias CC_LONG = UInt32
	fileprivate typealias CCModeOptions = UInt32

	fileprivate typealias CCRandomGenerateBytesT = @convention(c) (
		_ bytes: UnsafeMutableRawPointer,
		_ count: size_t) -> CCRNGStatus
	fileprivate typealias CCDigestGetOutputSizeT = @convention(c) (
		_ algorithm: CCDigestAlgorithm) -> size_t
	fileprivate typealias CCDigestT = @convention(c) (
		_ algorithm: CCDigestAlgorithm,
		_ data: UnsafeRawPointer,
		_ dataLen: size_t,
		_ output: UnsafeMutableRawPointer) -> CInt

	fileprivate typealias CCHmacT = @convention(c) (
		_ algorithm: CCHmacAlgorithm,
		_ key: UnsafeRawPointer,
		_ keyLength: Int,
		_ data: UnsafeRawPointer,
		_ dataLength: Int,
		_ macOut: UnsafeMutableRawPointer) -> Void
	fileprivate typealias CCCryptorCreateWithModeT = @convention(c)(
		_ op: CCOperation,
		_ mode: CCMode,
		_ alg: CCAlgorithm,
		_ padding: CCPadding,
		_ iv: UnsafeRawPointer?,
		_ key: UnsafeRawPointer, _ keyLength: Int,
		_ tweak: UnsafeRawPointer?, _ tweakLength: Int,
		_ numRounds: Int32, _ options: CCModeOptions,
		_ cryptorRef: UnsafeMutablePointer<CCCryptorRef?>) -> CCCryptorStatus
	fileprivate typealias CCCryptorGetOutputLengthT = @convention(c)(
		_ cryptorRef: CCCryptorRef,
		_ inputLength: size_t,
		_ final: Bool) -> size_t
	fileprivate typealias CCCryptorUpdateT = @convention(c)(
		_ cryptorRef: CCCryptorRef,
		_ dataIn: UnsafeRawPointer,
		_ dataInLength: Int,
		_ dataOut: UnsafeMutableRawPointer,
		_ dataOutAvailable: Int,
		_ dataOutMoved: UnsafeMutablePointer<Int>) -> CCCryptorStatus
	fileprivate typealias CCCryptorFinalT = @convention(c)(
		_ cryptorRef: CCCryptorRef,
		_ dataOut: UnsafeMutableRawPointer,
		_ dataOutAvailable: Int,
		_ dataOutMoved: UnsafeMutablePointer<Int>) -> CCCryptorStatus
	fileprivate typealias CCCryptorReleaseT = @convention(c)
		(_ cryptorRef: CCCryptorRef) -> CCCryptorStatus


	fileprivate static let dl = dlopen("/usr/lib/system/libcommonCrypto.dylib", RTLD_NOW)
	fileprivate static let CCRandomGenerateBytes: CCRandomGenerateBytesT? =
		getFunc(dl!, f: "CCRandomGenerateBytes")
	fileprivate static let CCDigestGetOutputSize: CCDigestGetOutputSizeT? =
		getFunc(dl!, f: "CCDigestGetOutputSize")
	fileprivate static let CCDigest: CCDigestT? = getFunc(dl!, f: "CCDigest")
	fileprivate static let CCHmac: CCHmacT? = getFunc(dl!, f: "CCHmac")
	fileprivate static let CCCryptorCreateWithMode: CCCryptorCreateWithModeT? =
		getFunc(dl!, f: "CCCryptorCreateWithMode")
	fileprivate static let CCCryptorGetOutputLength: CCCryptorGetOutputLengthT? =
		getFunc(dl!, f: "CCCryptorGetOutputLength")
	fileprivate static let CCCryptorUpdate: CCCryptorUpdateT? =
		getFunc(dl!, f: "CCCryptorUpdate")
	fileprivate static let CCCryptorFinal: CCCryptorFinalT? =
		getFunc(dl!, f: "CCCryptorFinal")
	fileprivate static let CCCryptorRelease: CCCryptorReleaseT? =
		getFunc(dl!, f: "CCCryptorRelease")

	open class RSA {

		public enum AsymmetricSAPadding: UInt32 {
			case pss = 1002
		}

		public static func generateKeyPair(_ keySize: Int = 4096) throws -> (Data, Data) {
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

		public static func getPublicKeyFromPrivateKey(_ derKey: Data) throws -> Data {
			let key = try importFromDERKey(derKey)
			defer { CCRSACryptorRelease!(key) }

			guard getKeyType(key) == .privateKey else { throw CCError(.paramError) }

			let publicKey = CCRSACryptorGetPublicKeyFromPrivateKey!(key)
			defer { CCRSACryptorRelease!(publicKey) }

			let pubDERKey = try exportToDERKey(publicKey)

			return pubDERKey
		}

		fileprivate static func importFromDERKey(_ derKey: Data) throws -> CCRSACryptorRef {
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

		fileprivate static func exportToDERKey(_ key: CCRSACryptorRef) throws -> Data {
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

		fileprivate static func getKeyType(_ key: CCRSACryptorRef) -> KeyType {
			return KeyType(rawValue: CCRSAGetKeyType!(key))!
		}

		fileprivate static func getKeySize(_ key: CCRSACryptorRef) -> Int {
			return Int(CCRSAGetKeySize!(key)/8)
		}

		public static func sign(_ message: Data,
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

		public static func verify(_ message: Data, derKey: Data, padding: AsymmetricSAPadding,
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

		fileprivate static func crypt(_ data: Data, key: CCRSACryptorRef) throws -> Data {
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

		fileprivate static func mgf1(_ digest: DigestAlgorithm,
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

		fileprivate static func xorData(_ data1: Data, _ data2: Data) -> Data {
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

		fileprivate static func add_pss_padding(_ digest: DigestAlgorithm,
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

		fileprivate static func verify_pss_padding(_ digest: DigestAlgorithm,
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


		public static func available() -> Bool {
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

		fileprivate typealias CCRSACryptorRef = UnsafeRawPointer
		fileprivate typealias CCRSAKeyType = UInt32
		fileprivate enum KeyType: CCRSAKeyType {
			case publicKey = 0, privateKey
			case blankPublicKey = 97, blankPrivateKey
			case badKey = 99
		}

		fileprivate typealias CCRSACryptorGeneratePairT = @convention(c) (
			_ keySize: Int,
			_ e: UInt32,
			_ publicKey: UnsafeMutablePointer<CCRSACryptorRef?>,
			_ privateKey: UnsafeMutablePointer<CCRSACryptorRef?>) -> CCCryptorStatus
		fileprivate static let CCRSACryptorGeneratePair: CCRSACryptorGeneratePairT? =
			getFunc(Cryptor.dl!, f: "CCRSACryptorGeneratePair")

		fileprivate typealias CCRSACryptorGetPublicKeyFromPrivateKeyT = @convention(c) (CCRSACryptorRef) -> CCRSACryptorRef
		fileprivate static let CCRSACryptorGetPublicKeyFromPrivateKey: CCRSACryptorGetPublicKeyFromPrivateKeyT? =
			getFunc(Cryptor.dl!, f: "CCRSACryptorGetPublicKeyFromPrivateKey")

		fileprivate typealias CCRSACryptorReleaseT = @convention(c) (CCRSACryptorRef) -> Void
		fileprivate static let CCRSACryptorRelease: CCRSACryptorReleaseT? =
			getFunc(dl!, f: "CCRSACryptorRelease")

		fileprivate typealias CCRSAGetKeyTypeT = @convention(c) (CCRSACryptorRef) -> CCRSAKeyType
		fileprivate static let CCRSAGetKeyType: CCRSAGetKeyTypeT? = getFunc(dl!, f: "CCRSAGetKeyType")

		fileprivate typealias CCRSAGetKeySizeT = @convention(c) (CCRSACryptorRef) -> Int32
		fileprivate static let CCRSAGetKeySize: CCRSAGetKeySizeT? = getFunc(dl!, f: "CCRSAGetKeySize")

		fileprivate typealias CCRSACryptorExportT = @convention(c) (
			_ key: CCRSACryptorRef,
			_ out: UnsafeMutableRawPointer,
			_ outLen: UnsafeMutablePointer<Int>) -> CCCryptorStatus
		fileprivate static let CCRSACryptorExport: CCRSACryptorExportT? =
			getFunc(dl!, f: "CCRSACryptorExport")

		fileprivate typealias CCRSACryptorImportT = @convention(c) (
			_ keyPackage: UnsafeRawPointer,
			_ keyPackageLen: Int,
			_ key: UnsafeMutablePointer<CCRSACryptorRef?>) -> CCCryptorStatus
		fileprivate static let CCRSACryptorImport: CCRSACryptorImportT? =
			getFunc(dl!, f: "CCRSACryptorImport")

		fileprivate typealias CCRSACryptorSignT = @convention(c) (
			_ privateKey: CCRSACryptorRef,
			_ hashToSign: UnsafeRawPointer,
			_ hashSignLen: size_t,
			_ digestType: CCDigestAlgorithm,
			_ saltLen: size_t,
			_ signedData: UnsafeMutableRawPointer,
			_ signedDataLen: UnsafeMutablePointer<Int>) -> CCCryptorStatus
		fileprivate static let CCRSACryptorSign: CCRSACryptorSignT? =
			getFunc(dl!, f: "CCRSACryptorSign")

		fileprivate typealias CCRSACryptorVerifyT = @convention(c) (
			_ publicKey: CCRSACryptorRef,
			_ hash: UnsafeRawPointer,
			_ hashLen: size_t,
			_ digestType: CCDigestAlgorithm,
			_ saltLen: size_t,
			_ signedData: UnsafeRawPointer,
			_ signedDataLen: size_t) -> CCCryptorStatus
		fileprivate static let CCRSACryptorVerify: CCRSACryptorVerifyT? =
			getFunc(dl!, f: "CCRSACryptorVerify")

		fileprivate typealias CCRSACryptorCryptT = @convention(c) (
			_ rsaKey: CCRSACryptorRef,
			_ data: UnsafeRawPointer, _ dataLength: size_t,
			_ out: UnsafeMutableRawPointer,
			_ outLength: UnsafeMutablePointer<size_t>) -> CCCryptorStatus
		fileprivate static let CCRSACryptorCrypt: CCRSACryptorCryptT? =
			getFunc(dl!, f: "CCRSACryptorCrypt")
	}
}

private func getFunc<T>(_ from: UnsafeMutableRawPointer, f: String) -> T? {
	let sym = dlsym(from, f)
	guard sym != nil else {
		return nil
	}
	return unsafeBitCast(sym, to: T.self)
}
