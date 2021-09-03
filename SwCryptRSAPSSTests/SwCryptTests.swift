import XCTest
@testable import SwCryptRSAPSS

let keyPair = try? SwCryptTest.createKeyPair(2048)

class SwCryptTest: XCTestCase {

    override func setUp() {
        super.setUp()
		self.continueAfterFailure = false
    }

    override func tearDown() {
        super.tearDown()
    }

	static func createKeyPair(_ size: Int) throws -> (Data, Data) {
		return try Cryptor.RSA.generateKeyPair(size)
	}

	func testAvailable() {
		XCTAssert(Cryptor.digestAvailable())
		XCTAssert(Cryptor.randomAvailable())
		XCTAssert(Cryptor.hmacAvailable())
		XCTAssert(Cryptor.cryptorAvailable())
		XCTAssert(Cryptor.RSA.available())
		XCTAssert(Cryptor.available())
	}

	func testDigest() {
		XCTAssert(Cryptor.digestAvailable())
		let testData = "rokafogtacsuka".data(using: String.Encoding.utf8)!
		let sha1 = "9e421ffa8b2c83ac23e96bc9f9302f4a16311037".dataFromHexadecimalString()!
		let sha256 = "ae6ab1cf65971f88b9cd92c2f334d6a99beaf5b40240d4b440fdb4a1231db0f0"
			.dataFromHexadecimalString()!
		let sha384 = ("acf011a346e96364091bd21415a2437273c7f3c84060b21ac19f2eafa1c6cde76467b0b0" +
			"aba99626b18aa3da83e442db").dataFromHexadecimalString()!
		let sha512 = ("016748fad47ddfba4fcd19aacc67ee031dfef40f5e9692c84f8846e520f2a827a4ea5035" +
			"af8a66686c60796a362c30e6c473cfdbb9d86f43312001fc0b660734").dataFromHexadecimalString()!
		let sha224 = "ec92519bb9e82a79097b0dd0618927b3262a70d6f02bd667c413009e"
			.dataFromHexadecimalString()!
		let md5 = "9b43f853613732cfc8531ed6bcbf6d68".dataFromHexadecimalString()!
		XCTAssert(Cryptor.digest(testData, alg: .sha1) == sha1)
		XCTAssert(Cryptor.digest(testData, alg: .sha256) == sha256)
		XCTAssert(Cryptor.digest(testData, alg: .sha384) == sha384)
		XCTAssert(Cryptor.digest(testData, alg: .sha512) == sha512)
		XCTAssert(Cryptor.digest(testData, alg: .sha224) == sha224)
		XCTAssert(Cryptor.digest(testData, alg: .md5) == md5)
	}

	func testRandom() {
		XCTAssert(Cryptor.randomAvailable())
		_ = Cryptor.generateRandom(10)
	}

    func testCreateKeyPair() {
		XCTAssert(keyPair != nil)
	}

	func encryptKey(_ enc: SwKeyConvert.PrivateKey.EncMode) {
		let pass = "hello"
		let (priv, _) = keyPair!
		let privKey = SwKeyConvert.PrivateKey.derToPKCS1PEM(priv)

		let privEncrypted = try? SwKeyConvert.PrivateKey.encryptPEM(privKey, passphrase: pass, mode: enc)
		XCTAssert(privEncrypted != nil)
		let privDecrypted = try? SwKeyConvert.PrivateKey.decryptPEM(privEncrypted!, passphrase: pass)
		XCTAssert(privDecrypted != nil)
		XCTAssert(privDecrypted == privKey)
	}

	func testEncryptKey() {
		encryptKey(.aes128CBC)
		encryptKey(.aes256CBC)
	}

	func testKeyNotEncrypted() {
        let decPEM = Fixture.privateDecryptedPEM
		XCTAssertThrowsError(try SwKeyConvert.PrivateKey.decryptPEM(decPEM, passphrase: "hello")) {
			XCTAssert($0 as? SwKeyConvert.SwError == SwKeyConvert.SwError.keyNotEncrypted)
		}
	}

	func testKeyInvalid() {
		var decPEM = Fixture.privateDecryptedPEM
		decPEM = "a" + decPEM
		XCTAssertThrowsError(try SwKeyConvert.PrivateKey.decryptPEM(decPEM, passphrase: "hello")) {
			XCTAssert($0 as? SwKeyConvert.SwError == SwKeyConvert.SwError.invalidKey)
		}
	}

	func decryptOpenSSLKeys(_ type: String) {
		let encPEM = Fixture.privateEncryptedPEMAES128
        let decPEM = Fixture.privateDecryptedPEM
		let d = try? SwKeyConvert.PrivateKey.decryptPEM(encPEM, passphrase: "hello")
		XCTAssert(d != nil)
		XCTAssert(d! == decPEM)
	}

	func decryptOpenSSLKeysBadPassphrase(_ type: String) {
		let encPEM = Fixture.privateEncryptedPEMAES128

		XCTAssertThrowsError(try SwKeyConvert.PrivateKey.decryptPEM(encPEM, passphrase: "nohello")) {
			XCTAssert($0 as? SwKeyConvert.SwError == SwKeyConvert.SwError.badPassphrase)
		}
	}

	func testOpenSSLKeyPair() {
        let priv = Fixture.privatePEM
        let pub = Fixture.publicPEM
		let privKey = try? SwKeyConvert.PrivateKey.pemToPKCS1DER(priv)
		XCTAssert(privKey != nil)
		let pubKey = try? SwKeyConvert.PublicKey.pemToPKCS1DER(pub)
		XCTAssert(pubKey != nil)
	}

	func testOpenSSLKeys() {
		decryptOpenSSLKeys("128")
		decryptOpenSSLKeys("256")
		decryptOpenSSLKeysBadPassphrase("128")
		decryptOpenSSLKeysBadPassphrase("256")
	}
    
    func testGetPublicKeyFromPrivateKey() {
        let priv = Fixture.privatePEM
        let pub = Fixture.publicPEM
        let privKey = try? SwKeyConvert.PrivateKey.pemToPKCS1DER(priv)
        let pubKey = try? SwKeyConvert.PublicKey.pemToPKCS1DER(pub)
        let genPubKey = try? Cryptor.RSA.getPublicKeyFromPrivateKey(privKey!)
            XCTAssert(pubKey == genPubKey)
    }

	func signVerify(_ privKey: Data, pubKey:Data, padding: Cryptor.RSA.AsymmetricSAPadding) {
		let testMessage = "rirararom_vagy_rararirom".data(using: String.Encoding.utf8)!
		let sign = try? Cryptor.RSA.sign(testMessage, derKey: privKey, padding: padding,
		                            digest: .sha256, saltLen: 16)
		XCTAssert(sign != nil)
		let verified = try? Cryptor.RSA.verify(testMessage, derKey: pubKey, padding: padding,
		                                  digest: .sha256, saltLen: 16, signedData: sign!)
		XCTAssert(verified != nil && verified! == true)
	}

	func testSignVerify() {
		let (priv, pub) = keyPair!
		signVerify(priv, pubKey: pub, padding: .pss)
	}
}
