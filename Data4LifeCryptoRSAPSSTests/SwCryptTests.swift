import XCTest
@testable import Data4LifeCryptoRSAPSS

class Data4LifeCryptoRSAPSSTests: XCTestCase {

    private let keyPair = try? Data4LifeCryptoRSAPSSTests.createKeyPair(2048)

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
		XCTAssert(Cryptor.cryptorAvailable())
		XCTAssert(Cryptor.RSA.available())
		XCTAssert(Cryptor.available())
	}

	func testDigest() {
		XCTAssert(Cryptor.digestAvailable())
		let testData = "rokafogtacsuka".data(using: String.Encoding.utf8)!
		let sha256 = "ae6ab1cf65971f88b9cd92c2f334d6a99beaf5b40240d4b440fdb4a1231db0f0"
			.dataFromHexadecimalString()!
		XCTAssert(Cryptor.digest(testData, alg: .sha256) == sha256)
	}

	func testRandom() {
		XCTAssert(Cryptor.randomAvailable())
		_ = Cryptor.generateRandom(10)
	}

    func testCreateKeyPair() {
		XCTAssert(keyPair != nil)
	}
    
    func testGetPublicKeyFromPrivateKey() {
        let priv = Fixture.privatePEM
        let pub = Fixture.publicPEM
        let privKey = try? KeyConverter.PrivateKey.pemToPKCS1DER(priv)
        let pubKey = try? KeyConverter.PublicKey.pemToPKCS1DER(pub)
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
