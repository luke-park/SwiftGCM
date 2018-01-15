import Foundation

public class SwiftGCM {
    private static let keySize128: Int = 16
    private static let keySize192: Int = 24
    private static let keySize256: Int = 32
    private static let requiredNonceSize: Int = 12
    private static let blockSize: Int = 16
    private static let emptyCounter: Data = Data(bytes: [0, 0, 0, 1])
    private static let emptyBlock: Data = Data(bytes: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    
    private let key: Data
    private var counter: UInt128
    private let used: Bool
    
    // Constructor.
    init(key: Data, nonce: Data) throws {
        if key.count != SwiftGCM.keySize128 && key.count != SwiftGCM.keySize192 && key.count != SwiftGCM.keySize256 {
            throw SwiftGCMError.invalidKeySize
        }
        if nonce.count != SwiftGCM.requiredNonceSize {
            throw SwiftGCMError.invalidNonceSize
        }
        
        self.key = key
        self.counter = SwiftGCM.makeCounter(nonce: nonce)
        self.used = false
    }
    
    // Encrypt/Decrypt.
    public func encrypt(auth: Data?, plaintext: Data) throws -> Data {
        if used { throw SwiftGCMError.instanceAlreadyUsed }
        
        let dataPadded: Data = GaloisField.padToBlockSize(plaintext)
        let blockCount: Int = dataPadded.count / SwiftGCM.blockSize
        let h: Data = try encryptBlock(data: SwiftGCM.emptyBlock)
        let eky0: Data = try encryptBlock(data: counter.getData())
        let authData: Data = (auth != nil ? auth! : Data())
        var ct: Data = Data()
        
        for i in 0..<blockCount {
            counter = counter.increment()
            let ekyi: Data = try encryptBlock(data: counter.getData())
            
            let ptBlock: Data = dataPadded[i * SwiftGCM.blockSize..<i * SwiftGCM.blockSize + SwiftGCM.blockSize]
            ct.append(SwiftGCM.xorData(d1: ptBlock, d2: ekyi))
        }
        
        ct = ct[0..<plaintext.count]
        
        let ghash: UInt128 = GaloisField.hash(h: UInt128(raw: h, offset: 0), a: authData, c: ct)
        let t: Data = (ghash ^ UInt128(raw: eky0, offset: 0)).getData()
        var result: Data = Data()
        
        result.append(ct)
        result.append(t)
        
        used = true
        return result
    }
    public func decrypt(auth: Data?, ciphertext: Data) throws -> Data {
        if used { throw SwiftGCMError.instanceAlreadyUsed }
        
        let ct: Data = ciphertext[0..<ciphertext.count - SwiftGCM.blockSize]
        let givenT: Data = ciphertext[(ciphertext.count - SwiftGCM.blockSize)...]
        
        let h: Data = try encryptBlock(data: SwiftGCM.emptyBlock)
        let eky0: Data = try encryptBlock(data: counter.getData())
        let authData: Data = (auth != nil ? auth! : Data())
        let ghash: UInt128 = GaloisField.hash(h: UInt128(raw: h, offset: 0), a: authData, c: ct)
        let computedT: Data = (ghash ^ UInt128(raw: eky0, offset: 0)).getData()
        
        if !SwiftGCM.tsCompare(d1: computedT, d2: givenT) {
            throw SwiftGCMError.authTagValidation
        }
        
        let dataPadded: Data = GaloisField.padToBlockSize(ct)
        let blockCount: Int = dataPadded.count / SwiftGCM.blockSize

        var pt: Data = Data()
        
        for i in 0..<blockCount {
            counter = counter.increment()
            let ekyi: Data = try encryptBlock(data: counter.getData())
            
            let ctBlock: Data = dataPadded[i * SwiftGCM.blockSize..<i * SwiftGCM.blockSize + SwiftGCM.blockSize]
            pt.append(SwiftGCM.xorData(d1: ctBlock, d2: ekyi))
        }
        
        pt = pt[0..<ct.count]
        
        used = true
        return pt
    }
    private func encryptBlock(data: Data) throws -> Data {
        if data.count != SwiftGCM.blockSize {
            throw SwiftGCMError.invalidDataSize
        }
        
        var dataMutable: Data = data
        var keyMutable: Data = key
        
        let operation: UInt32 = CCOperation(kCCEncrypt)
        let algorithm: UInt32 = CCAlgorithm(kCCAlgorithmAES)
        let options: UInt32 = CCOptions(kCCOptionECBMode)
        
        var ct: Data = Data(count: data.count)
        var num: size_t = 0
        
        let status = ct.withUnsafeMutableBytes { ctRaw in
            dataMutable.withUnsafeMutableBytes { dataRaw in
                keyMutable.withUnsafeMutableBytes{ keyRaw in
                    CCCrypt(operation, algorithm, options, keyRaw, key.count, nil, dataRaw, data.count, ctRaw, ct.count, &num)
                }
            }
        }
        
        if status != kCCSuccess {
            throw SwiftGCMError.commonCryptoError(err: status)
        }
        
        return ct
    }
    
    // Counter.
    private static func makeCounter(nonce: Data) -> UInt128 {
        var result = Data()
        
        result.append(nonce)
        result.append(SwiftGCM.emptyCounter)
        
        return UInt128(raw: result, offset: 0)
    }
    
    // Misc.
    private static func xorData(d1: Data, d2: Data) -> Data {
        var d1a: [UInt8] = [UInt8](d1)
        var d2a: [UInt8] = [UInt8](d2)
        var result: Data = Data(count: d1.count)
        
        for i in 0..<d1.count {
            let n1: UInt8 = d1a[i]
            let n2: UInt8 = d2a[i]
            result[i] = n1 ^ n2
        }
        
        return result
    }
    private static func tsCompare(d1: Data, d2: Data) -> Bool {
        if d1.count != d2.count { return false }
        
        var d1a: [UInt8] = [UInt8](d1)
        var d2a: [UInt8] = [UInt8](d2)
        var result: UInt8 = 0
        
        for i in 0..<d1.count {
            result |= d1a[i] ^ d2a[i]
        }
        
        return result == 0
    }
}

public enum SwiftGCMError: Error {
    case invalidKeySize
    case invalidNonceSize
    case invalidDataSize
    case instanceAlreadyUsed
    case commonCryptoError(err: Int32)
    case authTagValidation
}

public class GaloisField {
    private static let one: UInt128 = UInt128(b: 1)
    private static let r: UInt128 = UInt128(a: 0xE100000000000000, b: 0)
    private static let blockSize: Int = 16
    
    // Multiplication GF(2^128).
    public static func multiply(_ x: UInt128, _ y: UInt128) -> UInt128 {
        var z: UInt128 = UInt128(b: 0)
        var v: UInt128 = x
        var k: UInt128 = UInt128(a: 1 << 63, b: 0)
        
        for _ in 0...127 {
            if y & k == k {
                z = z ^ v
            }
            if v & GaloisField.one != GaloisField.one {
                v = UInt128.rightShift(v)
            } else {
                v = UInt128.rightShift(v) ^ r
            }
            k = UInt128.rightShift(k)
        }
        
        return z
    }
    
    // GHASH.
    public static func hash(h: UInt128, a: Data, c: Data) -> UInt128 {
        let ap: Data = padToBlockSize(a)
        let cp: Data = padToBlockSize(c)
        
        let m: Int = ap.count / blockSize
        let n: Int = cp.count / blockSize
        
        var apos: Int = 0
        var cpos: Int = 0
        
        var x: UInt128 = UInt128(b: 0)
        
        for _ in 0...m - 1 {
            let t: UInt128 = x ^ UInt128(raw: ap[apos..<apos + blockSize], offset: apos)
            x = multiply(t, h)
            apos += blockSize
        }
        
        for _ in 0...n - 1 {
            let t: UInt128 = x ^ UInt128(raw: cp[cpos..<cpos + blockSize], offset: cpos)
            x = multiply(t, h)
            cpos += blockSize
        }
        
        let len: UInt128 = UInt128(a: UInt64(a.count * 8), b: UInt64(c.count * 8))
        x = multiply((x ^ len), h)
        
        return x
    }
    
    // Padding.
    public static func padToBlockSize(_ x: Data) -> Data {
        let count: Int = blockSize - x.count % blockSize
        var result: Data = Data()
        
        result.append(x)
        for _ in 1...count {
            result.append(0)
        }
        
        return result
    }
}

public struct UInt128 {
    var a: UInt64
    var b: UInt64
    
    // Constructors.
    init(raw: Data, offset: Int) {
        let ar: Data = raw[offset..<offset + 8]
        let br: Data = raw[offset + 8..<offset + 16]
        
        a = ar.withUnsafeBytes { (p: UnsafePointer<UInt64>) -> UInt64 in
            return p.pointee
        }
        b = br.withUnsafeBytes { (p: UnsafePointer<UInt64>) -> UInt64 in
            return p.pointee
        }
        
        a = a.bigEndian
        b = b.bigEndian
    }
    init (a: UInt64, b: UInt64) {
        self.a = a
        self.b = b
    }
    init (b: UInt64) {
        self.a = 0
        self.b = b
    }
    
    // Data.
    public func getData() -> Data {
        var at: UInt64 = self.a.bigEndian
        var bt: UInt64 = self.b.bigEndian
        
        let ar: Data = Data(bytes: &at, count: MemoryLayout.size(ofValue: at))
        let br: Data = Data(bytes: &bt, count: MemoryLayout.size(ofValue: bt))
        
        var result: Data = Data()
        result.append(ar)
        result.append(br)
        
        return result
    }
    
    // Increment.
    public func increment() -> UInt128 {
        let bn: UInt64 = b + 1
        let an: UInt64 = (bn == 0 ? a + 1 : a)
        return UInt128(a: an, b: bn)
    }
    
    // XOR.
    public static func ^(n1: UInt128, n2: UInt128) -> UInt128 {
        let aX: UInt64 = n1.a ^ n2.a
        let bX: UInt64 = n1.b ^ n2.b
        return UInt128(a: aX, b: bX)
    }
    
    // AND.
    public static func &(n1: UInt128, n2: UInt128) -> UInt128 {
        let aX: UInt64 = n1.a & n2.a
        let bX: UInt64 = n1.b & n2.b
        return UInt128(a: aX, b: bX)
    }
    
    // Right Shift.
    public static func rightShift(_ n: UInt128) -> UInt128 {
        let aX: UInt64 = n.a >> 1
        let bX: UInt64 = n.b >> 1 + ((n.a & 1) << 63)
        return UInt128(a: aX, b: bX)
    }
    
    // Equality.
    public static func ==(lhs: UInt128, rhs: UInt128) -> Bool {
        return lhs.a == rhs.a && lhs.b == rhs.b
    }
    public static func !=(lhs: UInt128, rhs: UInt128) -> Bool {
        return !(lhs == rhs)
    }
}
