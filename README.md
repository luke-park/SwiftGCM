![](icon.png)

# SwiftGCM
This library implements Galois/Counter Mode for Swift.  It has no dependencies other than Apple's CommonCrypto (`CCCrypt`).  You can include SwiftGCM in your project by simply dragging and dropping `SwiftGCM.swift` into your project source files.

## Features
- Support for AES-128, AES-192 and AES-256.
- Support for Additional Authenticated Data.
- Support for arbitrary nonce sizes (96 bits recommended).
- Support for 128, 120, 112, 104, 96, 64 and 32 bit authentication tag sizes (128 bits recommended).

## Installing
To use SwiftGCM, simply drag `SwiftGCM.swift` into your project source files.  You will also need to include `Security.framework` in your code and add a bridging header to import CommonCrypto:
```
#import <CommonCrypto/CommonCrypto.h>
```

## Basic Example
```swift
 let key: Data = ...
 let nonce: Data = ...
 let plaintext: Data = ...
 let aad: Data = ...
  let tagSize = 16

 let gcmEnc: SwiftGCM = try SwiftGCM(key: key, nonce: nonce, tagSize:tagSize)
 let ciphertext: Data = try gcmEnc.encrypt(auth: aad, plaintext: plaintext)
 
 let gcmDec: SwiftGCM = try SwiftGCM(key: key, nonce: nonce, tagSize:tagSize)
 let result: Data = try gcmDec.decrypt(auth: aad, ciphertext: ciphertext)
```

Once an instance of `SwiftGCM` has been used to encrypt or decrypt, it cannot be used again, as per the example above.  Note that `auth` (the AAD) can be omitted by passing `nil`.

**Warning**: Reusing a key/nonce pair can lead to trivial exposure of plaintext.  If you are not versed in cryptography, ensure you view the production ready examples below before implementing this code in your project.

## Production Ready Examples
For examples on how to work with encryption in production, consult the example code in [this repository](https://github.com/luke-park/SecureCompatibleEncryptionExamples).

## Warning
This library has passed no security audits or anything similar, it is merely an implementation of GCM mode as per [The Galois/Counter Mode of Operation](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.694.695&rep=rep1&type=pdf) by David A. McGrew and John Viega.  It may contain bugs or errors in implementation.  Your contribution is appreciated!

## License
SwiftGCM is licensed under the MIT License.  If you use SwiftGCM in your code, please attribute back to this repository.
