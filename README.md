![](icon.png)

# SwiftGCM
As of *15th January 2018*, Apple is yet to make an implementation of Galois/Counter Mode available to developers.  As a solution to this issue, this library implements AES-128, AES-192 and AES-256 in Galois/Counter Mode with support for additional authenticated data.

**WARNING**: This library has passed no security audits or anything similar, it is merely an implementation of GCM mode as per [The Galois/Counter Mode of Operation](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.694.695&rep=rep1&type=pdf) by David A. McGrew and John Viega.  This library was first written and completed on the *15th January 2018*.  It may contain bugs or errors in implementation.  Your contribution is appreciated!

## Installation
SwiftGCM has no dependencies other than CommonCrypto.  To add CommonCrypto to your project, add a bridging header and import CommonCrypto:
```
#import <CommonCrypto/CommonCrypto.h>
```
You will also need to add `Security.framework` to your project.  To use SwiftGCM, simply drag `SwiftGCM.swift` into your project source files.

## Implementation Notes
- Nonces are required to be 96-bits in size.  No other size of nonce is supported.
- Authentication tags are always 128-bits.
- Key sizes of 128, 192 and 256 bits are supported.
- The last 128 bits of the output of `encrypt` is the authentication tag.

## Example
```
let key: Data = ...
let nonce: Data = ...
let plaintext: Data = ...
let aad: Data = ...

let gcmEnc: SwiftGCM = try SwiftGCM(key: key, nonce: nonce)
let ciphertext: Data = try gcmEnc.encrypt(auth: aad, plaintext: plaintext)

let gcmDec: SwiftGCM = try SwiftGCM(key: key, nonce: nonce)
let result: Data = try gcmDec.decrypt(auth: aad, ciphertext: ciphertext)
```

Once an instance of `SwiftGCM` has been used to encrypt or decrypt, it cannot be used again, as per the example above.

## License
SwiftGCM is licensed under the MIT License.  If you use SwiftGCM in your code, please attribute back to this repository.
