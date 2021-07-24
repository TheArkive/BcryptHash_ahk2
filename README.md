# BcryptHash_ahk2

Perform hashing of MD2, MD4, MD5, SHA1, SHA256, SHA384, or SHA512.

Supports one liners, and supports fast batch hashing.  See examples.

Input is dynamically detected as a file buffer, file name, or string.

Thanks to jNizM and his [CNG lib](https://www.autohotkey.com/boards/viewtopic.php?f=6&t=23413) for AHKv1 which provided many great examples for me getting started.

I plan to add functionality for the rest of the BCrypt suite, but it may be in another lib specifically for encryption / decryption.

---

The class version gives a bit more flexibility for quickly performing multiple types of hashes in rapid succession.  For example, if you wanted to hash a list of objects as sha256 and sha512, the class would be the fastest way to do this.

The function is simpler, but you can only have one type of hash object active at any given time.