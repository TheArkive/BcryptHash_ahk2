# BcryptHash_ahk2

Perform hashing of MD2, MD4, MD5, SHA1, SHA256, SHA384, or SHA512.

Input is dynamically detected as a file or string.

Previous item is remembered, and previously specified hash is also remembered.

Thanks to jNizM and his [CNG lib](https://www.autohotkey.com/boards/viewtopic.php?f=6&t=23413) for AHKv1 which provided many great examples for me getting started.

I plan to add functionality for the rest of the BCrypt suite, but it may be in another lib specifically for encryption / decryption.

Please see the inlcuded examples.

NOTE: The class is now defunct, since the function now remembers multiple hash algorithms, and memory is easily freed when calling `hash()`.