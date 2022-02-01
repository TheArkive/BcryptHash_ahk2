# BcryptHash_ahk2

Perform hashing of MD2, MD4, MD5, SHA1, SHA256, SHA384, or SHA512.

Input is dynamically detected as a file, string, or buffer object.

Previous item is remembered, and previously specified hash algorithm is also remembered.

Thanks to jNizM and his [CNG lib](https://www.autohotkey.com/boards/viewtopic.php?f=6&t=23413) for AHKv1 which provided many great examples for me getting started.

Please see the inlcuded examples.

```
; ================================================================================================================
; This function automatically remembers the last hash algorithm and last item hashed (in any combo).
;
; To gracefully free all hash objects, and the most recent item from memory, just call this func with
; no parameters:   hash()
;
;   Usage:
;
;   value := hash(item, hashType := "SHA256", c_size := 1024000, cb := "")
;
;   Parameters:
;
;       item     = A string, file name, or buffer object, as a VarRef.
;       hashType = MD2/MD4/MD5/SHA1/SHA256/SHA384/SHA512
;       c_size   = Chunk size, applies to files only, in bytes.
;                  Change the value of d_LSize below to set your desired default chunk size.
;       cb       = Callback must accept one param, the percent complete as a float.
; ================================================================================================================
```