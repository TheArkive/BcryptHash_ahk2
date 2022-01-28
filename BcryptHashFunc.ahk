; ========================================================
; Example: Easy one-line hash return
; ========================================================
; In this example you are doing a simple hash of a file.
; This is the most direct way to get a hash.  The hash
; object is still active after a call like this, but this
; is not a problem.  Objects and memory will be released
; automatically when changing specified hashType.

item := "AutoHotkey_2.0-a138-7538f26f.zip"
verify := FileRead("AutoHotkey_2.0-a138-7538f26f.zip.sha256") ; this is the hash specified in the text file
result := hash(item,"SHA256") ; SHA256 is the default and can be omitted.
msgbox "Item: " item "`n`n" result "`n`nMatch: " ((result=verify)?"true":"falsh") 

; ========================================================
; Example: Fast hashing of multiple values
;    NOTE: Must use same hash type when doing this.  If
;          you change the hash type, then this is treated
;          the same as hash() which terminates the hash
;          objects.  The value 1 is returned to indicate
;          a graceful releasing of hash objects.
; ========================================================

final_txt:=""

the_list := ["AutoHotkey_2.0-a138-7538f26f.zip","1234","abcd"] ; List contains a file, and 2 strings

For i, val in the_list                          ; Iterate through the list.
    final_txt .= (final_txt?"`r`n================================`r`n":"") "Item: " val "`n`n" hash(val,"SHA1") ; Perform hashing.

Msgbox final_txt "`r`n`r`nGraceful exit: " hash() ; Release hash objects and buffers.

; ========================================================
; This function automatically leaves hash objects active
; in prep for hashing multiple objects in one loop.  This
; should give a performance boost when hashing many items
; in succession.
;
; When changing hash types, the old hash object is
; automatically freed and new hash objects are created.
; To manually free the hash object and its memory, call
; this func with no parameters.
;
; Usage:
;
;   value := hash(item, hashType := "SHA256", enc := "UTF-16")
;
;       Parameters:
;
;           item     = a string, file name, or file buffer
;           hashType = MD2/MD4/MD5/SHA1/SHA256/SHA384/SHA512
;           enc      = pick your encoding
; ========================================================
hash(buf:="", hType:="SHA256", enc:="UTF-16") {
    Static _hType := hType  ; Setup initial values.
    Static _enc := enc      ; And load the BCrypt DLL.
    Static _hLib := DllCall("LoadLibrary","Str","bcrypt.dll","UPtr")
    Static hAlg := 0, hashObj := 0, hashSize := 0, hHash := 0
    
    (enc) ? _enc := enc : "" ; change encoding if specified
    
    If (!buf) { ; Free buffers/memory and release objects.
        graceful_exit(), hashObj := 0, hHash := 0, hashSize := 0, hAlg := 0
        return true
    }
    Else If (Type(buf) = "String" && FileExist(buf)) ; Determine buffer type.
        buf := FileRead(buf,"RAW")
    Else If (Type(buf) = "String")
        buf := Buffer(StrPut(val:=buf,_enc), 0)
      , StrPut(val, buf, _enc)
    
    If (buf && hType) { ; init obj that performs hashing
        If ((hType != _hType) && hType) ; if hashType changes, release old objects
            graceful_exit(), hashObj := 0, hHash := 0, hashSize := 0, hAlg := 0
          , ((hType!=_hType) ? _hType := hType : "") ; update hash type if changed
        
        r1 := DllCall("bcrypt\BCryptOpenAlgorithmProvider","UPtr*",&hAlg:=0     ; *phAlgorithm
                                                          ,"Str",_hType         ; pszAlgId
                                                          ,"UPtr",0             ; pszImplementation
                                                          ,"UInt",0x20)         ; dwFlags ; BCRYPT_HASH_REUSABLE_FLAG = 0x20
        
        r3 := DllCall("bcrypt\BCryptGetProperty","UPtr",hAlg,"Str","ObjectLength"   ; The buffer size to get the buffer size
                          ,"UInt*",&objSize:=0,"UInt",4,"UInt*",&_size:=0,"UInt",0) ; is usually 4 ... O_O (a DWORD).
        hashObj := Buffer(objSize)                                                  ; Just use UInt* for bSize, and ignore _size.
        
        r4 := DllCall("bcrypt\BCryptGetProperty","UPtr",hAlg,"Str","HashDigestLength"   ; If getting props other than "ObjectLength"
                           ,"UInt*",&hashSize:=0,"UInt",4,"UInt*",&_size:=0,"UInt",0)   ; or "HashDigestLength", you might need to pay more
        
        r5 := DllCall("bcrypt\BCryptCreateHash","UPtr",hAlg,"UPtr*",&hHash:=0   ; Setup fast reusage of hash obj...
        ,"UPtr",hashObj.ptr,"UInt",hashObj.size,"UPtr",0,"UInt",0,"UInt",0x20)  ; ... with 0x20 flag.
    }

    hDigest := Buffer(hashSize), outVal := "" ; Create new digest obj, and perform hashing on buf.
    r7 := DllCall("bcrypt\BCryptHashData","UPtr",hashObj.ptr,"UPtr",buf.ptr,"UInt",buf.size,"UInt",0)
    r8 := DllCall("bcrypt\BCryptFinishHash","UPtr",hashObj.ptr,"UPtr",hDigest.ptr,"UInt",hDigest.size,"UInt",0)
    
    Loop hDigest.size ; convert hDigest to hex string
        outVal .= Format("{:02X}",NumGet(hDigest,A_Index-1,"UChar"))
    
    return outVal
    
    graceful_exit() {
        If DllCall("bcrypt\BCryptDestroyHash","UPtr",hHash)
            throw Error("Unable to destroy hash object.")
        If DllCall("bcrypt\BCryptCloseAlgorithmProvider","UPtr",hAlg,"UInt",0)
            throw Error("Unable to close Algorithm Provider.")
    }
}
