; ================================================================================================================
; Example: Easy one-time hash return
; In this example you are doing a simple hash of a file.  Simply pass an absolute or relative path string.  If the
; specified path exists, then the RAW contents of the file will be loaded into a buffer.  If not, then the
; specified path will be treated as just a string.  You can of course specify an other string to hash a string.
; ================================================================================================================

item := "AutoHotkey_2.0-a138-7538f26f.zip"
verify := FileRead("AutoHotkey_2.0-a138-7538f26f.zip.sha256") ; this is the hash specified in the text file
result := hash(item,"SHA256") ; SHA256 is the default and can be omitted.
msgbox "Item: " item "`n`n" result "`n`nMatch: " ((result=verify)?"true":"falsh") 

; ================================================================================================================
; Example: Fast hashing of multiple values, and multiple algorithms
;    NOTE: The last item hashe is remembered, and the last hashType used is also remembered.  So you can omit
;          either param depending on your needs.
; ================================================================================================================

the_list := ["AutoHotkey_2.0-a138-7538f26f.zip","1234","abcd"] ; List contains a file, and 2 strings

final_txt:=""
For i, val in the_list                          ; Iterate through the list.
    final_txt .= (final_txt?"`r`n================================`r`n":"")
               . "Item: " val "`n`n"
               . "SHA1:`n" hash(val,"SHA1") "`n`n"  ; Perform hashing.  The last item to hash is remembered so you
               . "SHA256:`n" hash(,"SHA256") "`n`n" ; don't have to specify it again.  If you do specify it, then
               . "SHA384:`n" hash(,"SHA384") "`n`n" ; the buffer to hash will be recreated.  Each new hash
               . "SHA512:`n" hash(,"SHA512")        ; algorithm object is saved until hash() is called.

Msgbox final_txt "`r`n`r`nGraceful exit: " hash() ; Release hash objects and buffers.

; ================================================================================================================
; This function automatically leaves hash objects active in prep for hashing multiple objects in one loop.  This
; should give a performance boost when hashing many items in succession.
;
; Multiple hash objects can be created if desired, one for each supported hashType.
;
; To gracefully free all hash objects, and the most recent item from memory, just call this func with
; no parameters:   hash()
;
; Usage:
;
;   value := hash(item, hashType := "SHA256", enc := "UTF-16")
;
;       Parameters:
;
;           item     = a string, file name, or file buffer
;           hashType = MD2/MD4/MD5/SHA1/SHA256/SHA384/SHA512
;           enc      = pick your encoding, only affects 'text', this has no effect when hashing a file
; ================================================================================================================
hash(item:="", hType:="", enc:="") {
    Static _hLib := DllCall("LoadLibrary","Str","bcrypt.dll","UPtr"), LType := "SHA256"
    Static ob := {obj:"", hHash:0, hAlg:0}, close1 := "bcrypt\BCryptDestroyHash", close2 := "bcrypt\BCryptCloseAlgorithmProvider"
         , o_reset := {md2:ob, md4:ob, md5:ob, sha1:ob, sha256:ob, sha384:ob, sha512:ob}, o := o_reset, LBuf := ""
    LType := (hType ? StrUpper(hType) : LType) ; last type
    
    If (!item && !hType) { ; Free buffers/memory and release objects.
        return !graceful_exit()
    } Else If (Type(item) = "String" && FileExist(item)) { ; Determine buffer type.
        LBuf := FileRead(item,"RAW")
    } Else If (Type(item) = "String") {
        LBuf := Buffer(StrPut(item,_enc := (enc?enc:"UTF-16")), 0)
        StrPut(item, LBuf, _enc)
    }
    
    (!o.%LType%.hAlg) ? make_obj() : "" ; init obj that performs hashing
    
    If (LBuf && !(outVal:="")) {
        hDigest := Buffer(o.%LType%.size) ; Create new digest obj, and perform hashing on buf.
        r7 := DllCall("bcrypt\BCryptHashData","UPtr",o.%LType%.obj.ptr,"UPtr",LBuf.ptr,"UInt",LBuf.size,"UInt",0)
        r8 := DllCall("bcrypt\BCryptFinishHash","UPtr",o.%LType%.obj.ptr,"UPtr",hDigest.ptr,"UInt",hDigest.size,"UInt",0)
        Loop hDigest.size ; convert hDigest to hex string
            outVal .= Format("{:02X}",NumGet(hDigest,A_Index-1,"UChar"))
    }
    
    return outVal
    
    make_obj() { ; create hash object
        r1 := DllCall("bcrypt\BCryptOpenAlgorithmProvider","UPtr*",&hAlg:=0,"Str",LType,"UPtr",0,"UInt",0x20) ; dwFlags ; BCRYPT_HASH_REUSABLE_FLAG = 0x20
        
        r3 := DllCall("bcrypt\BCryptGetProperty","UPtr",hAlg,"Str","ObjectLength"   ; The buf size to get the buf size is usually 4 ... O_O (a DWORD).
                          ,"UInt*",&objSize:=0,"UInt",4,"UInt*",&_size:=0,"UInt",0) ; Just use UInt* for bSize, and ignore _size.
        
        r4 := DllCall("bcrypt\BCryptGetProperty","UPtr",hAlg,"Str","HashDigestLength"
                           ,"UInt*",&hashSize:=0,"UInt",4,"UInt*",&_size:=0,"UInt",0), obj:= Buffer(objSize)
        
        r5 := DllCall("bcrypt\BCryptCreateHash","UPtr",hAlg,"UPtr*",&hHash:=0           ; Setup fast reusage of hash obj...
                     ,"UPtr",obj.ptr,"UInt",obj.size,"UPtr",0,"UInt",0,"UInt",0x20)    ; ... with 0x20 flag.
        
        o.%LType% := {obj:obj, hHash:hHash, hAlg:hAlg, size:hashSize}
    }
    
    graceful_exit() {
        For name, obj in o.OwnProps() {
            If o.%name%.hHash && (r1 := DllCall(close1,"UPtr",o.%name%.hHash) || r2 := DllCall(close2,"UPtr",o.%name%.hAlg,"UInt",0))
                throw Error("Unable to destroy hash object. " r1 " " r2)
        } o := o_reset, LBuf := ""
    }
}


dbg(_in) { ; AHK v2
    Loop Parse _in, "`n", "`r"
        OutputDebug "AHK: " A_LoopField
}