; ================================================================================================================
; Example: Easy one-time hash return
; In this example you are doing a simple hash of a file.  Simply pass an absolute or relative path string.  If the
; specified path exists, then the RAW contents of the file will be loaded into a buffer.  If not, then the
; specified path will be treated as just a string.  You can of course specify an other string to hash a string.
; ================================================================================================================

item := "AutoHotkey_2.0-a138-7538f26f.zip"
verify := FileRead("AutoHotkey_2.0-a138-7538f26f.zip.sha256") ; this is the hash specified in the text file
result := hash(&item,"SHA256") ; SHA256 is the default and can be omitted.
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
               . "SHA1:`n" hash(&val,"SHA1") "`n`n"  ; Perform hashing.  The last item to hash is remembered so you
               . "SHA256:`n" hash(,"SHA256") "`n`n" ; don't have to specify it again.  If you do specify it, then
               . "SHA384:`n" hash(,"SHA384") "`n`n" ; the buffer to hash will be recreated.  Each new hash
               . "SHA512:`n" hash(,"SHA512")        ; algorithm object is saved until hash() is called.

Msgbox final_txt "`r`n`r`nGraceful exit: " hash() ; Release hash objects and buffers.

; ================================================================================================================
; Example: Using the callback function.
; ================================================================================================================

verify := FileRead("AutoHotkey_2.0-a138-7538f26f.zip.sha256") ; this is the hash specified in the text file

callback(prog) {
    Global g
    g["Prog"].Value := Round(prog*100)
    dbg("progress: " prog)
}

g := Gui("-MinimizeBox -MaximizeBox")
g.OnEvent("escape",(*)=>ExitApp())
g.OnEvent("close",(*)=>ExitApp())
g.Add("Progress","w450 vProg",0)
g.Add("Text","w450 vHash","`n")
g.Add("Text","w450 vOrig","Orig:`n" verify)
g.Add("Text","w450 vMatch")
g.Add("Text",,"Press ESC to exit.")
g.Show()

item := "AutoHotkey_2.0-a138-7538f26f.zip"
r := hash(&item,"SHA256",512,callback) ; set small chunk size and callback for example
g["Hash"].Text := "Hash:`n" r
g["Match"].Text := "Match: " ((r=verify)?"true":"false")


; ================================================================================================================
; This function automatically remembers the last hash algorithm and last item hashed (in any combo).
;
; To gracefully free all hash objects, and the most recent item from memory, just call this func with
; no parameters:   hash()
;
; Usage:
;
;   value := hash(item, hashType := "SHA256", c_size := 1024000, cb := "")
;
;       Parameters:
;
;           item     = A string, file name, or buffer object, as a VarRef.
;           hashType = MD2/MD4/MD5/SHA1/SHA256/SHA384/SHA512
;           c_size   = Chunk size, applies to files only, in bytes.
;                      Change the value of d_LSize below to set your desired default chunk size.
;           cb       = Callback must accept one param, the percent complete as a float.
; ================================================================================================================
hash(&item:="", hashType:="", c_size:="", cb:="") { ; default hashType = SHA256 /// default enc = UTF-16
    Static _hLib:=DllCall("LoadLibrary","Str","bcrypt.dll","UPtr"), LType:="SHA256", LItem:="", LBuf:="", LSize:="", d_LSize:=1024000
    Static ob := {obj:"",hHash:0,hAlg:0}, o_reset := {md2:ob,md4:ob,md5:ob,sha1:ob,sha256:ob,sha384:ob,sha512:ob}, o:=o_reset
    LType := (hashType?StrUpper(hashType):LType), LItem:=(item?item:LItem), _file:="", ((!o.%LType%.hAlg)?make_obj():"")
    
    If (!item && !hashType) { ; Free buffers/memory and release objects.
        return !graceful_exit()
    } Else If (Type(LItem) = "String" && FileExist(LItem)) { ; Determine buffer type.
        _file := FileOpen(LItem,"r"), LBuf := true, LSize:=(c_size?c_size:d_LSize)
    } Else If (Type(item) = "String") {
        LBuf := Buffer(StrPut(item,"UTF-8")-1,0), LItem:="", LSize:=d_LSize
        temp_buf := Buffer(LBuf.size+1,0), StrPut(item, temp_buf, "UTF-8"), copy_str()
    } Else If (Type(item) = "Buffer")
        LBuf := item, LItem:="", LSize:=d_LSize
    
    If (LBuf && !(outVal:="")) {
        hDigest := Buffer(o.%LType%.size) ; Create new digest obj
        Loop t:=(!_file ? 1 : (_file.Length//LSize)+1)
            (_file?_file.RawRead(LBuf:=Buffer(((_len:=_file.Length-_file.Pos)<LSize)?_len:LSize,0)):"")
          , r7 := DllCall("bcrypt\BCryptHashData","UPtr",o.%LType%.obj.ptr,"UPtr",LBuf.ptr,"UInt",LBuf.size,"UInt",0)
          , ((Type(cb)="Func") ? cb(A_index/t) : "")
        r8 := DllCall("bcrypt\BCryptFinishHash","UPtr",o.%LType%.obj.ptr,"UPtr",hDigest.ptr,"UInt",hDigest.size,"UInt",0)
        Loop hDigest.size ; convert hDigest to hex string
            outVal .= Format("{:02X}",NumGet(hDigest,A_Index-1,"UChar"))
    }
    
    _file?_file.Close():""
    return outVal
    
    make_obj() { ; create hash object
        r1 := DllCall("bcrypt\BCryptOpenAlgorithmProvider","UPtr*",&hAlg:=0,"Str",LType,"UPtr",0,"UInt",0x20) ; BCRYPT_HASH_REUSABLE_FLAG = 0x20
        
        r3 := DllCall("bcrypt\BCryptGetProperty","UPtr",hAlg,"Str","ObjectLength"
                          ,"UInt*",&objSize:=0,"UInt",4,"UInt*",&_size:=0,"UInt",0) ; Just use UInt* for bSize, and ignore _size.
        
        r4 := DllCall("bcrypt\BCryptGetProperty","UPtr",hAlg,"Str","HashDigestLength"
                           ,"UInt*",&hashSize:=0,"UInt",4,"UInt*",&_size:=0,"UInt",0), obj:= Buffer(objSize)
        
        r5 := DllCall("bcrypt\BCryptCreateHash","UPtr",hAlg,"UPtr*",&hHash:=0       ; Setup fast reusage of hash obj...
                     ,"UPtr",obj.ptr,"UInt",obj.size,"UPtr",0,"UInt",0,"UInt",0x20) ; ... with 0x20 flag.
        
        o.%LType% := {obj:obj, hHash:hHash, hAlg:hAlg, size:hashSize}
    }
    
    graceful_exit(r1:=0, r2:=0) {
        For name, obj in o.OwnProps() {
            If o.%name%.hHash && (r1 := DllCall("bcrypt\BCryptDestroyHash","UPtr",o.%name%.hHash)
                              ||  r2 := DllCall("bcrypt\BCryptCloseAlgorithmProvider","UPtr",o.%name%.hAlg,"UInt",0))
                throw Error("Unable to destroy hash object.")
            o.%name%.hHash := o.%name%.hAlg := o.%name%.obj := ""
        } o := o_reset, LBuf := "", LItem := "", LSize := c_size
    }
    
    copy_str() => DllCall("NtDll\RtlCopyMemory","UPtr",LBuf.ptr,"UPtr",temp_buf.ptr,"UPtr",LBuf.size)
}


; dbg(_in) { ; AHK v2
    ; Loop Parse _in, "`n", "`r"
        ; OutputDebug "AHK: " A_LoopField
; }