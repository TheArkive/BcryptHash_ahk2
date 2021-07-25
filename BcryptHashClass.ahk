; ========================================================
; Example: fast one-line hash return
; ========================================================
item := "AutoHotkey_2.0-a138-7538f26f.zip"
msgbox "Item: " item "`n`n" hash(item).value ; SHA256 is the default and can be omitted.

; ========================================================
; Example: fast hashing of multiple values
;    NOTE: Must use same hash type when doing this.
; ========================================================
h := hash()                 ; init hash obj
values := ["AutoHotkey_2.0-a138-7538f26f.zip","1234","abcd"]
For i, val in values        ; Iterate through your list and hash
    msgbox "Item: " val "`n`n" h.go(val)
h.close()                   ; close hash obj



; ========================================================================
; Supported hash types:  MD2, MD4, MD5, SHA1, SHA256, SHA384, SHA512
;
;   Usage:
;       obj := hash(input := "", hashType := "SHA256", encoding := "UTF-16")
;
;   - Input can be a string, a file name, or a buffer object.
;   - HashType = MD2, MD4, MD5, SHA1, SHA256, SHA384, SHA512 (one of these)
;   - encoding = Used when hasing a string.
;
;   Note: Default values are specified above under "Usage".
;
;   Methods:
;       obj.go(input := "")
;           This performs the next hash on the specified input object, or
;           performs the hash on the object that was specified on init.
;
;           This methods is called automatically if [ false := true ].
;
;       obj.close()
;           Closes the handles to all objects and buffers and frees memory.
;   
;   Properties:
;       obj.item
;           Use this property to get or set the buffer used to perform the
;           hash algorithm on.  This is normally not done directly.  You
;           would normally use:
;
;               obj.go(next_item)
;
;       obj.value
;           Stores the hex representation of the resulting hash value. If
;           no input is specified on init, and no input is specified when
;           using obj.go(), then nothing happens and nothing is returned.
;
;       obj.encoding
;           Specifies the encoding to use when hashing a string.  The
;           default is UTF-16.
; ========================================================================
class hash {
    __New(buf:="", hashType:="SHA256", encoding:="UTF-16") {
        this.encoding := encoding
        this.item := buf
        
        this.hLib := DllCall("LoadLibrary","Str","bcrypt.dll","UPtr")
        r1 := DllCall("bcrypt\BCryptOpenAlgorithmProvider","UPtr*",&hAlg:=0     ; *phAlgorithm
                                                          ,"Str",hashType       ; pszAlgId
                                                          ,"UPtr",0             ; pszImplementation
                                                          ,"UInt",0x20)         ; dwFlags ; BCRYPT_HASH_REUSABLE_FLAG = 0x20
        this.hAlg := hAlg
        
        r3 := DllCall("bcrypt\BCryptGetProperty","UPtr",hAlg,"Str","ObjectLength"   ; The buffer size to get the buffer size
                          ,"UInt*",&bSize:=0,"UInt",4,"UInt*",&_size:=0,"UInt",0)   ; is usually 4 ... O_O (a DWORD).
        this.haObj := Buffer(bSize)                                                 ; Just use UInt* for bSize, and ignore _size.
        
        r4 := DllCall("bcrypt\BCryptGetProperty","UPtr",this.hAlg,"Str","HashDigestLength"  ; If getting props other than "ObjectLength"
                              ,"UInt*",&bSize:=0,"UInt",4,"UInt*",&_size:=0,"UInt",0)       ; or "HashDigestLength", you might need to pay more
        this.hashSize := bSize                                                              ; attention to _size, and call BCryptGetProperty again.
        
        r5 := DllCall("bcrypt\BCryptCreateHash","UPtr",this.hAlg,"UPtr*",&hHash:=0   ; Setup fast reusage of hash obj...
           ,"UPtr",this.haObj.ptr,"UInt",this.haObj.size,"UPtr",0,"UInt",0,"UInt",0x20)   ; ... with 0x20 flag.
        this.hHash := hHash
        
        (buf) ? val := this.go() : "" ; automatically hash the specified item
    }
    __Delete() { ; Gracefully exit, in case the object is terminated before user does close()
        If this.hHash {
            If DllCall("bcrypt\BCryptDestroyHash","UPtr",this.hHash)
                throw Error("Unable to destroy hash object.")
        }
        
        If this.hAlg {
            If DllCall("bcrypt\BCryptCloseAlgorithmProvider","UPtr",this.hAlg,"UInt",0)
                throw Error("Unable to close Algorithm Provider.")
        }
        
        this.haDig := "", this.haObj := "" ; free buffers & clear data
        this.hHash := 0, this.hashSize := 0, this.value := "", this.item := "", this.hAlg := 0
    }
    go(newItem := "") {
        (newItem) ? (this.item := newItem) : ""
        If !this.item
            return "" ; do/return nothing if there is nothing to hash
        
        this.haDig := Buffer(this.hashSize)
        r7 := DllCall("bcrypt\BCryptHashData","UPtr",this.haObj.ptr,"UPtr",this.item.ptr,"UInt",this.item.size,"UInt",0)
        r8 := DllCall("bcrypt\BCryptFinishHash","UPtr",this.haObj.ptr,"UPtr",this.haDig.ptr,"UInt",this.haDig.size,"UInt",0)
        
        outVal := ""
        Loop this.haDig.size
            outVal .= Format("{:02X}",NumGet(this.haDig,A_Index-1,"UChar"))
        this.value := outVal
        
        return outVal
    }
    item {
        set {
            buf := value
            If (Type(value) = "String" && FileExist(value))
                buf := FileRead(value,"RAW")
            Else If (Type(value) = "String") && (value != "")
                buf := Buffer(StrPut(value,this.encoding),0)
              , StrPut(value, buf, this.encoding)
            Else buf := ""
            this.buf := buf
        }
        get => this.buf
    }
    close() {
        If DllCall("bcrypt\BCryptDestroyHash","UPtr",this.hHash)
            throw Error("Unable to destroy hash object.")
        If DllCall("bcrypt\BCryptCloseAlgorithmProvider","UPtr",this.hAlg,"UInt",0)
            throw Error("Unable to close Algorithm Provider.")
        this.haDig := "", this.haObj := "" ; free buffers & clear data
        this.hHash := 0, this.hashSize := 0, this.value := "", this.item := "", this.hAlg := 0
        return true
    }
}