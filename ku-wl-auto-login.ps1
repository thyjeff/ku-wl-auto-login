# ============================================================
#  KU-WL Auto Login
#  Auto-login to Karunya University Wi-Fi (FortiGate Portal)
#  https://github.com/thyjeff/ku-wl-auto-login
# ============================================================

param(
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Setup,
    [switch]$ChangeUser,
    [switch]$ChangePassword,
    [switch]$Loop,
    [switch]$Status,
    [switch]$Test,
    [switch]$Logs,
    [int]$Interval = 10
)

# --- Configuration ---
$SSID            = "KU-WL"
$PORTAL_BASE     = "https://seraph.karunya.edu:1003"
$TASK_NAME       = "KU-WL-AutoLogin"
$TASK_NAME_EVENT = "KU-WL-AutoLogin-WiFiEvent"
$INSTALL_DIR     = Join-Path $env:USERPROFILE ".ku-wl-autologin"
$ENV_FILE        = Join-Path $INSTALL_DIR ".env"
$LOG_DIR         = Join-Path $INSTALL_DIR "logs"
$LOG_FILE        = Join-Path $LOG_DIR "autologin.log"
$SCRIPT_DEST     = Join-Path $INSTALL_DIR "ku-wl-auto-login.ps1"
$VBS_LAUNCHER    = Join-Path $INSTALL_DIR "silent-launch.vbs"

# ===================== HELPERS =====================

function Write-Log {
    param([string]$Msg)
    if (-not (Test-Path $LOG_DIR)) { New-Item -ItemType Directory -Path $LOG_DIR -Force | Out-Null }
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$ts | $Msg" | Add-Content -Path $LOG_FILE -Encoding UTF8
}

function Write-Info { param([string]$Msg) Write-Host "  $Msg" }
function Write-Ok   { param([string]$Msg) Write-Host "  $Msg" -ForegroundColor Green }
function Write-Warn { param([string]$Msg) Write-Host "  $Msg" -ForegroundColor Yellow }
function Write-Err  { param([string]$Msg) Write-Host "  $Msg" -ForegroundColor Red }

function Get-WiFiSSID {
    try {
        $output = netsh wlan show interfaces
        foreach ($line in $output) {
            if ($line -match "^\s*SSID\s*:\s*(.+)$" -and $line -notmatch "BSSID") {
                return $Matches[1].Trim()
            }
        }
    } catch {}
    return $null
}

function Test-InternetAccess {
    try {
        $r = Invoke-WebRequest -Uri "http://www.msftconnecttest.com/connecttest.txt" `
             -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
        return ($r.Content -match "Microsoft Connect Test")
    } catch { return $false }
}

function Enable-SSLBypass {
    if (-not ([System.Management.Automation.PSTypeName]'SSLBypass').Type) {
        Add-Type @"
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public class SSLBypass {
    public static void Enable() {
        ServicePointManager.ServerCertificateValidationCallback =
            (sender, cert, chain, errors) => true;
    }
}
"@
    }
    [SSLBypass]::Enable()
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

# ===================== CREDENTIALS =====================

function Load-Credentials {
    if (-not (Test-Path $ENV_FILE)) { return $null }
    $creds = @{}
    Get-Content $ENV_FILE | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith("#")) {
            $parts = $line -split "=", 2
            if ($parts.Count -eq 2) { $creds[$parts[0].Trim()] = $parts[1].Trim() }
        }
    }
    if ($creds["SERAPH_ID"] -and $creds["PASSWORD"]) { return $creds }
    return $null
}

function Save-Credentials {
    param([string]$SeraphId, [string]$Password)
    if (-not (Test-Path $INSTALL_DIR)) { New-Item -ItemType Directory -Path $INSTALL_DIR -Force | Out-Null }
    $content = "# KU-WL Credentials (local only)`nSERAPH_ID=$SeraphId`nPASSWORD=$Password"
    Set-Content -Path $ENV_FILE -Value $content -Encoding UTF8
    (Get-Item $ENV_FILE).Attributes = 'Hidden'
}

function Prompt-Credentials {
    Write-Host ""
    Write-Host "  ========================================" -ForegroundColor Cyan
    Write-Host "  KU-WL Auto Login - Setup" -ForegroundColor Cyan
    Write-Host "  ========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Enter your Seraph portal credentials."
    Write-Host "  Stored ONLY on this computer."
    Write-Host ""
    $id = Read-Host "  Seraph ID (e.g. URK25XX0000)"
    if ([string]::IsNullOrWhiteSpace($id)) { Write-Err "Cancelled."; return $false }
    $secPass = Read-Host "  Password" -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secPass)
    $pass = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    if ([string]::IsNullOrWhiteSpace($pass)) { Write-Err "Cancelled."; return $false }
    Save-Credentials -SeraphId $id -Password $pass
    Write-Ok "Credentials saved!"
    return $true
}

# ===================== PORTAL LOGIN =====================

function Get-CaptivePortalUrl {
    $urls = @(
        "http://detectportal.firefox.com/canonical.html",
        "http://connectivitycheck.gstatic.com/generate_204",
        "http://www.msftconnecttest.com/redirect",
        "http://captive.apple.com/hotspot-detect.html"
    )
    foreach ($u in $urls) {
        try {
            $r = Invoke-WebRequest -Uri $u -TimeoutSec 6 `
                 -UseBasicParsing -MaximumRedirection 5 -ErrorAction Stop
            $final = $r.BaseResponse.ResponseUri.ToString()
            if ($final -match "seraph\.karunya\.edu") { return $final }
            if ($r.Content -match "(https?://seraph\.karunya\.edu[^\s""'<>]+)") { return $Matches[1] }
        } catch {
            try {
                $loc = $_.Exception.Response.Headers["Location"]
                if ($loc -and $loc -match "seraph\.karunya\.edu") { return $loc }
            } catch {}
        }
    }
    return $null
}

function Invoke-PortalLogin {
    param($Creds)
    Enable-SSLBypass
    $portalUrl = Get-CaptivePortalUrl
    if (-not $portalUrl) { $portalUrl = $PORTAL_BASE }
    Write-Log "Portal: $portalUrl"
    try {
        $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        $page = Invoke-WebRequest -Uri $portalUrl -WebSession $session `
                -TimeoutSec 15 -UseBasicParsing -ErrorAction Stop
        $html = $page.Content
        $magic = ""
        if ($html -match 'name=[''"]magic[''"][^>]*value=[''"]([^''"]+)[''"]') { $magic = $Matches[1] }
        elseif ($html -match 'value=[''"]([^''"]+)[''"][^>]*name=[''"]magic[''"]') { $magic = $Matches[1] }
        $postUrl = $portalUrl
        if ($html -match '<form[^>]*action=[''"]([^''"]+)[''"]') {
            $action = $Matches[1]
            if ($action -match "^https?://") { $postUrl = $action }
            elseif ($action -match "^/") {
                $uri = [Uri]$portalUrl; $postUrl = "$($uri.Scheme)://$($uri.Authority)$action"
            } else { $postUrl = ([Uri]::new([Uri]$portalUrl, $action)).AbsoluteUri }
        }
        $body = @{ username = $Creds["SERAPH_ID"]; password = $Creds["PASSWORD"] }
        if ($magic) { $body["magic"] = $magic }
        $hiddens = [regex]::Matches($html, '<input[^>]*type=[''"]hidden[''"][^>]*>')
        foreach ($m in $hiddens) {
            $fn = ""; $fv = ""
            if ($m.Value -match 'name=[''"]([^''"]+)[''"]') { $fn = $Matches[1] }
            if ($m.Value -match 'value=[''"]([^''"]*)[''"]') { $fv = $Matches[1] }
            if ($fn -and -not $body.ContainsKey($fn)) { $body[$fn] = $fv }
        }
        Write-Log "POST -> $postUrl"
        Invoke-WebRequest -Uri $postUrl -Method POST -Body $body `
            -WebSession $session -TimeoutSec 15 -UseBasicParsing `
            -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop | Out-Null
        return $true
    } catch {
        Write-Log "ERROR: $($_.Exception.Message)"
        return $false
    }
}

# ===================== COMMANDS =====================

function Invoke-Setup {
    Prompt-Credentials | Out-Null
}

function Invoke-ChangeUser {
    $creds = Load-Credentials
    $oldId = if ($creds) { $creds["SERAPH_ID"] } else { "(none)" }
    Write-Host "`n  Current Seraph ID: $oldId"
    $newId = Read-Host "  New Seraph ID"
    if ([string]::IsNullOrWhiteSpace($newId)) { Write-Err "Cancelled."; return }
    $pass = if ($creds) { $creds["PASSWORD"] } else { "" }
    if (-not $pass) {
        $secPass = Read-Host "  Password" -AsSecureString
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secPass)
        $pass = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
    Save-Credentials -SeraphId $newId -Password $pass
    Write-Ok "Seraph ID updated to: $newId"
}

function Invoke-ChangePassword {
    $creds = Load-Credentials
    if (-not $creds) { Write-Err "No credentials. Run with -Setup first."; return }
    Write-Host "`n  Seraph ID: $($creds['SERAPH_ID'])"
    $secPass = Read-Host "  New Password" -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secPass)
    $pass = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    if ([string]::IsNullOrWhiteSpace($pass)) { Write-Err "Cancelled."; return }
    Save-Credentials -SeraphId $creds["SERAPH_ID"] -Password $pass
    Write-Ok "Password updated!"
}

# --- Create VBS silent launcher (no cmd window flash) ---
function Create-SilentLauncher {
    param([string]$ScriptPath, [string]$ExtraArgs)
    $cmd = "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File ""$ScriptPath"" $ExtraArgs"
    $vbs = "Set objShell = CreateObject(""WScript.Shell"")`r`nobjShell.Run ""$cmd"", 0, False"
    Set-Content -Path $VBS_LAUNCHER -Value $vbs -Encoding ASCII
}

# --- Disable Windows captive portal browser popup ---
function Disable-CaptivePortalPopup {
    try {
        # This stops Windows from auto-opening browser when it detects captive portal
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet"
        Set-ItemProperty -Path $regPath -Name "EnableActiveProbing" -Value 0 -Type DWord -ErrorAction Stop
        Write-Log "Disabled Windows captive portal browser popup"
    } catch {
        Write-Log "Could not disable captive portal popup (need admin): $($_.Exception.Message)"
    }
}

# --- Re-enable Windows captive portal browser popup ---
function Enable-CaptivePortalPopup {
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet"
        Set-ItemProperty -Path $regPath -Name "EnableActiveProbing" -Value 1 -Type DWord -ErrorAction Stop
    } catch {}
}

# --- Install ---
function Install-Task {
    $creds = Load-Credentials
    if (-not $creds) {
        Write-Warn "No credentials found. Let's set them up."
        $result = Prompt-Credentials
        if (-not $result) { Write-Err "Install cancelled."; exit 1 }
    }

    # Create install directory and copy script
    if (-not (Test-Path $INSTALL_DIR)) { New-Item -ItemType Directory -Path $INSTALL_DIR -Force | Out-Null }
    $src = $MyInvocation.ScriptName
    if (-not $src) { $src = $PSCommandPath }
    if ($src -and (Test-Path $src) -and ($src -ne $SCRIPT_DEST)) { Copy-Item $src $SCRIPT_DEST -Force }
    $runScript = if (Test-Path $SCRIPT_DEST) { $SCRIPT_DEST } else { $src }

    # Create VBS silent launcher (prevents cmd window flash)
    Create-SilentLauncher -ScriptPath $runScript -ExtraArgs "-Loop"

    # Create a second VBS for single-run (event trigger)
    $vbsEvent = Join-Path $INSTALL_DIR "silent-event.vbs"
    $vbsContent = @"
Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File ""$runScript""", 0, False
"@
    Set-Content -Path $vbsEvent -Value $vbsContent -Encoding ASCII

    # Disable Windows captive portal browser popup
    Disable-CaptivePortalPopup

    # Stop old tasks
    Stop-ScheduledTask -TaskName $TASK_NAME -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TASK_NAME -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TASK_NAME_EVENT -Confirm:$false -ErrorAction SilentlyContinue

    # Task 1: Background loop via VBS (completely silent, no window)
    $actionLoop = New-ScheduledTaskAction -Execute "wscript.exe" -Argument "`"$VBS_LAUNCHER`""
    $triggerLogon = New-ScheduledTaskTrigger -AtLogOn
    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -MultipleInstances IgnoreNew `
        -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName $TASK_NAME `
        -Action $actionLoop -Trigger $triggerLogon -Settings $settings `
        -Description "KU-WL auto-login background loop" -Force | Out-Null

    # Task 2: WiFi event trigger via VBS (completely silent)
    $taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="Microsoft-Windows-WLAN-AutoConfig/Operational"&gt;&lt;Select Path="Microsoft-Windows-WLAN-AutoConfig/Operational"&gt;*[System[(EventID=8001)]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
      <Delay>PT3S</Delay>
    </EventTrigger>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="Microsoft-Windows-NetworkProfile/Operational"&gt;&lt;Select Path="Microsoft-Windows-NetworkProfile/Operational"&gt;*[System[(EventID=10000)]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
      <Delay>PT3S</Delay>
    </EventTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <ExecutionTimeLimit>PT5M</ExecutionTimeLimit>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>wscript.exe</Command>
      <Arguments>"$vbsEvent"</Arguments>
    </Exec>
  </Actions>
</Task>
"@
    Register-ScheduledTask -TaskName $TASK_NAME_EVENT -Xml $taskXml -Force | Out-Null

    # Start loop NOW
    Start-ScheduledTask -TaskName $TASK_NAME -ErrorAction SilentlyContinue

    Write-Log "INSTALLED"
    Write-Host ""
    Write-Host "  ========================================" -ForegroundColor Green
    Write-Host "  KU-WL Auto Login - INSTALLED" -ForegroundColor Green
    Write-Host "  ========================================" -ForegroundColor Green
    Write-Host ""
    Write-Ok "Auto-login is ACTIVE."
    Write-Ok "No windows will pop up."
    Write-Ok "No browser will open for login."
    Write-Host ""
    Write-Host "  Connect to KU-WL and it just works!" -ForegroundColor Cyan
    Write-Host "  ========================================" -ForegroundColor Green
    Write-Host ""
}

# --- Uninstall ---
function Uninstall-Task {
    Stop-ScheduledTask -TaskName $TASK_NAME -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TASK_NAME -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TASK_NAME_EVENT -Confirm:$false -ErrorAction SilentlyContinue
    # Re-enable Windows captive portal popup
    Enable-CaptivePortalPopup
    Write-Host ""
    Write-Warn "Uninstalled. Captive portal browser popup restored."
    Write-Host "  To remove all data: Remove-Item '$INSTALL_DIR' -Recurse -Force"
    Write-Host ""
}

# --- Status ---
function Show-Status {
    Write-Host ""
    Write-Host "  === KU-WL Auto Login ===" -ForegroundColor Cyan
    $ssid = Get-WiFiSSID; $inet = Test-InternetAccess
    Write-Info "SSID       : $( if ($ssid) { $ssid } else { 'Not connected' } )"
    Write-Info "Internet   : $( if ($inet) { 'Working' } else { 'No access' } )"
    Write-Info "Credentials: $( if (Load-Credentials) { 'Saved' } else { 'NOT SET' } )"
    $t1 = Get-ScheduledTask -TaskName $TASK_NAME -ErrorAction SilentlyContinue
    $t2 = Get-ScheduledTask -TaskName $TASK_NAME_EVENT -ErrorAction SilentlyContinue
    Write-Info "Loop task  : $( if ($t1) { $t1.State } else { 'Not installed' } )"
    Write-Info "Event task : $( if ($t2) { $t2.State } else { 'Not installed' } )"
    if (Test-Path $LOG_FILE) {
        Write-Host ""; Write-Host "  Recent:" -ForegroundColor Gray
        Get-Content $LOG_FILE -Tail 5 | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
    }
    Write-Host ""
}

function Show-Logs {
    if (Test-Path $LOG_FILE) { Get-Content $LOG_FILE -Tail 30 }
    else { Write-Warn "No logs yet." }
}

function Invoke-TestMode {
    Write-Host "`n  === Debug ===" -ForegroundColor Yellow
    Write-Info "SSID: $(Get-WiFiSSID)"
    Write-Info "Internet: $(Test-InternetAccess)"
    Enable-SSLBypass
    $url = Get-CaptivePortalUrl
    Write-Info "Portal: $url"
    if ($url) {
        try {
            $page = Invoke-WebRequest -Uri $url -TimeoutSec 15 -UseBasicParsing -ErrorAction Stop
            Write-Info "Page: $($page.Content.Length) bytes"
        } catch { Write-Err "$($_.Exception.Message)" }
    }
    $creds = Load-Credentials
    if (-not $creds) { Write-Err "No credentials."; return }
    Write-Info "Logging in..."
    Invoke-PortalLogin -Creds $creds
    Start-Sleep -Seconds 4
    $inet = Test-InternetAccess
    Write-Host "  Result: $inet" -ForegroundColor $(if ($inet) { 'Green' } else { 'Red' })
}

# ===================== ENTRY POINT =====================

if (-not ($Install -or $Uninstall -or $Setup -or $ChangeUser -or $ChangePassword `
    -or $Loop -or $Status -or $Test -or $Logs)) {
    Write-Host "`n  KU-WL Auto Login" -ForegroundColor Cyan
    Write-Host "  .\ku-wl-auto-login.ps1 -Install         (first time, run as Admin)"
    Write-Host "  .\ku-wl-auto-login.ps1 -ChangeUser       Change Seraph ID"
    Write-Host "  .\ku-wl-auto-login.ps1 -ChangePassword   Change password"
    Write-Host "  .\ku-wl-auto-login.ps1 -Status           Check status"
    Write-Host "  .\ku-wl-auto-login.ps1 -Uninstall        Remove`n"
    exit 0
}

if ($Setup)          { Invoke-Setup; exit 0 }
if ($ChangeUser)     { Invoke-ChangeUser; exit 0 }
if ($ChangePassword) { Invoke-ChangePassword; exit 0 }
if ($Install)        { Install-Task; exit 0 }
if ($Uninstall)      { Uninstall-Task; exit 0 }
if ($Status)         { Show-Status; exit 0 }
if ($Logs)           { Show-Logs; exit 0 }
if ($Test)           { Invoke-TestMode; exit 0 }

# --- Background Loop ---
if ($Loop) {
    Write-Log "Loop started PID=$PID"
    $lastState = ""
    while ($true) {
        try {
            $ssid = Get-WiFiSSID
            $internet = $false
            if ($ssid -eq $SSID) { $internet = Test-InternetAccess }
            $state = "ssid=$ssid|inet=$internet"
            if ($state -ne $lastState) {
                Write-Log "State: SSID='$ssid' Internet=$internet"
                $lastState = $state
            }
            if ($ssid -eq $SSID -and -not $internet) {
                $creds = Load-Credentials
                if ($creds) {
                    Write-Log "Logging in..."
                    Invoke-PortalLogin -Creds $creds | Out-Null
                    Start-Sleep -Seconds 4
                    if (Test-InternetAccess) {
                        Write-Log "SUCCESS!"
                        $lastState = "ssid=$SSID|inet=True"
                    } else { Write-Log "Failed. Retrying." }
                }
            }
        } catch { try { Write-Log "ERROR: $($_.Exception.Message)" } catch {} }
        Start-Sleep -Seconds $Interval
    }
}

# Default: single run
$creds = Load-Credentials
if ($creds) {
    $ssid = Get-WiFiSSID
    if ($ssid -eq $SSID -and -not (Test-InternetAccess)) {
        Invoke-PortalLogin -Creds $creds | Out-Null
    }
}
