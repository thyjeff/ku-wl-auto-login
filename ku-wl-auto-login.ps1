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
    [switch]$AddBackup,
    [switch]$SwitchAccount,
    [switch]$Logout,
    [switch]$Keepalive,
    [switch]$Update,
    [switch]$Loop,
    [switch]$Status,
    [switch]$Test,
    [switch]$Logs,
    [int]$Interval = 10
)

$SSID            = "KU-WL"
$PORTAL_BASE     = "https://seraph.karunya.edu:1003"
$TASK_NAME       = "KU-WL-AutoLogin"
$TASK_NAME_EVENT = "KU-WL-AutoLogin-WiFiEvent"
$INSTALL_DIR     = Join-Path $env:USERPROFILE ".ku-wl-autologin"
$ENV_FILE        = Join-Path $INSTALL_DIR ".env"
$SESSION_FILE    = Join-Path $INSTALL_DIR "session.json"
$LOG_DIR         = Join-Path $INSTALL_DIR "logs"
$LOG_FILE        = Join-Path $LOG_DIR "autologin.log"
$SCRIPT_DEST     = Join-Path $INSTALL_DIR "ku-wl-auto-login.ps1"

# ===================== HELPERS =====================

function Write-Log {
    param([string]$Msg)
    if (-not (Test-Path $LOG_DIR)) { New-Item -ItemType Directory -Path $LOG_DIR -Force | Out-Null }
    # Rotate log if larger than 1MB
    if ((Test-Path $LOG_FILE) -and ((Get-Item $LOG_FILE).Length -gt 1048576)) {
        try {
            $lines = Get-Content $LOG_FILE -Tail 500
            Set-Content -Path $LOG_FILE -Value $lines -Encoding UTF8
        } catch {}
    }
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$ts | $Msg" | Add-Content -Path $LOG_FILE -Encoding UTF8
}

function Write-Info { param([string]$Msg) Write-Host "  $Msg" }
function Write-Ok   { param([string]$Msg) Write-Host "  $Msg" -ForegroundColor Green }
function Write-Warn { param([string]$Msg) Write-Host "  $Msg" -ForegroundColor Yellow }
function Write-Err  { param([string]$Msg) Write-Host "  $Msg" -ForegroundColor Red }

function Get-WiFiSSID {
    try {
        $out = netsh wlan show interfaces
        foreach ($line in $out) {
            if ($line -match "^\s*SSID\s*:\s*(.+)$" -and $line -notmatch "BSSID") {
                return $Matches[1].Trim()
            }
        }
    } catch {}
    return $null
}

function Test-InternetAccess {
    try {
        # Quick 204 check
        $r1 = Invoke-WebRequest -Uri "http://connectivitycheck.gstatic.com/generate_204" `
              -TimeoutSec 4 -UseBasicParsing -ErrorAction SilentlyContinue
        if ($r1.StatusCode -eq 204) { return $true }
    } catch {}

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

# ===================== CREDENTIALS & SESSIONS =====================

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
    param(
        [string]$SeraphId,
        [string]$Password,
        [string]$BackupId = "",
        [string]$BackupPassword = "",
        [string]$AutoFailover = "1"
    )
    if (-not (Test-Path $INSTALL_DIR)) { New-Item -ItemType Directory -Path $INSTALL_DIR -Force | Out-Null }
    $content = "# KU-WL Credentials (local only)`nSERAPH_ID=$SeraphId`nPASSWORD=$Password"
    if ($BackupId -and $BackupPassword) {
        $content += "`nBACKUP_SERAPH_ID=$BackupId`nBACKUP_PASSWORD=$BackupPassword`nAUTO_FAILOVER=$AutoFailover"
    } elseif ($AutoFailover) {
        $content += "`nAUTO_FAILOVER=$AutoFailover"
    }
    Set-Content -Path $ENV_FILE -Value $content -Encoding UTF8
    (Get-Item $ENV_FILE).Attributes = 'Hidden'
}

function Load-Session {
    if (-not (Test-Path $SESSION_FILE)) { return $null }
    try {
        $raw = Get-Content $SESSION_FILE -Raw -Encoding UTF8
        return ($raw | ConvertFrom-Json)
    } catch { return $null }
}

function Save-Session {
    param([string]$Token, [string]$SeraphId)
    if (-not (Test-Path $INSTALL_DIR)) { New-Item -ItemType Directory -Path $INSTALL_DIR -Force | Out-Null }
    $sess = @{
        token         = $Token
        keepalive_url = "$PORTAL_BASE/keepalive?$Token"
        logout_url    = "$PORTAL_BASE/logout?$Token"
        seraph_id     = $SeraphId
        login_time    = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    }
    $sess | ConvertTo-Json | Set-Content -Path $SESSION_FILE -Encoding UTF8
}

function Prompt-Credentials {
    Write-Host "`n  ========================================" -ForegroundColor Cyan
    Write-Host "  KU-WL Auto Login - Setup" -ForegroundColor Cyan
    Write-Host "  ========================================" -ForegroundColor Cyan
    Write-Host "  Enter your Seraph portal credentials."
    Write-Host "  Stored ONLY on this computer.`n"
    $id = Read-Host "  Seraph ID (e.g. URK25XX0000)"
    if ([string]::IsNullOrWhiteSpace($id)) { Write-Err "Cancelled."; return $false }
    $secPass = Read-Host "  Password" -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secPass)
    $pass = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    if ([string]::IsNullOrWhiteSpace($pass)) { Write-Err "Cancelled."; return $false }

    $bId = ""
    $bPass = ""
    $addBak = Read-Host "`n  Do you want to add a backup ID for 8GB data limit failover? (y/n)"
    if ($addBak -eq "y" -or $addBak -eq "Y") {
        $bId = Read-Host "  Backup Seraph ID"
        if (-not [string]::IsNullOrWhiteSpace($bId)) {
            $bSecPass = Read-Host "  Backup Password" -AsSecureString
            $bBstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($bSecPass)
            $bPass = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bBstr)
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bBstr)
        }
    }

    Save-Credentials -SeraphId $id -Password $pass -BackupId $bId -BackupPassword $bPass -AutoFailover "1"
    Write-Ok "Credentials saved!"
    return $true
}

# ===================== PORTAL LOGIN =====================

function Get-CaptivePortalUrl {
    $urls = @(
        "http://connectivitycheck.gstatic.com/generate_204",
        "http://detectportal.firefox.com/canonical.html",
        "http://www.msftconnecttest.com/redirect",
        "http://www.msftconnecttest.com/connecttest.txt",
        "http://captive.apple.com/hotspot-detect.html"
    )
    foreach ($u in $urls) {
        try {
            $r = Invoke-WebRequest -Uri $u -TimeoutSec 5 -UseBasicParsing -MaximumRedirection 5 -ErrorAction Stop
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
    Write-Log "Portal URL: $portalUrl"
    try {
        $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        $page = Invoke-WebRequest -Uri $portalUrl -WebSession $session -TimeoutSec 15 -UseBasicParsing -ErrorAction Stop
        $html = $page.Content
        $magic = ""
        if ($html -match 'name=[''"]magic[''"][^>]*value=[''"]([^''"]+)[''"]') { $magic = $Matches[1] }
        elseif ($html -match 'value=[''"]([^''"]+)[''"][^>]*name=[''"]magic[''"]') { $magic = $Matches[1] }
        $postUrl = $portalUrl
        if ($html -match '<form[^>]*action=[''"]([^''"]+)[''"]') {
            $action = $Matches[1]
            if ($action -match "^https?://") { $postUrl = $action }
            elseif ($action -match "^/") { $uri = [Uri]$portalUrl; $postUrl = "$($uri.Scheme)://$($uri.Authority)$action" }
            else { $postUrl = ([Uri]::new([Uri]$portalUrl, $action)).AbsoluteUri }
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
        Write-Log "POST -> $postUrl ($($Creds['SERAPH_ID']))"
        $resp = Invoke-WebRequest -Uri $postUrl -Method POST -Body $body -WebSession $session `
                -TimeoutSec 15 -UseBasicParsing -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop

        # Capture and save keepalive/logout token
        $token = $null
        if ($resp.Content -match "(?:keepalive|logout)\?([a-f0-9]+)") {
            $token = $Matches[1]
        } elseif ($resp.Headers["Location"] -match "(?:keepalive|logout)\?([a-f0-9]+)") {
            $token = $Matches[1]
        }
        if ($token) {
            Save-Session -Token $token -SeraphId $Creds["SERAPH_ID"]
            Write-Log "Keepalive session active: $PORTAL_BASE/keepalive?$token"
        }

        return $true
    } catch {
        Write-Log "ERROR: $($_.Exception.Message)"
        return $false
    }
}

# ===================== INSTALL & TASKS =====================

function Disable-CaptivePortalPopup {
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" -Name "EnableActiveProbing" -Value 0 -Type DWord -ErrorAction Stop
        Write-Log "Disabled captive portal browser popup"
    } catch { Write-Log "Could not disable popup (need admin)" }
}

function Enable-CaptivePortalPopup {
    try { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" -Name "EnableActiveProbing" -Value 1 -Type DWord -ErrorAction Stop } catch {}
}

function Install-Task {
    $creds = Load-Credentials
    if (-not $creds) {
        Write-Warn "No credentials found. Let's set them up."
        if (-not (Prompt-Credentials)) { Write-Err "Install cancelled."; exit 1 }
    }

    if (-not (Test-Path $INSTALL_DIR)) { New-Item -ItemType Directory -Path $INSTALL_DIR -Force | Out-Null }
    $src = $PSCommandPath
    if ($src -and (Test-Path $src) -and ($src -ne $SCRIPT_DEST)) { Copy-Item $src $SCRIPT_DEST -Force }
    $runScript = if (Test-Path $SCRIPT_DEST) { $SCRIPT_DEST } else { $src }

    Disable-CaptivePortalPopup

    # Remove old tasks
    Stop-ScheduledTask -TaskName $TASK_NAME -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TASK_NAME -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TASK_NAME_EVENT -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $INSTALL_DIR "*.vbs") -Force -ErrorAction SilentlyContinue

    $psArgs = "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$runScript`""
    $psArgsLoop = "$psArgs -Loop"

    # Task 1: Background loop at logon
    $xml1 = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><LogonTrigger><Enabled>true</Enabled><Delay>PT10S</Delay></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <Hidden>true</Hidden>
    <RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
  </Settings>
  <Actions Context="Author"><Exec>
    <Command>conhost.exe</Command>
    <Arguments>--headless powershell.exe $psArgsLoop</Arguments>
  </Exec></Actions>
</Task>
"@
    Register-ScheduledTask -TaskName $TASK_NAME -Xml $xml1 -Force | Out-Null

    # Task 2: WiFi event trigger
    $xml2 = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <EventTrigger><Enabled>true</Enabled><Delay>PT3S</Delay>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="Microsoft-Windows-WLAN-AutoConfig/Operational"&gt;&lt;Select Path="Microsoft-Windows-WLAN-AutoConfig/Operational"&gt;*[System[(EventID=8001)]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
    </EventTrigger>
    <EventTrigger><Enabled>true</Enabled><Delay>PT3S</Delay>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="Microsoft-Windows-NetworkProfile/Operational"&gt;&lt;Select Path="Microsoft-Windows-NetworkProfile/Operational"&gt;*[System[(EventID=10000)]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
    </EventTrigger>
  </Triggers>
  <Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <Hidden>true</Hidden>
    <ExecutionTimeLimit>PT5M</ExecutionTimeLimit>
  </Settings>
  <Actions Context="Author"><Exec>
    <Command>conhost.exe</Command>
    <Arguments>--headless powershell.exe $psArgs</Arguments>
  </Exec></Actions>
</Task>
"@
    Register-ScheduledTask -TaskName $TASK_NAME_EVENT -Xml $xml2 -Force | Out-Null

    # Start loop now
    Start-ScheduledTask -TaskName $TASK_NAME -ErrorAction SilentlyContinue

    # Silent install counter
    try { Invoke-WebRequest -Uri "https://api.counterapi.dev/v1/ku-wl-auto-login/installs/up" -UseBasicParsing -TimeoutSec 3 -ErrorAction SilentlyContinue | Out-Null } catch {}

    Write-Log "INSTALLED"
    Write-Host "`n  ========================================" -ForegroundColor Green
    Write-Host "  KU-WL Auto Login - INSTALLED" -ForegroundColor Green
    Write-Host "  ========================================`n" -ForegroundColor Green
    Write-Ok "Auto-login is ACTIVE. No popups. No browser."
    Write-Host "  Connect to KU-WL and it just works!`n" -ForegroundColor Cyan
}

# ===================== USER COMMANDS =====================

function Invoke-Setup { Prompt-Credentials | Out-Null }

function Invoke-ChangeUser {
    $creds = Load-Credentials
    $oldId = if ($creds) { $creds["SERAPH_ID"] } else { "(none)" }
    Write-Host "`n  Current Seraph ID: $oldId"
    $newId = Read-Host "  New Seraph ID"
    if ([string]::IsNullOrWhiteSpace($newId)) { Write-Err "Cancelled."; return }
    $pass = if ($creds) { $creds["PASSWORD"] } else { "" }
    if (-not $pass) {
        $sp = Read-Host "  Password" -AsSecureString
        $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sp)
        $pass = [Runtime.InteropServices.Marshal]::PtrToStringAuto($b)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b)
    }
    Save-Credentials -SeraphId $newId -Password $pass `
                     -BackupId ($creds["BACKUP_SERAPH_ID"] ?? "") `
                     -BackupPassword ($creds["BACKUP_PASSWORD"] ?? "")
    Write-Ok "Seraph ID updated to: $newId"
}

function Invoke-ChangePassword {
    $creds = Load-Credentials
    if (-not $creds) { Write-Err "No credentials. Run with -Setup first."; return }
    Write-Host "`n  Seraph ID: $($creds['SERAPH_ID'])"
    $sp = Read-Host "  New Password" -AsSecureString
    $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sp)
    $pass = [Runtime.InteropServices.Marshal]::PtrToStringAuto($b)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b)
    if ([string]::IsNullOrWhiteSpace($pass)) { Write-Err "Cancelled."; return }
    Save-Credentials -SeraphId $creds["SERAPH_ID"] -Password $pass `
                     -BackupId ($creds["BACKUP_SERAPH_ID"] ?? "") `
                     -BackupPassword ($creds["BACKUP_PASSWORD"] ?? "")
    Write-Ok "Password updated!"
}

function Invoke-AddBackup {
    $creds = Load-Credentials
    if (-not $creds) { Write-Err "No primary credentials found. Run -Install or -Setup first."; return }
    Write-Host "`n  === 8GB Quota / Backup Account Setup ===" -ForegroundColor Cyan
    Write-Host "  When your 8GB daily limit is reached, auto-login will"
    Write-Host "  automatically roll over to this backup student account.`n"
    $bId = Read-Host "  Backup Seraph ID (e.g. URK25XX0000)"
    if ([string]::IsNullOrWhiteSpace($bId)) { Write-Err "Cancelled."; return }
    $secPass = Read-Host "  Backup Password" -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secPass)
    $bPass = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    if ([string]::IsNullOrWhiteSpace($bPass)) { Write-Err "Cancelled."; return }

    Save-Credentials -SeraphId $creds["SERAPH_ID"] -Password $creds["PASSWORD"] `
                     -BackupId $bId -BackupPassword $bPass -AutoFailover "1"
    Write-Ok "Backup account $bId saved with Auto-Failover enabled!"
    Write-Info "When daily 8GB runs out on $($creds['SERAPH_ID']), it automatically switches to $bId."
}

function Invoke-Logout {
    Enable-SSLBypass
    $sess = Load-Session
    $token = if ($sess) { $sess["token"] } else { $null }
    if ($token) {
        $logoutUrl = "$PORTAL_BASE/logout?$token"
        try {
            Invoke-WebRequest -Uri $logoutUrl -TimeoutSec 6 -UseBasicParsing -ErrorAction SilentlyContinue | Out-Null
            Write-Ok "Logged out active session for $($sess['seraph_id']) ($token)."
            Remove-Item $SESSION_FILE -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Warn "Logout request sent."
        }
    } else {
        Write-Warn "No active session token found. Session may already be expired or offline."
    }
}

function Invoke-Keepalive {
    $sess = Load-Session
    $kurl = if ($sess) { $sess["keepalive_url"] } else { $null }
    if ($kurl) {
        Write-Ok "Active Keepalive URL: $kurl"
        Write-Info "Opening session dashboard in default browser..."
        Start-Process $kurl
    } else {
        Write-Warn "No active keepalive session saved yet. Connect to KU-WL and log in first."
    }
}

function Invoke-SwitchAccount {
    $creds = Load-Credentials
    if (-not $creds) { Write-Err "No credentials found. Run -Setup first."; return }
    Write-Host "`n  === Switch Active Seraph Account ===" -ForegroundColor Cyan
    Write-Info "Active Account : $($creds['SERAPH_ID'])"
    $backupId = if ($creds["BACKUP_SERAPH_ID"]) { $creds["BACKUP_SERAPH_ID"] } else { "(none)" }
    Write-Info "Backup Account : $backupId"

    if ($creds["BACKUP_SERAPH_ID"] -and $creds["BACKUP_PASSWORD"]) {
        $choice = Read-Host "`n  Switch to backup account $backupId now? (y/n/new)"
        if ($choice -eq "y" -or $choice -eq "Y") {
            Save-Credentials -SeraphId $creds["BACKUP_SERAPH_ID"] -Password $creds["BACKUP_PASSWORD"] `
                             -BackupId $creds["SERAPH_ID"] -BackupPassword $creds["PASSWORD"] `
                             -AutoFailover ($creds["AUTO_FAILOVER"] ?? "1")
            Write-Ok "Active account swapped to $backupId! Terminating old session..."
            Invoke-Logout
            Write-Info "Logging in with $backupId..."
            Invoke-TestMode
            return
        }
    }

    $newId = Read-Host "  Enter new Seraph ID to activate"
    if ([string]::IsNullOrWhiteSpace($newId)) { Write-Err "Cancelled."; return }
    $secPass = Read-Host "  Password" -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secPass)
    $pass = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    if ([string]::IsNullOrWhiteSpace($pass)) { Write-Err "Cancelled."; return }

    Save-Credentials -SeraphId $newId -Password $pass `
                     -BackupId ($creds["BACKUP_SERAPH_ID"] ?? "") `
                     -BackupPassword ($creds["BACKUP_PASSWORD"] ?? "")
    Write-Ok "Switched to $newId! Terminating old session and logging in..."
    Invoke-Logout
    Invoke-TestMode
}

function Invoke-Update {
    Write-Host "`n  KU-WL Auto Login - Checking for updates..." -ForegroundColor Cyan
    $rawUrl = "https://raw.githubusercontent.com/thyjeff/ku-wl-auto-login/master/ku-wl-auto-login.ps1"
    try {
        $tmp = Join-Path $env:TEMP "ku-wl-auto-login-update.ps1"
        Invoke-WebRequest -Uri $rawUrl -OutFile $tmp -TimeoutSec 15 -UseBasicParsing -ErrorAction Stop
        if (Test-Path $SCRIPT_DEST) {
            Copy-Item $tmp $SCRIPT_DEST -Force
        }
        $userScript = Join-Path $env:USERPROFILE "ku-wl-auto-login.ps1"
        if (Test-Path $userScript) {
            Copy-Item $tmp $userScript -Force
        }
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue

        # Restart scheduled task
        Stop-ScheduledTask -TaskName $TASK_NAME -ErrorAction SilentlyContinue
        Start-ScheduledTask -TaskName $TASK_NAME -ErrorAction SilentlyContinue

        Write-Ok "Updated successfully to the latest version!"
        Write-Host "  Background auto-login daemon restarted with newest features.`n" -ForegroundColor Green
    } catch {
        Write-Err "Update failed: $($_.Exception.Message)"
    }
}

function Uninstall-Task {
    Stop-ScheduledTask -TaskName $TASK_NAME -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TASK_NAME -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TASK_NAME_EVENT -Confirm:$false -ErrorAction SilentlyContinue
    Enable-CaptivePortalPopup
    Remove-Item (Join-Path $INSTALL_DIR "*.vbs") -Force -ErrorAction SilentlyContinue
    Write-Host ""
    Write-Warn "Uninstalled. To remove all data:"
    Write-Host "  Remove-Item '$INSTALL_DIR' -Recurse -Force`n"
}

function Show-Status {
    Write-Host "`n  === KU-WL Auto Login ===" -ForegroundColor Cyan
    $ssid = Get-WiFiSSID; $inet = Test-InternetAccess
    $creds = Load-Credentials
    $sess = Load-Session

    Write-Info "SSID           : $(if ($ssid) {$ssid} else {'Not connected'})"
    Write-Info "Internet       : $(if ($inet) {'Working (Online)'} else {'No access / Quota Exceeded'})"
    Write-Info "Active Account : $(if ($creds) {$creds['SERAPH_ID']} else {'NOT SET'})"
    $backupText = if ($creds -and $creds['BACKUP_SERAPH_ID']) { "$($creds['BACKUP_SERAPH_ID']) (Auto-Failover ON)" } else { "None (run -AddBackup to set)" }
    Write-Info "Backup Account : $backupText"

    $kurl = if ($sess) { $sess["keepalive_url"] } else { "(captured on next login)" }
    Write-Info "Keepalive URL  : $kurl"

    $t1 = Get-ScheduledTask -TaskName $TASK_NAME -ErrorAction SilentlyContinue
    $t2 = Get-ScheduledTask -TaskName $TASK_NAME_EVENT -ErrorAction SilentlyContinue
    Write-Info "Loop task      : $(if ($t1) {$t1.State} else {'Not installed'})"
    Write-Info "Event task     : $(if ($t2) {$t2.State} else {'Not installed'})"

    if (Test-Path $LOG_FILE) {
        Write-Host "`n  Recent Activity:" -ForegroundColor Gray
        Get-Content $LOG_FILE -Tail 5 | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
    }
    Write-Host ""
}

function Show-Logs {
    if (Test-Path $LOG_FILE) { Get-Content $LOG_FILE -Tail 40 }
    else { Write-Warn "No logs yet." }
}

function Invoke-TestMode {
    Write-Host "`n  === Debug Test ===" -ForegroundColor Yellow
    Write-Info "SSID: $(Get-WiFiSSID)"
    Write-Info "Internet: $(Test-InternetAccess)"
    Enable-SSLBypass
    $url = Get-CaptivePortalUrl
    Write-Info "Portal URL: $url"
    $creds = Load-Credentials
    if (-not $creds) { Write-Err "No credentials."; return }
    Write-Info "Logging in with $($creds['SERAPH_ID'])..."
    Invoke-PortalLogin -Creds $creds
    Start-Sleep -Seconds 4
    $inet = Test-InternetAccess
    Write-Host "  Result: $inet" -ForegroundColor $(if ($inet) {'Green'} else {'Red'})
    $sess = Load-Session
    if ($sess) {
        Write-Info "Keepalive URL: $($sess['keepalive_url'])"
    }
}

# ===================== ENTRY POINT =====================

if (-not ($Install -or $Uninstall -or $Setup -or $ChangeUser -or $ChangePassword -or `
          $AddBackup -or $SwitchAccount -or $Logout -or $Keepalive -or $Update -or `
          $Loop -or $Status -or $Test -or $Logs)) {
    Write-Host "`n  KU-WL Auto Login" -ForegroundColor Cyan
    Write-Host "  .\ku-wl-auto-login.ps1 -Install         First time setup (run as Admin)"
    Write-Host "  .\ku-wl-auto-login.ps1 -Status          Check connection & session status"
    Write-Host "  .\ku-wl-auto-login.ps1 -AddBackup       Add backup account for 8GB quota failover"
    Write-Host "  .\ku-wl-auto-login.ps1 -SwitchAccount   Switch between active & backup accounts"
    Write-Host "  .\ku-wl-auto-login.ps1 -Logout          Log out current FortiGate session"
    Write-Host "  .\ku-wl-auto-login.ps1 -Keepalive       View/open active keepalive dashboard URL"
    Write-Host "  .\ku-wl-auto-login.ps1 -Update          Update script to latest version"
    Write-Host "  .\ku-wl-auto-login.ps1 -ChangeUser      Change primary Seraph ID"
    Write-Host "  .\ku-wl-auto-login.ps1 -ChangePassword  Change primary password"
    Write-Host "  .\ku-wl-auto-login.ps1 -Uninstall       Remove`n"
    exit 0
}

if ($Setup)          { Invoke-Setup; exit 0 }
if ($ChangeUser)     { Invoke-ChangeUser; exit 0 }
if ($ChangePassword) { Invoke-ChangePassword; exit 0 }
if ($AddBackup)      { Invoke-AddBackup; exit 0 }
if ($SwitchAccount)  { Invoke-SwitchAccount; exit 0 }
if ($Logout)         { Invoke-Logout; exit 0 }
if ($Keepalive)      { Invoke-Keepalive; exit 0 }
if ($Update)         { Invoke-Update; exit 0 }
if ($Install)        { Install-Task; exit 0 }
if ($Uninstall)      { Uninstall-Task; exit 0 }
if ($Status)         { Show-Status; exit 0 }
if ($Logs)           { Show-Logs; exit 0 }
if ($Test)           { Invoke-TestMode; exit 0 }

if ($Loop) {
    Write-Log "Loop started PID=$PID"
    $lastState = ""
    $lastKeepalivePing = Get-Date

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
                # Dynamically re-read credentials on every attempt
                $creds = Load-Credentials
                if ($creds) {
                    Write-Log "Logging in ($($creds['SERAPH_ID']))..."
                    Invoke-PortalLogin -Creds $creds | Out-Null
                    Start-Sleep -Seconds 4

                    if (Test-InternetAccess) {
                        Write-Log "SUCCESS - Online with $($creds['SERAPH_ID'])"
                        $lastState = "ssid=$SSID|inet=True"
                        $lastKeepalivePing = Get-Date
                    } else {
                        # Internet restricted after login: check 8GB quota failover
                        if ($creds["AUTO_FAILOVER"] -ne "0" -and $creds["BACKUP_SERAPH_ID"] -and $creds["BACKUP_PASSWORD"]) {
                            Write-Log "Internet restricted after login for $($creds['SERAPH_ID']) (possible 8GB quota reached). Attempting auto-failover to backup account $($creds['BACKUP_SERAPH_ID'])..."
                            $backupCreds = @{
                                SERAPH_ID = $creds["BACKUP_SERAPH_ID"]
                                PASSWORD  = $creds["BACKUP_PASSWORD"]
                            }
                            Invoke-PortalLogin -Creds $backupCreds | Out-Null
                            Start-Sleep -Seconds 4

                            if (Test-InternetAccess) {
                                Write-Log "SUCCESS - Quota rollover successful! Online with backup account $($creds['BACKUP_SERAPH_ID'])"
                                # Swap primary and backup in .env so working account remains active
                                Save-Credentials -SeraphId $backupCreds["SERAPH_ID"] -Password $backupCreds["PASSWORD"] `
                                                 -BackupId $creds["SERAPH_ID"] -BackupPassword $creds["PASSWORD"] `
                                                 -AutoFailover "1"
                                $lastState = "ssid=$SSID|inet=True"
                                $lastKeepalivePing = Get-Date
                            } else {
                                Write-Log "Backup account login attempted but internet still restricted."
                            }
                        } else {
                            Write-Log "Login failed or still restricted. Will retry."
                        }
                    }
                }
            } else {
                # Online: periodically ping keepalive URL every ~10 minutes (600s)
                if ($internet -and ((Get-Date) - $lastKeepalivePing).TotalSeconds -ge 600) {
                    $lastKeepalivePing = Get-Date
                    $sess = Load-Session
                    if ($sess -and $sess["keepalive_url"]) {
                        try {
                            Invoke-WebRequest -Uri $sess["keepalive_url"] -TimeoutSec 6 -UseBasicParsing -ErrorAction SilentlyContinue | Out-Null
                            Write-Log "Keepalive ping sent to $($sess['keepalive_url'])"
                        } catch {}
                    }
                }
            }
        } catch { try { Write-Log "ERROR: $($_.Exception.Message)" } catch {} }
        Start-Sleep -Seconds $Interval
    }
}

# Default: single run (event trigger)
$creds = Load-Credentials
if ($creds) {
    $ssid = Get-WiFiSSID
    if ($ssid -eq $SSID -and -not (Test-InternetAccess)) {
        Invoke-PortalLogin -Creds $creds | Out-Null
    }
}
