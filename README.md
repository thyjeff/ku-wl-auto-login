# KU-WL Auto Login 🔐

![Installs](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.counterapi.dev%2Fv1%2Fku-wl-auto-login%2Finstalls&query=%24.count&label=installs&color=brightgreen&style=flat-square)

**Tired of logging into Karunya Wi-Fi every single day?** This script does it for you — automatically.

When you connect to **KU-WL**, it detects the FortiGate captive portal, fills in your Seraph ID, and logs you in within seconds. No browser needed.

---

## Install (2 Commands — No Apps Needed)

Open **PowerShell as Administrator** (right-click Start → "Windows PowerShell (Admin)") and paste:

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/thyjeff/ku-wl-auto-login/master/ku-wl-auto-login.ps1" -OutFile "$env:USERPROFILE\ku-wl-auto-login.ps1"
```
```powershell
powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\ku-wl-auto-login.ps1" -Install
```

It asks your **Seraph ID** and **password** once → saves locally → auto-logs in forever.

**Done. Close the terminal. Connect to KU-WL and it just works.**

---

## Other Commands (Optional)

```powershell
# Check if it's working
powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\ku-wl-auto-login.ps1" -Status

# Change Seraph ID
powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\ku-wl-auto-login.ps1" -ChangeUser

# Change password
powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\ku-wl-auto-login.ps1" -ChangePassword

# Uninstall
powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\ku-wl-auto-login.ps1" -Uninstall
```

## How It Works

1. You connect to **KU-WL** Wi-Fi
2. Script detects the Seraph portal → fills your credentials → logs you in
3. Runs silently in background — you never see it

## Is My Password Safe?

Your credentials are in a **hidden file on your PC only**:
```
%USERPROFILE%\.ku-wl-autologin\.env
```
Never uploaded anywhere. Never sent to any server except Karunya's login portal.

## FAQ

**Do I need Git, Python, or any app?** No. Just PowerShell which every Windows laptop has.

**Changed your password?** Run `-ChangePassword` command above.

**Want to remove it completely?**
```powershell
powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\ku-wl-auto-login.ps1" -Uninstall
Remove-Item "$env:USERPROFILE\.ku-wl-autologin" -Recurse -Force
Remove-Item "$env:USERPROFILE\ku-wl-auto-login.ps1" -Force
```

## Requirements

- Windows 10/11 with PowerShell (pre-installed)
- Run as Administrator once for setup

## License

MIT
