# KU-WL Auto Login 🔐

![Installs](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.counterapi.dev%2Fv1%2Fku-wl-auto-login%2Finstalls&query=%24.count&label=installs&color=brightgreen&style=flat-square)

**Tired of logging into Karunya Wi-Fi every single day?** This script does it for you — automatically.

When you connect to **KU-WL**, it detects the FortiGate captive portal, fills in your Seraph ID, and logs you in within seconds. No browser needed.

Now includes **8GB Daily Quota Rollover**, **Keepalive Session Tracking**, and **One-Click Account Switching**!

---

## ⚡ How to Update (For Existing Users)

If you already have `ku-wl-auto-login` installed on your laptop, update to the latest version with one command:

```powershell
powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\ku-wl-auto-login.ps1" -Update
```

*(Or right-click PowerShell -> Run as Administrator and run the install command below).*

---

## 🚀 First-Time Install (2 Commands — No Apps Needed)

Open **PowerShell as Administrator** (right-click Start → "Windows PowerShell (Admin)") and paste:

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/thyjeff/ku-wl-auto-login/master/ku-wl-auto-login.ps1" -OutFile "$env:USERPROFILE\ku-wl-auto-login.ps1"
```
```powershell
powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\ku-wl-auto-login.ps1" -Install
```

It asks for your **Seraph ID** and **Password** (and optionally a **Backup ID** for when your 8GB quota runs out) → saves locally → auto-logs in forever.

**Done! Close the terminal. Connect to KU-WL and it just works.**

---

## 🔄 8GB Daily Quota Rollover & Multi-Account Features

Karunya Wi-Fi enforces an **8GB daily data allowance** per student account. When your quota is exhausted, FortiGate restricts traffic.

### 1. Set a Backup Account (Automatic Rollover)
```powershell
powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\ku-wl-auto-login.ps1" -AddBackup
```
Enter a friend's or secondary Seraph ID. When your 8GB limit is reached, the background script **automatically switches accounts and restores your internet** without opening any browser!

### 2. Switch Active Account On-Demand
```powershell
powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\ku-wl-auto-login.ps1" -SwitchAccount
```
Instantly swap between primary and backup accounts or type in a new Seraph ID.

### 3. Log Out Active Session
```powershell
powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\ku-wl-auto-login.ps1" -Logout
```
Cleanly ends your session on the FortiGate firewall (`https://seraph.karunya.edu:1003/logout?...`), freeing the connection.

### 4. View Active Keepalive Dashboard
```powershell
powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\ku-wl-auto-login.ps1" -Keepalive
```
Opens your active FortiGate session dashboard (`https://seraph.karunya.edu:1003/keepalive?...`) in your default browser so you can view session time and data usage.

---

## 📋 Full Command Reference

Run any of these in PowerShell:

| Command | What it does |
|---|---|
| `.\ku-wl-auto-login.ps1 -Status` | View current connection, active Seraph ID, backup ID, and keepalive URL |
| `.\ku-wl-auto-login.ps1 -AddBackup` | Add a backup Seraph ID for automatic 8GB quota failover |
| `.\ku-wl-auto-login.ps1 -SwitchAccount` | Swap between active & backup accounts or activate a new ID |
| `.\ku-wl-auto-login.ps1 -Logout` | Cleanly terminate active FortiGate session |
| `.\ku-wl-auto-login.ps1 -Keepalive` | Open the active keepalive dashboard in browser |
| `.\ku-wl-auto-login.ps1 -Update` | Pull latest updates and restart background service |
| `.\ku-wl-auto-login.ps1 -ChangeUser` | Change primary Seraph ID |
| `.\ku-wl-auto-login.ps1 -ChangePassword` | Change primary password |
| `.\ku-wl-auto-login.ps1 -Logs` | View recent auto-login logs |
| `.\ku-wl-auto-login.ps1 -Uninstall` | Remove scheduled tasks and stop background runner |

---

## 🧠 How It Works

1. You connect to **KU-WL** Wi-Fi.
2. Script probes multiple endpoints (`connectivitycheck.gstatic.com`, `detectportal.firefox.com`, `msftconnecttest.com`) to reliably catch the captive portal redirect.
3. Automatically posts your Seraph ID and password to `https://seraph.karunya.edu:1003/fgtauth?...`.
4. Captures the generated session token (`keepalive?...`), saving the keepalive and logout URLs.
5. Periodically pings the keepalive URL in the background so FortiGate never times out your session.
6. If the 8GB quota is reached, it detects the restriction and automatically switches to your backup account!

---

## 🔒 Is My Password Safe?

Your credentials are stored in a **hidden local file on your laptop only**:
```
%USERPROFILE%\.ku-wl-autologin\.env
```
Never uploaded anywhere. Never sent to any external server except Karunya's official login portal (`https://seraph.karunya.edu:1003`).

---

## ❓ FAQ

**Do I need Git, Python, or any external apps?**
No. It uses pure Windows PowerShell which is pre-installed on every Windows 10/11 laptop.

**How do I update if I already installed it?**
Just run `-Update`:
```powershell
powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\ku-wl-auto-login.ps1" -Update
```

**Changed your university password?**
Run `-ChangePassword`.

**Want to remove it completely?**
```powershell
powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\ku-wl-auto-login.ps1" -Uninstall
Remove-Item "$env:USERPROFILE\.ku-wl-autologin" -Recurse -Force
Remove-Item "$env:USERPROFILE\ku-wl-auto-login.ps1" -Force
```

---

## Requirements

- Windows 10 or 11 with PowerShell (pre-installed)
- Run as Administrator once during initial setup

## License

MIT
