# KU-WL Auto Login 🔐

**Tired of logging into Karunya Wi-Fi every single day?** This script does it for you — automatically.

When you connect to **KU-WL**, it detects the FortiGate captive portal, fills in your Seraph ID, and logs you in within seconds. No browser needed.

## Quick Install (2 commands)

Open **PowerShell as Administrator** and paste:

```powershell
irm https://raw.githubusercontent.com/jefflthyagu/ku-wl-auto-login/main/ku-wl-auto-login.ps1 -OutFile "$env:TEMP\ku-wl-auto-login.ps1"; powershell -ExecutionPolicy Bypass -File "$env:TEMP\ku-wl-auto-login.ps1" -Install
```

It will:
1. Ask for your **Seraph ID** and **password** (stored only on your PC)
2. Set up background tasks that auto-login whenever you connect to KU-WL

**That's it. You're done.**

---

## Manual Install

```powershell
# Download
git clone https://github.com/jefflthyagu/ku-wl-auto-login.git
cd ku-wl-auto-login

# Save your credentials (first time only)
powershell -ExecutionPolicy Bypass -File .\ku-wl-auto-login.ps1 -Setup

# Install (run as Admin)
powershell -ExecutionPolicy Bypass -File .\ku-wl-auto-login.ps1 -Install
```

## Commands

| Command | What it does |
|---------|-------------|
| `-Setup` | Save your Seraph ID & password |
| `-Install` | Enable auto-login (run as Admin) |
| `-ChangeUser` | Change your Seraph ID |
| `-ChangePassword` | Change your password |
| `-Status` | Check if everything is working |
| `-Logs` | View recent login logs |
| `-Test` | Debug mode — shows portal HTML and attempts login |
| `-Uninstall` | Remove auto-login tasks |

## How It Works

1. **WiFi Event Trigger** — Windows detects you connected to a network → runs the script within ~5s
2. **Background Loop** — Checks every 15s if you're on KU-WL without internet → logs you in
3. **FortiGate Portal** — Captures the redirect URL with magic token, POSTs your credentials

## Where Are My Credentials?

Your Seraph ID and password are stored in a **hidden file** on your computer:
```
%USERPROFILE%\.ku-wl-autologin\.env
```
- **Never uploaded** anywhere
- **Never committed** to git
- Only readable by your Windows user account

## FAQ

**Q: Will my password be visible on GitHub?**
No. Credentials are stored locally in a hidden file. The script on GitHub has zero credentials.

**Q: Does it work on hostel Wi-Fi?**
Yes, as long as the SSID is "KU-WL" and the portal is seraph.karunya.edu.

**Q: I changed my Seraph password. How do I update?**
```powershell
powershell -ExecutionPolicy Bypass -File .\ku-wl-auto-login.ps1 -ChangePassword
```

**Q: How do I completely remove it?**
```powershell
# Remove tasks
powershell -ExecutionPolicy Bypass -File .\ku-wl-auto-login.ps1 -Uninstall

# Remove all data including credentials
Remove-Item "$env:USERPROFILE\.ku-wl-autologin" -Recurse -Force
```

## Requirements

- Windows 10/11
- PowerShell 5.1+ (pre-installed on Windows)
- Admin rights (for installing scheduled tasks)

## Contributing

PRs welcome! If you find issues or want to add features, feel free to contribute.

## License

MIT
