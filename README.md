# KU-WL Auto Login 🔐

**Tired of logging into Karunya Wi-Fi every single day?** This script does it for you — automatically.

When you connect to **KU-WL**, it detects the FortiGate captive portal, fills in your Seraph ID, and logs you in within seconds. No browser needed.

---

## Install (Just 2 Commands)

Open **PowerShell as Administrator** (right-click Start → "Windows PowerShell (Admin)") and paste:

**Step 1: Download the script**
```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/thyjeff/ku-wl-auto-login/master/ku-wl-auto-login.ps1" -OutFile "$env:USERPROFILE\ku-wl-auto-login.ps1"
```

**Step 2: Install**
```powershell
powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\ku-wl-auto-login.ps1" -Install
```

It will ask for your **Seraph ID** and **password** (stored only on your PC, never uploaded anywhere).

**That's it. Close the terminal. It works forever.**

---

## Commands

Run these in PowerShell anytime:

```powershell
# Check if it's working
powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\ku-wl-auto-login.ps1" -Status

# Change your Seraph ID
powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\ku-wl-auto-login.ps1" -ChangeUser

# Change your password
powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\ku-wl-auto-login.ps1" -ChangePassword

# Uninstall completely
powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\ku-wl-auto-login.ps1" -Uninstall
```

## How It Works

1. You connect to **KU-WL** Wi-Fi
2. Windows fires a network event → script runs within ~5 seconds
3. Script finds the Seraph portal, fills your ID + password, clicks Login
4. A background loop also checks every 15 seconds as backup
5. You're online — no browser, no typing

## Is My Password Safe?

Yes. Your credentials are stored in a **hidden file** on your computer only:
```
%USERPROFILE%\.ku-wl-autologin\.env
```
- Never uploaded anywhere
- Never sent to any server except the Karunya login portal
- Not visible in File Explorer (hidden file)

## FAQ

**Q: Do I need to install anything (Git, Python, Node)?**
No. Just PowerShell, which every Windows laptop already has.

**Q: I changed my Seraph password. How do I update?**
```powershell
powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\ku-wl-auto-login.ps1" -ChangePassword
```

**Q: How do I remove it completely?**
```powershell
powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\ku-wl-auto-login.ps1" -Uninstall
Remove-Item "$env:USERPROFILE\.ku-wl-autologin" -Recurse -Force
Remove-Item "$env:USERPROFILE\ku-wl-auto-login.ps1" -Force
```

**Q: Does it work on hostel/campus Wi-Fi?**
Yes, anywhere the SSID is "KU-WL" and portal is seraph.karunya.edu.

## Requirements

- Windows 10/11
- PowerShell (pre-installed on all Windows laptops)
- Run as Administrator once for installation

## Contributing

PRs welcome! If you find bugs or want features, feel free to contribute.

## License

MIT
