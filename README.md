🎮 Game Modding Master Pre-Checks v6.0
=============================================

**Author:** [MAC]
**Version:** 6.0 – Stable Release (Public)  
**Release Date:** October 2025  
**Script Type:** PowerShell  
**Compatibility:** Windows 10 / 11 (Pro & Enterprise editions)  
**Purpose:** Perform deep system and security diagnostics before launching or testing game modifications.

🧠 Overview
-----------
**Game Modding Pre-Checks v6.0** is a PowerShell-based diagnostic and configuration script designed for PC modders and developers.  
It scans a Windows system for environment readiness, lists active security features, and can (optionally) disable them to ensure compatibility when running or debugging heavily modified game clients.

The script generates a full timestamped **Security Feature Report** under:
```
C:\TobysFiles\Security_Feature_Report_<timestamp>.txt
```

⚙️ Key Features
---------------

🔍 **System Audit**
- Collects full hardware & OS information (CPU, GPU, BIOS, TPM, Virtualization, RAM, Storage, Motherboard)  
- Displays build number, architecture, and Windows version  
- Logs all findings to file for later reference  

🛡️ **Security Check Suite**
Scans and reports the status of:
- **SmartScreen** (Explorer, Edge, Store Apps)  
- **Windows Defender Real-Time Protection**  
- **User Account Control (UAC)**  
- **Windows Firewall Profiles** (Domain, Private, Public)  
- **Exploit Protection Mitigations**  
  - Control Flow Guard (CFG)  
  - Data Execution Prevention (DEP)  
  - ASLR (Force Relocate Images, Bottom-up, High Entropy)  
  - SEHOP and Heap Integrity Validation  

🧩 **Optional Disable Module**
After review, users can opt to disable all security features for modding/testing.  
The script safely:
- Edits the registry using hardened functions  
- Updates Defender, Firewall, and UAC settings  
- Disables Exploit Protection system-wide  
- Re-checks and verifies each setting post-change  

🧾 **Comprehensive Logging**
- Every action is timestamped and written to a report  
- Includes error handling and status color-coding for each operation  
- Safe registry functions (`Set-RegValueSafe`, `Ensure-Key`) prevent damage  

🧰 Usage
--------

**1️⃣ Run Pre-Check Only**
1. Save the script as `GAME MODDING-MASTER-PRECHECKS v6.0.ps1`  
2. Right-click → **Run with PowerShell (Admin)**  
3. The script will:  
   - Elevate permissions if needed  
   - Collect and display all system and security information  
   - Generate a log in `C:\TobysFiles`  

**2️⃣ Optional Disable Stage**
After the scan, it asks:
```
You can disable the above security features now. (Some changes require a reboot to fully apply.)
Disable ALL now? (Y/N)
```
If “Yes”, the script automatically adjusts SmartScreen, Defender, Firewall, UAC, and Exploit Protection, then runs a post-check verification.

📂 Log Output Example
----------------------
```
===== Windows Security Section =====
Check apps and files                           : Enabled
SmartScreen for Microsoft Edge                 : Enabled
SmartScreen for Microsoft Store apps           : Enabled
Windows Defender Real-time Protection          : Enabled
User Account Control (UAC)                     : Prompting (EnableLUA=1, ConsentPrompt=5)
Windows Firewall - Domain                      : On
Windows Firewall - Private                     : On
Windows Firewall - Public                      : On
Control Flow Guard (CFG)                       : Enabled
...
Security feature scan complete.
Report saved to: C:\TobysFiles\Security_Feature_Report_20251021_210045.txt
```

⚠️ Warnings & Notes
--------------------
- Always run as Administrator for full access.  
- Disabling Defender or UAC may require a reboot to apply.  
- Do **not** run the disable options on production systems.  
- All changes are logged for audit and reversal if needed.  

🧩 Advanced Options
--------------------
The script includes:
- **Safe registry writes** (`Set-RegValueSafe`)  
- **Process mitigation API calls** (`Get-ProcessMitigation`, `Set-ProcessMitigation`)  
- **TPM & Virtualization status probes**  
- **Dynamic log timestamping for versioned report tracking**  

🧑‍💻 Contributors
------------------
- **MAC** – Lead Developer & Maintainer  
- Script family inspired by Phr0sTByTe diagnostic utilities  

📜 License
-----------
This project is licensed under the **MIT License** — you may use, modify, and redistribute with credit to MAC.

MIT License © 2025 MAC
