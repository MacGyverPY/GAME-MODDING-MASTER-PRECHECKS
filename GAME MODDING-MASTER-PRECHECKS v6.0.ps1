# =======================================================================================================
# Game Modding Pre-Checks v6.0 – Stable Release (Public) - October 2025
# Built By: MAC
# =======================================================================================================

# --- SAFETY FIX: Ensure script runs inside PowerShell Console ---
if ($Host.Name -ne 'ConsoleHost' -and $Host.Name -ne 'Visual Studio Code Host') {
    Write-Host "`n[!] Relaunching in PowerShell Console for proper output..." -ForegroundColor Yellow
    Start-Process powershell "-ExecutionPolicy Bypass -NoExit -File `"$PSCommandPath`""
    exit
}

# --- Elevate to Administrator if needed ---
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Host "[!] Elevating to Administrator..." -ForegroundColor Yellow
    Start-Process powershell "-ExecutionPolicy Bypass -NoExit -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# =======================================================================================================
# HEADER OUTPUT
# =======================================================================================================
Write-Host "`n===================================================================================================" -ForegroundColor Cyan
Write-Host "BadBoyCheats Pre-Checks v6.0 – Stable Release (Public) - October 2025" -ForegroundColor Cyan
Write-Host "Built By: Toby / Phr0sTByTe" -ForegroundColor Cyan
Write-Host "===================================================================================================`n" -ForegroundColor Cyan

# =======================================================================================================
# SETUP LOGGING
# =======================================================================================================
$logFolder = "C:\TobysFiles"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = Join-Path $logFolder "Security_Feature_Report_$timestamp.txt"

if (!(Test-Path $logFolder)) {
    New-Item -Path $logFolder -ItemType Directory -Force | Out-Null
}

Add-Content $logFile "==================================================================================================="
Add-Content $logFile "Game Modding Pre-Checks v6.0 – Stable Release (Public) - October 2025"
Add-Content $logFile "Built By: MAC"
Add-Content $logFile "Run at: $(Get-Date -Format u)"
Add-Content $logFile "==================================================================================================="

# =======================================================================================================
# HELPERS
# =======================================================================================================
function Add-SystemInfo {
    param($title, $value)
    Write-Host ("{0,-35}: {1}" -f $title, $value) -ForegroundColor Gray
    Add-Content $logFile ("{0}: {1}" -f $title, $value)
}

function Write-Status {
    param(
        [string]$Name,
        [string]$State,   # Enabled, Disabled, On, Off, OK, Warn, Error, "Skipped"
        [string]$Info = ""
    )
    $color = switch -Regex ($State) {
        "Enabled|OK|On"                 { "Green"; break }
        "Disabled|Off"                  { "Red"; break }
        "Warn|Not Found|Skipped|Error"  { "Yellow"; break }
        default                         { "Yellow" }
    }
    $line = if ($Info) { ("{0,-50}: {1}  ({2})" -f $Name, $State, $Info) }
            else       { ("{0,-50}: {1}"       -f $Name, $State) }
    Write-Host $line -ForegroundColor $color
    Add-Content $logFile $line
}

# Safe key creation (never deletes an existing key)
function Ensure-Key {
    param([string]$Path)
    try {
        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        return $true
    } catch {
        Write-Status "Registry Key" "Skipped" "Create failed: $Path"
        Add-Content $logFile "ERROR Ensure-Key: $Path :: $($_.Exception.Message)"
        return $false
    }
}

# Safely set registry value (creates key if allowed; writes value; logs warnings)
function Set-RegValueSafe {
    param(
        [string]$Path,
        [string]$Name,
        [Parameter(Mandatory=$true)] $Value,
        [ValidateSet('String','DWord','QWord','Binary','MultiString','ExpandString')]
        [string]$Type = 'String',
        [switch]$CreateKeyIfMissing = $true
    )
    try {
        if (-not (Test-Path -LiteralPath $Path)) {
            if ($CreateKeyIfMissing) {
                if (-not (Ensure-Key -Path $Path)) { return $false }
            } else {
                Write-Status "Registry Value" "Skipped" "Path missing: $Path"
                Add-Content $logFile "WARN Set-RegValueSafe: Path missing $Path"
                return $false
            }
        }

        $exists = $false
        try {
            $null = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
            $exists = $true
        } catch { $exists = $false }

        if ($exists) {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -ErrorAction Stop | Out-Null
        } else {
            New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction Stop | Out-Null
        }
        return $true
    } catch {
        Write-Status "Registry Value" "Skipped" "Set failed: $Path\$Name (see log)"
        Add-Content $logFile "ERROR Set-RegValueSafe: $Path\$Name :: $($_.Exception.Message)"
        return $false
    }
}

# =======================================================================================================
# SYSTEM INFORMATION
# =======================================================================================================
Write-Host "`n===== System Information Summary =====" -ForegroundColor Cyan
Add-Content $logFile "`n===== System Information Summary ====="

try {
    $osInfo    = Get-ComputerInfo | Select-Object -Property OsName, OsArchitecture, WindowsVersion, WindowsBuildLabEx
    $dispVer   = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").DisplayVersion
    Add-SystemInfo "Operating System" "$($osInfo.OsName) ($dispVer)"
    Add-SystemInfo "Architecture"     "$($osInfo.OsArchitecture)"
    Add-SystemInfo "Windows Version"  "$($osInfo.WindowsVersion)"
    Add-SystemInfo "Build Lab"        "$($osInfo.WindowsBuildLabEx)"
} catch { Add-SystemInfo "Operating System" "Unable to retrieve" }

try { $bios = Get-CimInstance Win32_BIOS | Select-Object -First 1
      Add-SystemInfo "BIOS Version" "$($bios.SMBIOSBIOSVersion) - $($bios.Manufacturer)"
} catch { Add-SystemInfo "BIOS Version" "Unable to retrieve" }

try { $hwid = (Get-CimInstance Win32_ComputerSystemProduct).UUID
      Add-SystemInfo "HWID (UUID)" "$hwid"
} catch { Add-SystemInfo "HWID" "Unable to retrieve" }

try {
    $storageDevices = Get-CimInstance Win32_DiskDrive | ForEach-Object {
        $serial = if ($_.SerialNumber) { $_.SerialNumber } else { "N/A" }
        [PSCustomObject]@{Model=$_.Model; SerialNumber=$serial}
    }
    foreach ($d in $storageDevices) {
        Add-SystemInfo "Disk Model" "$($d.Model) - Serial: $($d.SerialNumber)"
    }
} catch { Add-SystemInfo "Storage Devices" "Unable to retrieve" }

try { $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name
      Add-SystemInfo "Processor" "$cpu"
} catch { Add-SystemInfo "Processor" "Unable to retrieve" }

try {
    $gpus = Get-CimInstance Win32_VideoController | Select-Object Name, AdapterCompatibility, DriverVersion
    foreach ($g in $gpus) {
        Add-SystemInfo "Graphics Card"       "$($g.AdapterCompatibility) - $($g.Name)"
        Add-SystemInfo "GPU Driver Version"  "$($g.DriverVersion)"
    }
} catch { Add-SystemInfo "Graphics Card" "Unable to retrieve" }

try { $ramBytes = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
      $ramGB = [math]::Round($ramBytes/1GB,2)
      Add-SystemInfo "Installed RAM" "$ramGB GB"
} catch { Add-SystemInfo "Installed RAM" "Unable to retrieve" }

try { $mb = Get-CimInstance Win32_BaseBoard | Select-Object -First 1
      Add-SystemInfo "Motherboard" "$($mb.Manufacturer) $($mb.Product)"
} catch { Add-SystemInfo "Motherboard" "Unable to retrieve" }

try {
    $tpm = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm -ErrorAction Stop
    $tpmStatus = if ($tpm -and $tpm.IsEnabled_InitialValue) {"Enabled"} else {"Disabled or Not Present"}
    Add-SystemInfo "TPM" "$tpmStatus"
} catch { Add-SystemInfo "TPM" "Unable to retrieve" }

# Virtualization enabled in firmware
try {
    $virtSupport = systeminfo | Select-String "Virtualization Enabled In Firmware"
    $virtStatus = if ($virtSupport -match ":\s*Yes") { "Enabled" } else { "Disabled or Unsupported" }
    Add-SystemInfo "Virtualization" "$virtStatus"
} catch { Add-SystemInfo "Virtualization" "Unable to retrieve" }

# =======================================================================================================
# WINDOWS SECURITY SECTION
# =======================================================================================================
Write-Host "`n===== Windows Security Section =====" -ForegroundColor Cyan
Add-Content $logFile "`n===== Windows Security Section ====="

# --- 1) SmartScreen Status (robust detection across keys) ---
function Get-SmartScreenStatus {
    $result = [ordered]@{}

    # Check apps and files (Explorer policy value is historically string: Off/Warn/RequireAdmin; sometimes DWORD)
    try {
        $explKey  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
        $explProp = (Get-ItemProperty -Path $explKey -Name "SmartScreenEnabled" -ErrorAction Stop).SmartScreenEnabled
        $result["Check apps and files"] = if ($explProp -in @("Warn","RequireAdmin",1,"1")) {"Enabled"} elseif ($explProp -in @("Off",0,"0")) {"Disabled"} else {"Unknown ($explProp)"}
    } catch {
        $result["Check apps and files"] = "Not Found"
    }

    # SmartScreen for Microsoft Edge (DWORD 1/0 under HKCU)
    try {
        $edgeKey  = "HKCU:\Software\Microsoft\Edge"
        $edgeVal  = (Get-ItemProperty -Path $edgeKey -Name "SmartScreenEnabled" -ErrorAction Stop).SmartScreenEnabled
        $result["SmartScreen for Microsoft Edge"] = if ($edgeVal -eq 1) {"Enabled"} elseif ($edgeVal -eq 0) {"Disabled"} else {"Unknown ($edgeVal)"}
    } catch {
        $result["SmartScreen for Microsoft Edge"] = "Not Found"
    }

    # SmartScreen for Microsoft Store apps (DWORD 1/0 under HKCU, key: EnableWebContentEvaluation)
    try {
        $appHostKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost"
        $appVal     = (Get-ItemProperty -Path $appHostKey -Name "EnableWebContentEvaluation" -ErrorAction Stop).EnableWebContentEvaluation
        $result["SmartScreen for Microsoft Store apps"] = if ($appVal -eq 1) {"Enabled"} elseif ($appVal -eq 0) {"Disabled"} else {"Unknown ($appVal)"}
    } catch {
        $result["SmartScreen for Microsoft Store apps"] = "Not Found"
    }

    return [PSCustomObject]$result
}

$ss = Get-SmartScreenStatus
$ss.PSObject.Properties | ForEach-Object { Write-Status $_.Name $_.Value }

# --- 2) Defender Real-time Protection ---
try {
    $rt = (Get-MpComputerStatus -ErrorAction Stop).RealTimeProtectionEnabled
    Write-Status "Windows Defender Real-time Protection" ($(if ($rt) {"Enabled"} else {"Disabled"}))
} catch {
    Write-Status "Windows Defender Real-time Protection" "Error" "Module unavailable or Tamper Protection"
    Add-Content $logFile "ERROR Get-MpComputerStatus: $($_.Exception.Message)"
}

# --- 3) UAC status (Never notify / disabled) ---
try {
    $polKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $lua  = (Get-ItemProperty -Path $polKey -Name "EnableLUA" -ErrorAction Stop).EnableLUA
    $cons = (Get-ItemProperty -Path $polKey -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
    $uacStatus = if ($lua -eq 0 -or $cons -eq 0) {"Never notify"} else {"Prompting"}
    Write-Status "User Account Control (UAC)" $uacStatus "EnableLUA=$lua, ConsentPrompt=$cons"
} catch {
    Write-Status "User Account Control (UAC)" "Error" "Unable to read policy"
    Add-Content $logFile "ERROR Read UAC policy: $($_.Exception.Message)"
}

# --- 4) Firewall profiles ---
try {
    $profiles = Get-NetFirewallProfile
    foreach ($p in $profiles) {
        $state = if ($p.Enabled) {"On"} else {"Off"}
        Write-Status ("Windows Firewall - {0}" -f $p.Name) $state
    }
} catch {
    Write-Status "Windows Firewall (all profiles)" "Error" "Unable to query"
    Add-Content $logFile "ERROR Get-NetFirewallProfile: $($_.Exception.Message)"
}

# --- 5) Exploit Protection (System) – Accurate detection (Dual-Check) ---
Write-Host "`n===== Exploit Protection (System) =====" -ForegroundColor Cyan
Add-Content $logFile "`n===== Exploit Protection (System) ====="

function Get-EPValueFromKeys {
    param(
        [string]$ValueName
    )
    # Primary (Defender ExploitGuard system policy)
    $k1 = "HKLM:\SOFTWARE\Microsoft\Windows Defender\ExploitGuard\MitigationPolicies\System"
    # Secondary (Memory Management fallback probe; some builds surface toggles here via derived values)
    $k2 = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"

    try {
        $v1 = (Get-ItemProperty -Path $k1 -Name $ValueName -ErrorAction Stop).$ValueName
        return @{ Found=$true; Value=$v1; Source=$k1 }
    } catch {
        try {
            $v2 = (Get-ItemProperty -Path $k2 -Name $ValueName -ErrorAction Stop).$ValueName
            return @{ Found=$true; Value=$v2; Source=$k2 }
        } catch {
            return @{ Found=$false; Value=$null; Source=$null }
        }
    }
}

function Report-EP {
    param(
        [string]$Label,
        [string]$RegValueName,
        [bool]$FallbackMitigationEnabled
    )
    $probe = Get-EPValueFromKeys -ValueName $RegValueName

    if ($probe.Found) {
        if ($probe.Value -eq 1) {
            Write-Status $Label "Enabled" "Policy override ($($probe.Source))"
        } elseif ($probe.Value -eq 0) {
            Write-Status $Label "Disabled" "Off by default ($($probe.Source))"
        } else {
            # Unknown custom value; show numeric
            Write-Status $Label "Warn" "Unknown value=$($probe.Value) ($($probe.Source))"
        }
    } else {
        # If not set in registry, treat as "Off by default" regardless of Get-ProcessMitigation
        if ($FallbackMitigationEnabled) {
            # GUI often shows Off-by-default; be explicit that no policy exists
            Write-Status $Label "Disabled" "Off by default (no policy set)"
        } else {
            Write-Status $Label "Disabled" "Off by default"
        }
    }
}

# We still call Get-ProcessMitigation once for boolean fallbacks
$mit = $null
try { $mit = Get-ProcessMitigation -System } catch { Add-Content $logFile "WARN Get-ProcessMitigation fallback: $($_.Exception.Message)" }

Report-EP "Control Flow Guard (CFG)"                       "CFGEnable"                 ($mit -and $mit.CFG.Enable)
Report-EP "Data Execution Prevention (DEP)"                "EnableDEP"                 ($mit -and $mit.DEP.Enable)
Report-EP "Force Randomization for Images"                 "ForceRelocateImages"       ($mit -and $mit.ASLR.ForceRelocateImages)
Report-EP "Randomize Memory Allocations (Bottom-up ASLR)"  "BottomUpASLR"              ($mit -and $mit.ASLR.BottomUp)
Report-EP "High-Entropy ASLR"                              "HighEntropyASLR"           ($mit -and $mit.ASLR.HighEntropy)
Report-EP "Validate Exception Chains (SEHOP)"              "SEHOP"                     ($mit -and $mit.SEHOP.Enable)
Report-EP "Validate Heap Integrity"                        "HeapTerminateOnCorruption" ($mit -and $mit.Heap.EnableTermination)

# =======================================================================================================
# OPTION: DISABLE ALL with HARDENED REG HANDLING (silent errors -> logs)
# =======================================================================================================
Write-Host "`nYou can disable the above security features now. (Some changes require a reboot to fully apply.)" -ForegroundColor Yellow
$doDisable = Read-Host "Disable ALL now? (Y/N)"
$DisableReport = @()

if ($doDisable -match '^(y|yes)$') {
    $steps = @(
        "Disable SmartScreen (Explorer, Edge, Store apps)",
        "Disable Defender Real-Time Monitoring",
        "Set UAC to 'Never notify' (EnableLUA=0; ConsentPrompt=0)",
        "Turn OFF Windows Firewall (Domain/Private/Public)",
        "Disable Exploit Protection mitigations (system)"
    )

    $i = 0
    foreach ($s in $steps) {
        $i++
        Write-Progress -Activity "Disabling Security Features" -Status $s -PercentComplete (($i-1)/$steps.Count*100)

        switch ($s) {
            "Disable SmartScreen (Explorer, Edge, Store apps)" {
                $ok1 = Set-RegValueSafe -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off" -Type String -CreateKeyIfMissing:$true
                if (-not $ok1) { Write-Status "SmartScreen (Check apps and files)" "Skipped" "Permission or policy" }

                $ok2 = Set-RegValueSafe -Path "HKCU:\Software\Microsoft\Edge" -Name "SmartScreenEnabled" -Value 0 -Type DWord -CreateKeyIfMissing:$true
                if (-not $ok2) { Write-Status "SmartScreen (Edge)" "Skipped" "Permission or policy" }

                $ok3 = Set-RegValueSafe -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Value 0 -Type DWord -CreateKeyIfMissing:$true
                if (-not $ok3) { Write-Status "SmartScreen (Store apps)" "Skipped" "Permission or policy" }

                $DisableReport += [pscustomobject]@{ Item="SmartScreen (Explorer/Edge/Store)"; Result= if ($ok1 -and $ok2 -and $ok3) {"Disabled"} else {"Partial/Skipped"} }
            }

            "Disable Defender Real-Time Monitoring" {
                $ok = $false
                try { Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop; $ok = $true }
                catch {
                    Write-Status "Defender Realtime" "Skipped" "Tamper Protection or policy (see log)"
                    Add-Content $logFile "ERROR Set-MpPreference -DisableRealtimeMonitoring: $($_.Exception.Message)"
                }
                $DisableReport += [pscustomobject]@{ Item="Defender Real-time"; Result= if ($ok) {"Disabled"} else {"Skipped"} }
            }

            "Set UAC to 'Never notify' (EnableLUA=0; ConsentPrompt=0)" {
                $polKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                $okA=$false; $okB=$false; $okC=$false

                if (Test-Path $polKey) {
                    $okA = Set-RegValueSafe -Path $polKey -Name "EnableLUA" -Value 0 -Type DWord -CreateKeyIfMissing:$false
                    $okB = Set-RegValueSafe -Path $polKey -Name "ConsentPromptBehaviorAdmin" -Value 0 -Type DWord -CreateKeyIfMissing:$false
                    $okC = Set-RegValueSafe -Path $polKey -Name "PromptOnSecureDesktop" -Value 0 -Type DWord -CreateKeyIfMissing:$false
                } else {
                    Write-Status "UAC policy" "Skipped" "Key missing ($polKey)"
                    Add-Content $logFile "WARN UAC policy key missing: $polKey"
                }
                $DisableReport += [pscustomobject]@{ Item="UAC (Never notify)"; Result= if ($okA -and $okB -and $okC) {"Set"} else {"Partial/Skipped"} }
            }

            "Turn OFF Windows Firewall (Domain/Private/Public)" {
                $ok = $false
                try { Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled False -ErrorAction Stop; $ok = $true }
                catch {
                    Write-Status "Firewall" "Skipped" "Permission or GPO (see log)"
                    Add-Content $logFile "ERROR Set-NetFirewallProfile disable: $($_.Exception.Message)"
                }
                $DisableReport += [pscustomobject]@{ Item="Firewall Profiles"; Result= if ($ok) {"Off"} else {"Skipped"} }
            }

            "Disable Exploit Protection mitigations (system)" {
                $ok = $false
                try {
                    Set-ProcessMitigation -System -Disable DEP,CFG,ForceRelocateImages,BottomUp,SEHOP,HighEntropy -ErrorAction Stop | Out-Null
                    $ok = $true
                } catch {
                    Add-Content $logFile "ERROR Set-ProcessMitigation -System -Disable: $($_.Exception.Message)"
                    Write-Status "Process Mitigation" "Skipped" "Policy/OS restriction (see log)"
                }
                $DisableReport += [pscustomobject]@{ Item="Exploit Protection (system)"; Result= if ($ok) {"Disabled"} else {"Skipped"} }
            }
        }
    }
    Write-Progress -Activity "Disabling Security Features" -Completed

    Write-Host "`nRe-checking statuses..." -ForegroundColor Yellow
    Add-Content $logFile "`n=== Post-Disable Verification ==="

    # Re-check SmartScreen
    $ss2 = Get-SmartScreenStatus
    $ss2.PSObject.Properties | ForEach-Object { Write-Status $_.Name $_.Value }

    # Re-check Defender
    try {
        $rt2 = (Get-MpComputerStatus -ErrorAction Stop).RealTimeProtectionEnabled
        Write-Status "Windows Defender Real-time Protection" ($(if ($rt2) {"Enabled"} else {"Disabled"}))
    } catch {
        Write-Status "Windows Defender Real-time Protection" "Error" "Module unavailable or Tamper Protection"
        Add-Content $logFile "ERROR Post-check Get-MpComputerStatus: $($_.Exception.Message)"
    }

    # Re-check UAC
    try {
        $polKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $lua2  = (Get-ItemProperty -Path $polKey -Name "EnableLUA" -ErrorAction Stop).EnableLUA
        $cons2 = (Get-ItemProperty -Path $polKey -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
        $uacStatus2 = if ($lua2 -eq 0 -or $cons2 -eq 0) {"Never notify"} else {"Prompting"}
        Write-Status "User Account Control (UAC)" $uacStatus2 "EnableLUA=$lua2, ConsentPrompt=$cons2"
    } catch {
        Write-Status "User Account Control (UAC)" "Error" "Unable to read policy"
        Add-Content $logFile "ERROR Post-check UAC policy: $($_.Exception.Message)"
    }

    # Re-check Firewall
    try {
        $profiles2 = Get-NetFirewallProfile
        foreach ($p in $profiles2) {
            $state2 = if ($p.Enabled) {"On"} else {"Off"}
            Write-Status ("Windows Firewall - {0}" -f $p.Name) $state2
        }
    } catch {
        Write-Status "Windows Firewall (all profiles)" "Error" "Unable to query"
        Add-Content $logFile "ERROR Post-check Get-NetFirewallProfile: $($_.Exception.Message)"
    }

    # Re-check Exploit Protection with dual-check again
    Write-Host "`n===== Exploit Protection (System) - After Disable =====" -ForegroundColor Cyan
    Add-Content $logFile "`n===== Exploit Protection (System) - After Disable ====="
    try {
        $mit2 = $null
        try { $mit2 = Get-ProcessMitigation -System } catch { Add-Content $logFile "WARN Post-check Get-ProcessMitigation: $($_.Exception.Message)" }
        Report-EP "Control Flow Guard (CFG)"                       "CFGEnable"                 ($mit2 -and $mit2.CFG.Enable)
        Report-EP "Data Execution Prevention (DEP)"                "EnableDEP"                 ($mit2 -and $mit2.DEP.Enable)
        Report-EP "Force Randomization for Images"                 "ForceRelocateImages"       ($mit2 -and $mit2.ASLR.ForceRelocateImages)
        Report-EP "Randomize Memory Allocations (Bottom-up ASLR)"  "BottomUpASLR"              ($mit2 -and $mit2.ASLR.BottomUp)
        Report-EP "High-Entropy ASLR"                              "HighEntropyASLR"           ($mit2 -and $mit2.ASLR.HighEntropy)
        Report-EP "Validate Exception Chains (SEHOP)"              "SEHOP"                     ($mit2 -and $mit2.SEHOP.Enable)
        Report-EP "Validate Heap Integrity"                        "HeapTerminateOnCorruption" ($mit2 -and $mit2.Heap.EnableTermination)
    } catch {
        Write-Status "Exploit Protection" "Error" "Unable to query post-disable"
        Add-Content $logFile "ERROR Post-Disable EP recheck: $($_.Exception.Message)"
    }

    # --- Summary of disable operations ---
    Write-Host "`n===== Disable Operations Summary =====" -ForegroundColor Cyan
    Add-Content $logFile "`n===== Disable Operations Summary ====="
    foreach ($row in $DisableReport) {
        try {
            $color = if ($row.Result -match 'Disabled|Off|Set') { "Green" } else { "Yellow" }
            $msg   = ("{0,-50}: {1}" -f $row.Item, $row.Result)
            Write-Host $msg -ForegroundColor $color
            Add-Content $logFile $msg
        } catch {
            $errMsg = "Summary write failed for $($row.Item): $($_.Exception.Message)"
            Write-Host $errMsg -ForegroundColor Yellow
            Add-Content $logFile $errMsg
        }
    }

    Write-Host "`n[!] Note: UAC changes require a restart to fully apply." -ForegroundColor Yellow
}

# =======================================================================================================
# END OF REPORT
# =======================================================================================================
Write-Host "`n===================================================================================================" -ForegroundColor Cyan
Write-Host "Security feature scan complete. Report saved to:" -ForegroundColor Green
Write-Host "$logFile" -ForegroundColor Yellow
Write-Host "===================================================================================================`n" -ForegroundColor Cyan

Read-Host "Press ENTER to exit"