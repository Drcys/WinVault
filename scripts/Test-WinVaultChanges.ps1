<#
.SYNOPSIS
  Makes a small set of harmless, clearly-labelled changes so you can check
  that WinVault detects them. Run ONLY inside your disposable dev VM.

.DESCRIPTION
  Every artifact is named "WinVaultTest*" and only ever points at notepad.exe.
  Nothing is started or executed. Run with -Cleanup to remove everything.

  Expected detections after `winvault compare`:
    registry : + HKLM\...\Run\WinVaultTest
    services : + WinVaultTestSvc            (manual start, never started)
    tasks    : + \WinVaultTest               (on-logon, notepad.exe)
    users    : + user wv_testuser, ~ group Administrators (members)
    startup  : + WinVaultTest.txt in the All Users Startup folder
    firewall : + rule WinVaultTest           (inbound TCP 4444, only for notepad.exe)
    defender : + path exclusion C:\WinVaultTest (a folder that does not exist)
    software : + WinVaultTest App            (Uninstall entry only, nothing installed)
    system   : + IFEO debugger for WinVaultTest.exe (a program that does not exist)

.EXAMPLE
  winvault baseline --label "clean"
  .\scripts\Test-WinVaultChanges.ps1
  winvault compare --json report.json
  .\scripts\Test-WinVaultChanges.ps1 -Cleanup
#>
[CmdletBinding()]
param([switch]$Cleanup)

$ErrorActionPreference = 'Continue'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated (Administrator) PowerShell.'
}

$RunKey      = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
$StartupFile = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp\WinVaultTest.txt'
$Notepad     = Join-Path $env:SystemRoot 'System32\notepad.exe'
$AdminsGroup = (Get-LocalGroup -SID 'S-1-5-32-544').Name
$SoftwareKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WinVaultTest'
$IfeoKey     = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\WinVaultTest.exe'
$Exclusion   = 'C:\WinVaultTest'

if ($Cleanup) {
    Remove-ItemProperty -Path $RunKey -Name 'WinVaultTest' -ErrorAction SilentlyContinue
    sc.exe delete WinVaultTestSvc | Out-Null
    Unregister-ScheduledTask -TaskName 'WinVaultTest' -Confirm:$false -ErrorAction SilentlyContinue
    Remove-LocalGroupMember -Group $AdminsGroup -Member 'wv_testuser' -ErrorAction SilentlyContinue
    Remove-LocalUser -Name 'wv_testuser' -ErrorAction SilentlyContinue
    Remove-Item $StartupFile -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -Name 'WinVaultTest' -ErrorAction SilentlyContinue
    Remove-Item $SoftwareKey -Recurse -ErrorAction SilentlyContinue
    Remove-Item $IfeoKey -Recurse -ErrorAction SilentlyContinue
    try { Remove-MpPreference -ExclusionPath $Exclusion -ErrorAction Stop } catch { }
    Write-Host 'WinVault test artifacts removed.' -ForegroundColor Green
    return
}

# 1. Registry Run value
New-ItemProperty -Path $RunKey -Name 'WinVaultTest' -Value "`"$Notepad`"" -PropertyType String -Force | Out-Null

# 2. Service (registered, manual start, never started)
sc.exe create WinVaultTestSvc binPath= "`"$Notepad`"" start= demand DisplayName= "WinVault Test Service" | Out-Null

# 3. Scheduled task (on logon, current user)
$action  = New-ScheduledTaskAction -Execute $Notepad
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
Register-ScheduledTask -TaskName 'WinVaultTest' -Action $action -Trigger $trigger `
    -Description 'WinVault detection test - safe to delete' -Force | Out-Null

# 4. Local user + Administrators membership
$pw = ConvertTo-SecureString ([guid]::NewGuid().ToString() + 'Aa1!') -AsPlainText -Force
New-LocalUser -Name 'wv_testuser' -Password $pw -Description 'WinVault detection test' | Out-Null
Add-LocalGroupMember -Group $AdminsGroup -Member 'wv_testuser'

# 5. Startup folder file (plain text, not executable)
'WinVault detection test - safe to delete' | Set-Content -Path $StartupFile

# 6. Firewall rule: inbound TCP 4444, only for notepad.exe (which is not listening)
New-NetFirewallRule -Name 'WinVaultTest' -DisplayName 'WinVaultTest' -Direction Inbound -Action Allow `
    -Protocol TCP -LocalPort 4444 -Program $Notepad | Out-Null

# 7. Microsoft Defender exclusion for a folder that does not exist (skipped if Defender is not active)
try { Add-MpPreference -ExclusionPath $Exclusion -ErrorAction Stop }
catch { Write-Warning "Defender exclusion skipped: $($_.Exception.Message)" }

# 8. Installed-software entry (registry only; nothing is installed)
New-Item -Path $SoftwareKey -Force | Out-Null
New-ItemProperty -Path $SoftwareKey -Name 'DisplayName' -Value 'WinVaultTest App' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $SoftwareKey -Name 'DisplayVersion' -Value '1.0' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $SoftwareKey -Name 'Publisher' -Value 'WinVault' -PropertyType String -Force | Out-Null

# 9. IFEO debugger for WinVaultTest.exe, a program that does not exist
New-Item -Path $IfeoKey -Force | Out-Null
New-ItemProperty -Path $IfeoKey -Name 'Debugger' -Value "`"$Notepad`"" -PropertyType String -Force | Out-Null

Write-Host 'Test artifacts created. Now run: winvault compare' -ForegroundColor Cyan
Write-Host 'Remove them afterwards with: .\scripts\Test-WinVaultChanges.ps1 -Cleanup'
