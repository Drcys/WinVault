# Changelog

All notable changes to WinVault. Versions follow [Semantic Versioning](https://semver.org/).

## [1.2.0] — 2026-10-13
Completes the twelve areas of the original project plan.

### Added
- **Five new collectors** (11 in total):
  - `firewall` — every Windows Firewall rule (local and Group Policy store) and each profile's on/off state and default inbound action, read from the registry (fast, language-independent).
  - `defender` — Microsoft Defender exclusions (path, extension, process, IP) and protection settings, including tamper protection (Get-MpPreference / Get-MpComputerStatus).
  - `policy` — password and lockout policy and user rights assignments (`secedit /export`) and the advanced audit policy by subcategory GUID (`auditpol /backup`).
  - `software` — installed software from the Uninstall keys (machine 64/32-bit and every loaded user).
  - `system` — UAC, Remote Desktop/NLA, LSA protection, NTLM level, WDigest, SMBv1/signing, Windows Update and PowerShell logging policies, Defender/WinRM policies; Image File Execution Options debuggers and SilentProcessExit monitors.
- **15 new scoring rules** (35 in total): new inbound allow rules and commonly abused ports, rules opened up, firewall profile off; Defender exclusions (broad, user-writable, interpreters, executable types) and weakened protection; weakened password/lockout/audit policy and sensitive user rights granted; new software, remote access tools, security software removed; weakened system settings; IFEO / sticky-keys / SilentProcessExit hijacks.
- **Noise rules** for Microsoft Store app firewall rules (package-scoped, no open port) and software version updates / upgrade pairs, each with adversarial tests.
- **Evidence:** Security 4946/4947/4948 (firewall rules), 4704/4705 (user rights), 4719 (audit policy) and Defender 5007/5001 are collected and correlated; `winvault audit --enable` turns on the three extra audit subcategories.
- `Test-WinVaultChanges.ps1` also adds a firewall rule, a Defender exclusion, an Uninstall entry and an IFEO debugger (all harmless, removed by `-Cleanup`); the Windows CI job asserts that each is detected and scored.
- 26 new tests (125 in total).

## [1.1.0] — 2026-10-13
Hardening release based on the capstone security assessment (findings F-2 to F-6).

### Added
- **Scoring of hijacked existing objects.** Changes to what an existing object runs are now scored, not only new objects: a service whose binary or DLL changed (+40), a scheduled task whose action changed (+40), made to run as SYSTEM (+20) or with highest privileges (+10), or made hidden (+15), an existing Run/RunOnce value that now runs something else (+30), and a startup item whose content was replaced (+25). The *executes an interpreter* and *user-writable location* qualifiers now also apply when such a modification points at powershell/cmd/… or at a user-writable folder.
- New startup items that Windows will run or open at logon (`.exe`, scripts, `.lnk`, `.url`, …) get +20.
- `winvault diff` with snapshot **files** checks them: a file that differs from the SHA-256 recorded for that snapshot in the store index is refused, and a file that can't be checked prints its SHA-256 (also shown in the HTML report) so it can be compared with the original report.
- 17 new tests (`tests/test_hardening.py`), 99 in total.

### Security
- Task definitions and event records containing a DTD or entity declaration are refused before parsing (protects the standard-library XML parser against entity-expansion input).
- Built-in Windows programs (`powershell.exe`, `icacls.exe`, `auditpol.exe`, `wevtutil.exe`, `taskkill.exe`, `tasklist.exe`, `explorer.exe`) are started by their full path under `%SystemRoot%`, so a look-alike earlier on PATH can't be run by the elevated process.

### Changed
- Repository moved to [github.com/Drcys/WinVault](https://github.com/Drcys/WinVault); `Update-WinVault.ps1`, README and the About dialog point there.

## [1.0.2] — 2026-10-01
### Added
- `winvault install` now **pins WinVault to the taskbar** on Windows 11 (from an Administrator terminal), next to File Explorer, with its icon. Your existing pins are kept. It uses Windows' own taskbar-layout setting for the current user, and restarts Explorer once so the pin shows up straight away. `--no-pin` skips it.
- `winvault uninstall` removes the taskbar pin and that setting again.

### Changed
- When it can't pin automatically (Windows 10, a non-admin install, or a taskbar layout your organization already manages), `install` says why and how to pin it by hand.

### Fixed
- `Update-WinVault.ps1` failed to parse in Windows PowerShell 5.1 (the built-in one) because of a non-ASCII character. All scripts are now plain ASCII, and a test keeps them that way.

## [1.0.1] — 2026-09-30
### Added
- `winvault install` also adds a **WinVault** Start menu entry for the desktop app, so it can be searched and pinned to the taskbar. `uninstall` removes it.
- `scripts/Update-WinVault.ps1`: install or update to the latest release in one command, with SHA-256 verification against `SHA256SUMS.txt`.

### Fixed
- A pinned WinVault-GUI.exe and its running window no longer show up as two separate taskbar buttons.

## [1.0.0] — 2026-09-29

First stable release, ready for everyday use on Windows 10/11 without a lab setup.

### Added
- **`winvault.exe` works like any command-line tool**: `winvault install` puts it on PATH, so `winvault compare` works from any terminal.
- `winvault status` (store, elevation, auditing at a glance), `--fail-on LEVEL` exit codes for scripts, coloured output (`--no-color` / `NO_COLOR`), help with examples.
- `winvault audit [--enable]` and *Tools → Enable Auditing* in the app: check and turn on the audit settings WinVault uses, without any script.
- Warning when the Security or System log no longer reaches back to the baseline (evidence overwritten).
- App icon, menu bar, About dialog, and Windows version details on the `.exe` files.
- End-user README, development guide, contributing guide, security policy, and issue and PR templates.

### Changed
- Release binaries renamed: `winvault.exe` (command line, runs inside your terminal, no UAC popup) and `WinVault-GUI.exe` (desktop app).
- The snapshot store is created readable only by Administrators and SYSTEM.
- Index updates are protected by a cross-process lock (two runs at once no longer lose entries). Snapshot writes are fsync'd.

## [0.5.0] — 2026-09-29
### Added
- Self-contained HTML investigation report (`--html`, *Export Report…*) with print layout for PDF.
- `files` collector: SHA-256 of critical configuration files (`hosts`, etc.) and a scoring rule.
- Release workflow that builds `WinVault.exe` and `winvault-cli.exe` with `SHA256SUMS.txt`.

### Fixed
- Group membership changes show only the added/removed members in the app.
- `winvault gui` without PySide6 prints a helpful message instead of a traceback.

## [0.4.0] — 2026-09-29
### Added
- Desktop app (PySide6): severity dashboard, findings table with details, timeline, snapshot manager with integrity check, background workers.
- Shared `service` pipeline and Qt-free `presentation` layer.

## [0.3.0] — 2026-09-29
### Added
- Event Log correlation: who / when / which process, with honest confidence levels.
- Timeline view, alert on cleared audit logs, and coverage warnings when auditing is off.
- `scripts/Enable-WinVaultAuditing.ps1`.

## [0.2.0] — 2026-09-29
### Added
- Noise filtering of known Windows activity (tagged with a reason, never dropped).
- Explainable rule-based risk scoring (Low / Medium / High / Critical).

## [0.1.0] — 2026-09-28
### Added
- Collectors: autorun registry, services, scheduled tasks, users and groups, startup folders.
- SHA-256-verified snapshot store, comparison engine, and CLI.
