; MI CS — Windows installer (NSIS 3.x)
;
; Steps 1-2 of ب3: install the files, one Start-Menu entry, a desktop icon, the
; AUMID the toast identity needs — both halves of it: the registry key, and the
; shortcut's System.AppUserModel.ID, which is a Shell property IPropertyStore
; writes (scripts\register-aumid.ps1) and NSIS cannot. An entry in Apps & features
; removes the lot again.
;
; ب4 (D-026) moved one more thing in here: on a per-machine install this elevated
; run also installs the privileged helper — by calling the shipped engine's own
; `install-helper`, so the service definition stays in the engine — and on uninstall
; it stops and deletes the service it created, through
; scripts\check-helper-ownership.ps1 -Remove, whose removal is scoped to the name in
; HELPER_SVC_KEY. The product therefore asks for UAC once, at install, and never
; again; a portable copy still installs the helper from the app, as D-007 describes.
;
; Everything is driven by defines the build script passes in:
;   /DVERSION=0.1.0 /DSRCDIR=<package> /DSCRIPTDIR=<repo scripts> /DOUTFILE=<exe>
;   [/DTESTUSER] [/DHELPER_SVC_KEY=<registry path>]
; TESTUSER builds the same script per-user under %LOCALAPPDATA% with no UAC
; prompt, which is how scripts\verify-installer.ps1 installs and removes it
; without a human clicking anything. The shipped build is per-machine, and only a
; verification build redefines HELPER_SVC_KEY (it defaults to the real service).
;
; Unicode: the product name and the Arabic UI behind it assume it.

Unicode true
SetCompressor /SOLID lzma

!include "MUI2.nsh"
!include "LogicLib.nsh"

!ifndef VERSION
  !define VERSION "0.0.0"
!endif
!ifndef SRCDIR
  !error "SRCDIR must point at the assembled package (pass /DSRCDIR=...)"
!endif
; Which architecture this setup packages (D-003). The binaries inside decide what
; actually runs; this define only names the file, records the arch and lets the
; setup refuse a machine it was not built for.
!ifndef MICS_ARCH
  !define MICS_ARCH "x64"
!endif
!ifndef OUTFILE
  !define OUTFILE "MICS-setup-${VERSION}-${MICS_ARCH}.exe"
!endif
!ifndef SCRIPTDIR
  !error "SCRIPTDIR must point at the repo's scripts folder (pass /DSCRIPTDIR=...)"
!endif

!define APP_NAME "MI CS"
!define APP_EXE "mics_app.exe"
!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\MICS"
!define AUMID_KEY "Software\Classes\AppUserModelId\MICS"
!define AUMID "MICS"

; The Explorer verb (D-041): "Scan with MI CS" on a file, on a folder, and on the
; empty space inside a folder. Explorer reads the per-user class store first, and
; HKCU is written for the account that ran the installer (UAC keeps that user),
; exactly like the toast AUMID above - so even the per-machine build needs no
; extra prompt for this. The command line is the app's `--scan` entry point: one
; path, handed to the window that is already open, or opened in a new one.
!define SCAN_KEY "Software\Classes"
!define SCAN_VERB "MICS"
!define SCAN_LABEL "Scan with ${APP_NAME}"

; The privileged helper the app installs (engine\src\privileged\ops.rs,
; SERVICE_NAME). This installer never creates it - it only asks whose it is before
; removing a copy it points at. A verification build may point this elsewhere; the
; shipped build must leave the default.
!ifndef HELPER_SVC_KEY
  !define HELPER_SVC_KEY "HKLM\SYSTEM\CurrentControlSet\Services\MICSHelper"
!endif

; $SYSDIR resolves to System32 on 32-bit Windows and to SysWOW64 on 64-bit, which
; is exactly where a 32-bit installer's own PowerShell lives.
!define POWERSHELL "$SYSDIR\WindowsPowerShell\v1.0\powershell.exe"

Name "${APP_NAME} ${VERSION}"
BrandingText "${APP_NAME} ${VERSION}"
OutFile "${OUTFILE}"
ShowInstDetails show
ShowUninstDetails show

!ifdef TESTUSER
  RequestExecutionLevel user
  InstallDir "$LOCALAPPDATA\${APP_NAME}"
  !define SHELL_CONTEXT current
!else
  RequestExecutionLevel admin
  InstallDir "$PROGRAMFILES64\${APP_NAME}"
  !define SHELL_CONTEXT all
!endif

!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN "$INSTDIR\${APP_EXE}"
!define MUI_FINISHPAGE_RUN_TEXT "Open ${APP_NAME}"
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "${APP_NAME}"
VIAddVersionKey "FileDescription" "${APP_NAME} installer"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" "MI CS"

; Remember where it went, so an upgrade installs over the same copy instead of
; asking again and leaving a second one behind.
Function .onInit
  SetShellVarContext ${SHELL_CONTEXT}
  ; Refuse the wrong machine before anything is written: an x64 package on Windows
  ; on ARM and an ARM64 package on x64 both install "successfully" and then fail to
  ; start, which is the worst shape a packaging mistake can take. PROCESSOR_
  ; ARCHITECTURE is the machine's own answer (AMD64 / ARM64), not the emulated
  ; process view, so it is the value to ask for. Silent mode gets an exit code
  ; instead of a box, so an unattended install cannot hang on a dialog.
  ReadEnvStr $0 "PROCESSOR_ARCHITECTURE"
  !if "${MICS_ARCH}" == "arm64"
    ${If} $0 != "ARM64"
      IfSilent +2 0
      MessageBox MB_ICONSTOP "This is the Windows on ARM (ARM64) package. This PC reports $0, so the x64 package is the one to run."
      SetErrorLevel 2
      Abort
    ${EndIf}
  !else
    ${If} $0 == "ARM64"
      IfSilent +2 0
      MessageBox MB_ICONSTOP "This is the x64 package. This PC reports ARM64, so the Windows on ARM package is the one to run."
      SetErrorLevel 2
      Abort
    ${EndIf}
  !endif
  ; $PLUGINSDIR is where the AUMID writer is unpacked (and deleted again on exit):
  ; the package folder itself must stay byte-for-byte the one the release gate
  ; checked, so nothing of ours is written into $INSTDIR from here.
  InitPluginsDir
!ifndef TESTUSER
  ReadRegStr $0 HKLM "${UNINST_KEY}" "InstallLocation"
  ${If} $0 != ""
    StrCpy $INSTDIR $0
  ${EndIf}
!endif
FunctionEnd

Section "MI CS" SecMain
  SetShellVarContext ${SHELL_CONTEXT}
  SetOutPath "$INSTDIR"

  ; An upgrade cannot overwrite a running copy: ask the app to close first. A
  ; failure here is normal on a fresh install and is not an error.
  nsExec::ExecToLog 'taskkill /IM ${APP_EXE} /F'
  Pop $0
  Sleep 400

  File /r "${SRCDIR}\*.*"

  WriteUninstaller "$INSTDIR\uninstall.exe"

  CreateDirectory "$SMPROGRAMS\${APP_NAME}"
  CreateShortcut "$SMPROGRAMS\${APP_NAME}\${APP_NAME}.lnk" "$INSTDIR\${APP_EXE}" "" "$INSTDIR\${APP_EXE}" 0
  CreateShortcut "$SMPROGRAMS\${APP_NAME}\Uninstall ${APP_NAME}.lnk" "$INSTDIR\uninstall.exe"
  CreateShortcut "$DESKTOP\${APP_NAME}.lnk" "$INSTDIR\${APP_EXE}" "" "$INSTDIR\${APP_EXE}" 0

  ; The other half of the toast identity: the Shell files a shortcut - and a card
  ; raised under the same id - by System.AppUserModel.ID, which is a property on
  ; the .lnk, not a registry value, so WriteRegStr cannot set it. The proven
  ; IPropertyStore writer is scripts\register-aumid.ps1; the installer unpacks it
  ; (with its interop file) into the temporary plugins folder and calls it for
  ; both shortcuts it just created. Failing to write the property costs the label
  ; on the card, not the card, so it warns instead of aborting the install.
  SetOutPath "$PLUGINSDIR"
  File "${SCRIPTDIR}\register-aumid.ps1"
  File "${SCRIPTDIR}\aumid-interop.ps1"
  SetOutPath "$INSTDIR"
  ; One call per shortcut, deliberately: through a native command line PowerShell
  ; binds only the first value to an array parameter, so
  ; `-Shortcut "a.lnk" "b.lnk"` tags a.lnk and leaves b.lnk unbound and silent
  ; (measured - the desktop icon came out of the first build untagged while the
  ; Start-Menu one read MICS).
  nsExec::ExecToLog '"${POWERSHELL}" -NoProfile -ExecutionPolicy Bypass -File "$PLUGINSDIR\register-aumid.ps1" -AppDir "$INSTDIR" -Shortcut "$SMPROGRAMS\${APP_NAME}\${APP_NAME}.lnk"'
  Pop $0
  nsExec::ExecToLog '"${POWERSHELL}" -NoProfile -ExecutionPolicy Bypass -File "$PLUGINSDIR\register-aumid.ps1" -AppDir "$INSTDIR" -Shortcut "$DESKTOP\${APP_NAME}.lnk"'
  Pop $1
  ${If} $0 == "0"
  ${AndIf} $1 == "0"
    DetailPrint "System.AppUserModel.ID = ${AUMID} written on both shortcuts"
  ${Else}
    DetailPrint "WARNING: the shortcut AUMID property was not written (start menu exit $0, desktop exit $1) - the card source label still comes from the registry key"
  ${EndIf}

  ; The toast identity: Windows shows the card's source as this AppID. The key
  ; is per-user, so it is written for the account that ran the installer (UAC
  ; keeps the same user) — HKCU is correct even from the elevated process.
  WriteRegStr HKCU "${AUMID_KEY}" "DisplayName" "${APP_NAME}"
  WriteRegStr HKCU "${AUMID_KEY}" "IconUri" "$INSTDIR\${APP_EXE}"

  ; "Scan with MI CS" in Explorer's context menu (D-041). Three verbs, because
  ; Windows splits the menu by what was clicked: `*` is a file, `Directory` is a
  ; folder, and `Directory\Background` is the empty space inside one (where
  ; Explorer substitutes %V, the folder, for the %1 a selection gives). The
  ; label is the same text Explorer shows and the icon is the app's own; the
  ; command is the `--scan` entry point, quoted so a path with spaces survives.
  WriteRegStr HKCU "${SCAN_KEY}\*\shell\${SCAN_VERB}" "" "${SCAN_LABEL}"
  WriteRegStr HKCU "${SCAN_KEY}\*\shell\${SCAN_VERB}" "Icon" "$INSTDIR\${APP_EXE}"
  WriteRegStr HKCU "${SCAN_KEY}\*\shell\${SCAN_VERB}\command" "" '"$INSTDIR\${APP_EXE}" --scan "%1"'
  WriteRegStr HKCU "${SCAN_KEY}\Directory\shell\${SCAN_VERB}" "" "${SCAN_LABEL}"
  WriteRegStr HKCU "${SCAN_KEY}\Directory\shell\${SCAN_VERB}" "Icon" "$INSTDIR\${APP_EXE}"
  WriteRegStr HKCU "${SCAN_KEY}\Directory\shell\${SCAN_VERB}\command" "" '"$INSTDIR\${APP_EXE}" --scan "%1"'
  WriteRegStr HKCU "${SCAN_KEY}\Directory\Background\shell\${SCAN_VERB}" "" "${SCAN_LABEL}"
  WriteRegStr HKCU "${SCAN_KEY}\Directory\Background\shell\${SCAN_VERB}" "Icon" "$INSTDIR\${APP_EXE}"
  WriteRegStr HKCU "${SCAN_KEY}\Directory\Background\shell\${SCAN_VERB}\command" "" '"$INSTDIR\${APP_EXE}" --scan "%V"'

  !ifdef TESTUSER
    WriteRegStr HKCU "${UNINST_KEY}" "DisplayName" "${APP_NAME} ${VERSION}"
    WriteRegStr HKCU "${UNINST_KEY}" "DisplayVersion" "${VERSION}"
    WriteRegStr HKCU "${UNINST_KEY}" "DisplayIcon" "$INSTDIR\${APP_EXE}"
    WriteRegStr HKCU "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
    WriteRegStr HKCU "${UNINST_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
    WriteRegStr HKCU "${UNINST_KEY}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
    WriteRegDWORD HKCU "${UNINST_KEY}" "NoModify" 1
    WriteRegDWORD HKCU "${UNINST_KEY}" "NoRepair" 1
  !else
    WriteRegStr HKLM "${UNINST_KEY}" "DisplayName" "${APP_NAME} ${VERSION}"
    WriteRegStr HKLM "${UNINST_KEY}" "DisplayVersion" "${VERSION}"
    WriteRegStr HKLM "${UNINST_KEY}" "Publisher" "MI CS"
    WriteRegStr HKLM "${UNINST_KEY}" "DisplayIcon" "$INSTDIR\${APP_EXE}"
    WriteRegStr HKLM "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINST_KEY}" "Architecture" "${MICS_ARCH}"
    WriteRegStr HKLM "${UNINST_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
    WriteRegStr HKLM "${UNINST_KEY}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
    WriteRegDWORD HKLM "${UNINST_KEY}" "NoModify" 1
    WriteRegDWORD HKLM "${UNINST_KEY}" "NoRepair" 1
    WriteRegDWORD HKLM "${UNINST_KEY}" "EstimatedSize" 51200
  !endif

  ; The privileged helper, installed by the same prompt that installed the product
  ; (ب4/D-026). The engine's `install-helper` is the one place that knows the
  ; service definition (`sc create` with the quoted binPath and the helper-service
  ; argument), so the installer calls it instead of repeating it — the app's
  ; Settings -> Engine button remains as the repair path. A per-user build cannot
  ; own a LocalSystem service, so this is per-machine only.
  ;
  ; A failure is reported, not fatal: an install that cannot create the service
  ; still gives the user a working app (it asks once, later, the way a portable
  ; copy does) and aborting would take the product away over it.
  !ifndef TESTUSER
    DetailPrint "Installing the privileged helper (this is the only prompt MI CS needs)..."
    nsExec::ExecToLog '"$INSTDIR\mics-engine.exe" install-helper'
    Pop $2
    ${If} $2 == "0"
      DetailPrint "The privileged helper is installed and running: no later action will ask for administrator rights."
    ${Else}
      DetailPrint "WARNING: the privileged helper was not installed (exit $2) - MI CS will ask once the first time you use a fix that needs administrator rights, and Settings -> Engine can install or repair it."
    ${EndIf}
  !endif

  ; The app's own state directory: the engine creates it on first run. Tell the
  ; user where the audit trail lives, because that is the product's evidence.
  DetailPrint "State and audit trail: %PROGRAMDATA%\MICS (helper) and %LOCALAPPDATA%\MICS (this user)"
SectionEnd

Section "Uninstall"
  SetShellVarContext ${SHELL_CONTEXT}

  ; The privileged helper, and this is the half ب4 added. This installer created
  ; the service (the app creates it on a portable copy), so it is this installer's
  ; to take away: the checker is asked again with -Remove, which stops and deletes
  ; the service named by HELPER_SVC_KEY, and only when its binPath points at
  ; $INSTDIR. The same elevated run that installed the product removes it, so an
  ; uninstall is one prompt and never leaves a LocalSystem service aimed at a
  ; deleted mics-engine.exe.
  ;
  ; It can still refuse - an unelevated uninstaller, a service another account
  ; owns, a delete the SCM did not accept - and then nothing is removed and the
  ; message says to use the app's own button (which is also what a portable copy
  ; needs). The MessageBox is what an interactive user sees, and it is guarded by
  ; ${IfNot} ${Silent} because a dialog in a silent run waits for a click nobody is
  ; there to make: measured, the refusal dialog stayed open under /S and the exit
  ; code below never arrived, which made "the uninstaller refuses with 5" a claim
  ; only a human could cash. The error level is the answer a scripted caller asks
  ; for, and reading it has a documented form of its own (NSIS copies an uninstaller
  ; to %TEMP% and runs it from there, so a plain `uninstall.exe /S` always answers 0
  ; - appendix D.1):
  ; `uninstall.exe /S _?=$INSTDIR` answers 5 when a refusal fires (the switch must
  ; be last - anywhere else NSIS swallows the rest of the command line into
  ; $INSTDIR, which was measured: the result was a "successful" uninstall that
  ; took the shortcuts and the registry entry and left the files).
  InitPluginsDir
  SetOutPath "$PLUGINSDIR"
  File "${SCRIPTDIR}\check-helper-ownership.ps1"
  nsExec::ExecToLog '"${POWERSHELL}" -NoProfile -ExecutionPolicy Bypass -File "$PLUGINSDIR\check-helper-ownership.ps1" -InstallDir "$INSTDIR" -ServiceKey "${HELPER_SVC_KEY}"'
  Pop $0
  ; 2 means the helper points here, 1 that the key could not be read, anything
  ; else that the check itself did not run. Only the first can be fixed here.
  ${If} $0 == "2"
    nsExec::ExecToLog '"${POWERSHELL}" -NoProfile -ExecutionPolicy Bypass -File "$PLUGINSDIR\check-helper-ownership.ps1" -InstallDir "$INSTDIR" -ServiceKey "${HELPER_SVC_KEY}" -Remove'
    Pop $3
    ${If} $3 == "0"
      DetailPrint "The privileged helper was stopped and removed with this copy."
    ${Else}
      DetailPrint "uninstall refused: the privileged helper could not be removed (exit $3)"
      SetErrorLevel 5
      ; No dialog when the run is silent: it would block a scripted uninstall
      ; forever (measured - the refusal dialog stayed open under /S and the exit
      ; code never arrived), and the error level is the answer a caller asked for.
      ${IfNot} ${Silent}
        MessageBox MB_OK|MB_ICONSTOP "MI CS could not remove its privileged helper, so nothing has been removed.$\r$\n$\r$\nOpen MI CS, go to Settings -> Engine and remove the helper, then run this uninstaller again."
      ${EndIf}
      Abort
    ${EndIf}
  ${ElseIf} $0 != "0"
    DetailPrint "uninstall refused: the helper check did not answer definitively (exit $0)"
    SetErrorLevel 5
    ${IfNot} ${Silent}
      MessageBox MB_OK|MB_ICONSTOP "MI CS could not confirm that no privileged helper points at this copy, so nothing has been removed.$\r$\n$\r$\nIf MI CS is installed, open it, go to Settings -> Engine and remove the helper, then run this uninstaller again. If this is a portable copy that never installed the helper, run the uninstaller again from an account where Windows PowerShell works."
    ${EndIf}
    Abort
  ${EndIf}

  nsExec::ExecToLog 'taskkill /IM ${APP_EXE} /F'
  Pop $0
  Sleep 400

  Delete "$SMPROGRAMS\${APP_NAME}\${APP_NAME}.lnk"
  Delete "$SMPROGRAMS\${APP_NAME}\Uninstall ${APP_NAME}.lnk"
  RMDir "$SMPROGRAMS\${APP_NAME}"
  Delete "$DESKTOP\${APP_NAME}.lnk"

  RMDir /r "$INSTDIR\data"
  RMDir /r "$INSTDIR\rules"
  Delete "$INSTDIR\*.dll"
  Delete "$INSTDIR\*.exe"
  Delete "$INSTDIR\*.json"
  Delete "$INSTDIR\THIRD-PARTY-NOTICES"
  Delete "$INSTDIR\VERSION"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"

  DeleteRegKey HKCU "${AUMID_KEY}"
  ; The Explorer verbs this installer wrote, and only those: the three keys
  ; named above, under HKCU\Software\Classes (D-041). A verb another product
  ; wrote under its own name is not touched, and neither is `Classes` itself.
  DeleteRegKey HKCU "${SCAN_KEY}\*\shell\${SCAN_VERB}"
  DeleteRegKey HKCU "${SCAN_KEY}\Directory\shell\${SCAN_VERB}"
  DeleteRegKey HKCU "${SCAN_KEY}\Directory\Background\shell\${SCAN_VERB}"
  DeleteRegKey HKCU "${UNINST_KEY}"
  !ifndef TESTUSER
    DeleteRegKey HKLM "${UNINST_KEY}"
  !endif

  DetailPrint "Files, shortcuts, the AUMID and the Apps & features entry are gone. Your state folder (audit trail, quarantine, logs) is kept - delete it by hand if you want it gone."
SectionEnd
