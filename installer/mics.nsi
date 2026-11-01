; MI CS — Windows installer (NSIS 3.x)
;
; Step 1 of ب3: install the files, one Start-Menu entry, a desktop icon, the
; AUMID the toast identity needs, and an entry in Apps & features that can
; uninstall it again. The privileged helper stays where it is for now (the app
; installs it behind one UAC prompt); folding it into this installer is ب4, and
; the shortcut's System.AppUserModel.ID property is step 2 of ب3.
;
; Everything is driven by defines the build script passes in:
;   /DVERSION=0.1.0 /DSRCDIR=<package> /DOUTFILE=<exe> [/DTESTUSER]
; TESTUSER builds the same script per-user under %LOCALAPPDATA% with no UAC
; prompt, which is how scripts\verify-installer.ps1 installs and removes it
; without a human clicking anything. The shipped build is per-machine.
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
!ifndef OUTFILE
  !define OUTFILE "MICS-setup-${VERSION}-x64.exe"
!endif

!define APP_NAME "MI CS"
!define APP_EXE "mics_app.exe"
!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\MICS"
!define AUMID_KEY "Software\Classes\AppUserModelId\MICS"
!define AUMID "MICS"

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

  ; The toast identity: Windows shows the card's source as this AppID. The key
  ; is per-user, so it is written for the account that ran the installer (UAC
  ; keeps the same user) — HKCU is correct even from the elevated process.
  WriteRegStr HKCU "${AUMID_KEY}" "DisplayName" "${APP_NAME}"
  WriteRegStr HKCU "${AUMID_KEY}" "IconUri" "$INSTDIR\${APP_EXE}"

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
    WriteRegStr HKLM "${UNINST_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
    WriteRegStr HKLM "${UNINST_KEY}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
    WriteRegDWORD HKLM "${UNINST_KEY}" "NoModify" 1
    WriteRegDWORD HKLM "${UNINST_KEY}" "NoRepair" 1
    WriteRegDWORD HKLM "${UNINST_KEY}" "EstimatedSize" 51200
  !endif

  ; The app's own state directory: the engine creates it on first run. Tell the
  ; user where the audit trail lives, because that is the product's evidence.
  DetailPrint "State and audit trail: %PROGRAMDATA%\MICS (helper) and %LOCALAPPDATA%\MICS (this user)"
SectionEnd

Section "Uninstall"
  SetShellVarContext ${SHELL_CONTEXT}

  nsExec::ExecToLog 'taskkill /IM ${APP_EXE} /F'
  Pop $0
  Sleep 400

  ; The helper service is installed by the app, not by this script: removing it
  ; needs its own elevation and is folded in with ب4. Say so instead of leaving
  ; a service behind silently.
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
  DeleteRegKey HKCU "${UNINST_KEY}"
  !ifndef TESTUSER
    DeleteRegKey HKLM "${UNINST_KEY}"
  !endif

  DetailPrint "If the privileged helper was installed, remove it from the app (Settings -> Engine) before uninstalling."
SectionEnd
