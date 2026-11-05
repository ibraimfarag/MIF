/*
    MI CS starter YARA pack (10 rules) — bundled offline intel.
    Generic detection rules for the v1.0 starter set; community packs are
    synced by the feed updater once configured.
*/

rule EICAR_Test_File
{
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Suspicious_Cmd_PowerShell_Download
{
    strings:
        $ps_download = /(powershell|pwsh).{0,40}(DownloadFile|DownloadString|Invoke-WebRequest|IEX|Invoke-Expression)/i nocase
        $url = /https?:\/\/[^ ]*/ nocase
    condition:
        $ps_download and $url
}

rule Suspicious_VBS_Dropper
{
    strings:
        $wscript = "WScript.Shell" nocase
        $run = ".Run" nocase
        $http = /https?:\/\/[^ ]*/ nocase
    condition:
        filesize < 64KB and all of them
}

rule Suspicious_BAT_Certutil_Download
{
    strings:
        $certutil = /certutil.{0,30}-urlcache/i nocase
        $bitsadmin = /bitsadmin.{0,30}\/transfer/i nocase
    condition:
        1 of them
}

rule Suspicious_HTA_Exec
{
    strings:
        $hta = "<HTA" nocase
        $exec = /(WScript\.Shell|ActiveXObject)/ nocase
    condition:
        $hta and $exec
}

rule Tiny_Packed_Pe_Installer
{
    meta:
        description = "Very small PE — classic dropper shape"
    condition:
        uint16(0) == 0x5A4D and filesize < 40KB and
        uint32(0x3C) < filesize and
        uint32(uint32(0x3C)) == 0x00004550
}

rule Double_Extension_Emailer
{
    strings:
        $pdfexe = /\.pdf\.exe\b/
        $docexe = /\.doc\.exe\b/
        $imgexe = /\.(jpe?g|png)\.exe\b/
    condition:
        any of them
}

rule Ransom_Note_Names
{
    strings:
        $readme = /README_(FOR_)?DECRYPT/i
        $howto = /HOW_TO_(FIX|RECOVER|DECRYPT)/i
        $ransom = /your files (have been|are) encrypt/i nocase
    condition:
        any of them
}

rule Suspicious_Scheduled_Task_Creator
{
    strings:
        $schtasks = /schtasks.{0,40}\/create/i nocase
        $hidden = /\/sc\s+(onlogon|onstart)/i nocase
    condition:
        $schtasks and $hidden
}

rule Malicious_Macro_AutoOpen
{
    strings:
        $autoopen = "AutoOpen" nocase
        $shell = "Shell" nocase
        $createobject = "CreateObject" nocase
    condition:
        // 0x4B50 is "PK": uint16(0) reads little-endian, so a zip/OOXML
        // container (50 4B 03 04) is 0x4B50, not 0x504B. The inverted constant
        // this used to carry matched only a file starting with "KP", so the
        // rule could never fire on a real .docm/.docm-family document.
        uint16(0) == 0x4B50 and 2 of them
}
