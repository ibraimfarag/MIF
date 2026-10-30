<#
.SYNOPSIS
  Defines the MicsAumid helper: read/write a shortcut's System.AppUserModel.ID.

.DESCRIPTION
  Dot-source this file; it defines one type and does nothing else:

    . (Join-Path $PSScriptRoot "aumid-interop.ps1")

  Why it exists: System.AppUserModel.ID is a Shell property, and WScript.Shell
  (which scripts\create-shortcuts.ps1 uses to write TargetPath and IconLocation)
  cannot set it. The documented way is IPropertyStore, so the interop lives here
  in one place instead of being copied into the writer and the reader - the two
  must agree on the property key or a "registered" AUMID reads back empty.

  The type guard makes dot-sourcing twice (or alongside the other script in one
  session) harmless.

.NOTES
  ASCII only on purpose (docs/TODO.md 8.9). Windows PowerShell 5.1 compiles this
  with the C# 5 compiler, so nothing newer than that belongs in here.
#>
if ("MicsAumid" -as [type]) { return }

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

// System.AppUserModel.ID is a Shell property, not a WScript field, so it is read
// and written through IPropertyStore.
public static class MicsAumid {
  const uint GPS_READWRITE = 2;
  const ushort VT_EMPTY = 0;
  const ushort VT_LPWSTR = 31;

  [StructLayout(LayoutKind.Sequential, Pack = 4)]
  struct PropertyKey {
    public Guid fmtid;
    public uint pid;
  }

  [StructLayout(LayoutKind.Sequential)]
  struct PropVariant {
    public ushort vt;
    public ushort r1;
    public ushort r2;
    public ushort r3;
    public IntPtr value;
    public IntPtr pad;
  }

  [ComImport]
  [Guid("886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99")]
  [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  interface IPropertyStore {
    void GetCount(out uint count);
    void GetAt(uint index, out PropertyKey key);
    void GetValue(ref PropertyKey key, out PropVariant value);
    void SetValue(ref PropertyKey key, ref PropVariant value);
    void Commit();
  }

  [DllImport("shell32.dll", CharSet = CharSet.Unicode, PreserveSig = false)]
  static extern void SHGetPropertyStoreFromParsingName(
      string path, IntPtr bindContext, uint flags, ref Guid iid,
      [MarshalAs(UnmanagedType.Interface)] out IPropertyStore store);

  [DllImport("ole32.dll")]
  static extern int PropVariantClear(ref PropVariant pv);

  static PropertyKey IdKey() {
    PropertyKey key;
    key.fmtid = new Guid("9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3"); // PKEY_AppUserModel_ID
    key.pid = 5;
    return key;
  }

  static IPropertyStore Open(string path, uint flags) {
    Guid iid = new Guid("886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99");
    IPropertyStore store;
    SHGetPropertyStoreFromParsingName(path, IntPtr.Zero, flags, ref iid, out store);
    return store;
  }

  /// The shortcut's AUMID, or "" when it carries none.
  public static string Read(string shortcutPath) {
    IPropertyStore store = Open(shortcutPath, 0);
    try {
      PropertyKey key = IdKey();
      PropVariant pv;
      store.GetValue(ref key, out pv);
      try {
        if (pv.vt != VT_LPWSTR) return "";
        return Marshal.PtrToStringUni(pv.value) ?? "";
      } finally {
        PropVariantClear(ref pv);
      }
    } finally {
      Marshal.ReleaseComObject(store);
    }
  }

  /// Tags the shortcut with the AUMID; writing the same value twice is a no-op.
  ///
  /// The PROPVARIANT is built by hand because InitPropVariantFromString is not
  /// exported by name on this Windows build (EntryPointNotFoundException), and a
  /// VT_LPWSTR string is the whole value anyway. SetValue copies it into the
  /// store when Commit runs, so the buffer can go immediately after.
  public static void Write(string shortcutPath, string aumid) {
    IPropertyStore store = Open(shortcutPath, GPS_READWRITE);
    IntPtr text = IntPtr.Zero;
    try {
      PropertyKey key = IdKey();
      text = Marshal.StringToCoTaskMemUni(aumid);
      PropVariant pv = new PropVariant();
      pv.vt = VT_LPWSTR;
      pv.value = text;
      store.SetValue(ref key, ref pv);
      store.Commit();
    } finally {
      if (text != IntPtr.Zero) Marshal.FreeCoTaskMem(text);
      Marshal.ReleaseComObject(store);
    }
  }

  /// Drops the tag: VT_EMPTY is how IPropertyStore deletes a value.
  public static void Clear(string shortcutPath) {
    IPropertyStore store = Open(shortcutPath, GPS_READWRITE);
    try {
      PropertyKey key = IdKey();
      PropVariant empty = new PropVariant();
      empty.vt = VT_EMPTY;
      store.SetValue(ref key, ref empty);
      store.Commit();
    } finally {
      Marshal.ReleaseComObject(store);
    }
  }
}
'@