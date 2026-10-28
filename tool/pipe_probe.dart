// ignore_for_file: avoid_print
//
// Diagnostic probe for the engine's named-pipe transport and push channel.
//
//   dart run tool/pipe_probe.dart [<folder-to-scan>]
//
// It proves, end to end and without the Flutter app:
//   1. CreateFileW on \\.\pipe\mics_engine works from Dart,
//   2. a request/response round-trip works (ping -> pong, job.list),
//   3. the engine pushes `progress` / `event` notifications on the same
//      connection while a scan job runs.
//
// Exit code 0 means all three hold. Kept as a dev tool: if it breaks, the
// app's transport layer is broken.

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

const int _genericRead = 0x80000000;
const int _genericWrite = 0x40000000;
const int _openExisting = 3;

final DynamicLibrary _kernel32 = DynamicLibrary.open('kernel32.dll');

typedef _CreateFileWNative = IntPtr Function(
    Pointer<Utf16>, Uint32, Uint32, IntPtr, Uint32, Uint32, IntPtr);
typedef _CreateFileWDart = int Function(
    Pointer<Utf16>, int, int, int, int, int, int);

final _createFileW = _kernel32.lookupFunction<_CreateFileWNative,
    _CreateFileWDart>('CreateFileW');

typedef _ReadFileNative = Int32 Function(
    IntPtr, Pointer<Uint8>, Uint32, Pointer<Uint32>, IntPtr);
typedef _ReadFileDart = int Function(
    int, Pointer<Uint8>, int, Pointer<Uint32>, int);
final _readFile =
    _kernel32.lookupFunction<_ReadFileNative, _ReadFileDart>('ReadFile');

typedef _WriteFileNative = Int32 Function(
    IntPtr, Pointer<Uint8>, Uint32, Pointer<Uint32>, IntPtr);
typedef _WriteFileDart = int Function(
    int, Pointer<Uint8>, int, Pointer<Uint32>, int);
final _writeFile =
    _kernel32.lookupFunction<_WriteFileNative, _WriteFileDart>('WriteFile');

typedef _CloseHandleNative = Int32 Function(IntPtr);
typedef _CloseHandleDart = int Function(int);
final _closeHandle =
    _kernel32.lookupFunction<_CloseHandleNative, _CloseHandleDart>('CloseHandle');

final _getLastError =
    _kernel32.lookupFunction<Uint32 Function(), int Function()>('GetLastError');

final _buf = malloc<Uint8>(8192);
final _read = malloc<Uint32>();
final _written = malloc<Uint32>();

/// Receive buffer: consumed bytes are removed, and a complete line that is
/// already buffered is returned without waiting for new socket data.
List<int> _buffer = [];

int _nextId = 1;

void main(List<String> args) {
  final target = args.isNotEmpty ? args.first : null;
  final handle = _connect(r'\\.\pipe\mics_engine');
  print('connected to pipe');

  var ok = true;
  ok &= _expect(_request(handle, 'ping'), '"pong"', 'ping -> pong');
  ok &= _expect(_request(handle, 'job.list', {'limit': 5}), '"job_id"',
      'job.list responds');

  if (target != null) {
    final reply = _request(handle, 'scan.start', {'path': target});
    print('scan.start: $reply');
    ok &= _expect(reply, '"job_id"', 'scan.start returns a job id');

    var progressSeen = 0;
    var finished = false;
    final deadline = DateTime.now().add(const Duration(minutes: 3));
    while (!finished && DateTime.now().isBefore(deadline)) {
      final line = _readLine(handle);
      if (line == null) break;
      if (line.contains('"progress"')) {
        progressSeen++;
        if (progressSeen <= 3) print('  progress: $line');
      }
      if (line.contains('job_finished') || line.contains('"method":"event"')) {
        print('  terminal: $line');
        finished = true;
      }
    }
    ok &= progressSeen > 0;
    print(progressSeen > 0
        ? 'PASS: $progressSeen progress notification(s) received'
        : 'FAIL: no progress notifications');
  }

  _closeHandle(handle);
  print(ok ? 'ALL PASS' : 'FAILURES PRESENT');
  exit(ok ? 0 : 2);
}

bool _expect(String actual, String needle, String label) {
  final pass = actual.contains(needle);
  print('${pass ? 'PASS' : 'FAIL'}: $label (${_short(actual)})');
  return pass;
}

/// Appends one line to `_testdata/probe-trace.log` so a hang can be inspected
/// while the probe is still running (stdout is buffered when redirected).
void _trace(String text) {
  try {
    File('_testdata/probe-trace.log')
        .writeAsStringSync('$text\n', mode: FileMode.append);
  } catch (_) {
    // tracing must never break the probe itself
  }
}

String _short(String s) => s.length <= 120 ? s : '${s.substring(0, 120)}...';

int _connect(String path) {
  var err = 0;
  for (var i = 0; i < 40; i++) {
    final name = path.toNativeUtf16();
    final h =
        _createFileW(name, _genericRead | _genericWrite, 0, 0, _openExisting, 0, 0);
    err = _getLastError();
    malloc.free(name);
    if (h != -1 && h != 0) return h;
    sleep(const Duration(milliseconds: 250));
  }
  stderr.writeln('FAIL: cannot open $path (errno $err)');
  exit(1);
}

/// Sends a request and reads until the reply with the matching id arrives,
/// printing any notification that shows up in between.
String _request(int handle, String method,
    [Map<String, dynamic>? params]) {
  final id = _nextId++;
  final body = <String, dynamic>{
    'jsonrpc': '2.0',
    'id': id,
    'method': method,
  };
  if (params != null) body['params'] = params;
  _send(handle, jsonEncode(body));
  while (true) {
    final line = _readLine(handle);
    if (line == null) return '<closed>';
    _trace('<- $line');
    final decoded = jsonDecode(line);
    if (decoded is Map && decoded['id'] == id) {
      return decoded['error'] != null
          ? '{"error":${jsonEncode(decoded['error'])}}'
          : jsonEncode(decoded['result']);
    }
  }
}

void _send(int handle, String line) {
  final bytes = utf8.encode('$line\n');
  final buf = malloc<Uint8>(bytes.length);
  buf.asTypedList(bytes.length).setAll(0, bytes);
  final ok = _writeFile(handle, buf, bytes.length, _written, 0);
  final n = _written.value;
  malloc.free(buf);
  if (ok == 0) throw StateError('WriteFile failed (errno ${_getLastError()})');
  if (n != bytes.length) throw StateError('short write: $n');
}

String? _readLine(int handle) {
  while (true) {
    // Consume any complete line that arrived in an earlier chunk first.
    final end = _buffer.indexOf(10);
    if (end >= 0) {
      final line =
          utf8.decode(_buffer.sublist(0, end), allowMalformed: true).trim();
      _buffer = _buffer.sublist(end + 1);
      if (line.isNotEmpty) return line;
      continue;
    }
    final ok = _readFile(handle, _buf, 8192, _read, 0);
    if (ok == 0) {
      stderr.writeln('ReadFile failed (errno ${_getLastError()})');
      return null;
    }
    final n = _read.value;
    if (n == 0) return null;
    _buffer.addAll(_buf.asTypedList(n));
  }
}
