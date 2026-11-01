// A blocking JSON-RPC client for the engine's named pipe.
//
// The app uses the same transport through `lib/core/ipc/pipe_client.dart`, and
// `tool/pipe_probe.dart` proved the FFI calls work from Dart. What this file
// adds for the contract harness is a **deadline**: every read polls
// `PeekNamedPipe` first instead of blocking inside `ReadFile`, so a handler that
// never answers fails a case instead of hanging CI. That is the same class of
// bug the product's own ping/heartbeat exists to catch.

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
final _createFileW = _kernel32
    .lookupFunction<_CreateFileWNative, _CreateFileWDart>('CreateFileW');

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

typedef _PeekNamedPipeNative = Int32 Function(
    IntPtr, Pointer<Uint8>, Uint32, Pointer<Uint32>, Pointer<Uint32>,
    Pointer<Uint32>);
typedef _PeekNamedPipeDart = int Function(
    int, Pointer<Uint8>, int, Pointer<Uint32>, Pointer<Uint32>,
    Pointer<Uint32>);
final _peekNamedPipe = _kernel32
    .lookupFunction<_PeekNamedPipeNative, _PeekNamedPipeDart>('PeekNamedPipe');

typedef _CloseHandleNative = Int32 Function(IntPtr);
typedef _CloseHandleDart = int Function(int);
final _closeHandle =
    _kernel32.lookupFunction<_CloseHandleNative, _CloseHandleDart>('CloseHandle');

final _getLastError =
    _kernel32.lookupFunction<Uint32 Function(), int Function()>('GetLastError');

/// One JSON-RPC answer: either a result or an error, never both.
class RpcReply {
  const RpcReply.ok(this.result)
      : code = null,
        message = null,
        timedOut = false,
        gone = false;
  const RpcReply.error(this.code, this.message)
      : result = null,
        timedOut = false,
        gone = false;
  const RpcReply.timeout({this.gone = false})
      : result = null,
        code = null,
        message = 'no answer before the deadline',
        timedOut = true;

  final dynamic result;
  final int? code;
  final String? message;
  final bool timedOut;

  /// The engine closed its end of the pipe: "no answer" means "the process is
  /// gone", which is a different bug from "the handler is stuck".
  final bool gone;

  bool get ok => !timedOut && code == null;

  String get short {
    if (gone) return 'pipe closed by the engine';
    if (timedOut) return 'timeout';
    if (!ok) return 'error ${code ?? '?'}: $message';
    final text = jsonEncode(result);
    return text.length <= 90 ? text : '${text.substring(0, 90)}...';
  }
}

class PipeClient {
  PipeClient._(this._handle);

  final int _handle;
  final List<int> _buffer = [];
  int _nextId = 1;
  bool _closed = false;
  bool _peerGone = false;

  /// Opens `\\.\pipe\<name>`, retrying while the engine finishes starting.
  static PipeClient connect(String pipeName,
      {Duration timeout = const Duration(seconds: 30)}) {
    final path = r'\\.\pipe\' + pipeName;
    final deadline = DateTime.now().add(timeout);
    var lastError = 0;
    while (true) {
      final name = path.toNativeUtf16();
      final handle = _createFileW(
          name, _genericRead | _genericWrite, 0, 0, _openExisting, 0, 0);
      lastError = _getLastError();
      malloc.free(name);
      if (handle != -1 && handle != 0) return PipeClient._(handle);
      if (DateTime.now().isAfter(deadline)) {
        throw StateError(
            'cannot open $path after ${timeout.inSeconds}s (Win32 error $lastError)');
      }
      sleep(const Duration(milliseconds: 200));
    }
  }

  /// Sends one request and waits for the reply bearing its id.
  ///
  /// The wait is **asynchronous** on purpose. A blocking `sleep` here would stop
  /// the isolate's event loop, and with it the listeners draining the engine's
  /// stdio: the engine logs every request to stderr (`Processing request: ...`)
  /// synchronously, so a full stderr pipe parks the thread that is trying to log
  /// — measured as "the engine stopped reading the pipe" after a few chatty
  /// calls, with the process still alive. Yielding between polls keeps the drain
  /// alive and makes the client's deadline mean what it says.
  Future<RpcReply> call(String method,
      {Object? params, Duration timeout = const Duration(seconds: 30)}) async {
    if (_closed) throw StateError('pipe already closed');
    final id = _nextId++;
    final body = <String, dynamic>{
      'jsonrpc': '2.0',
      'id': id,
      'method': method,
    };
    if (params != null) body['params'] = params;
    _send(jsonEncode(body));

    final deadline = DateTime.now().add(timeout);
    while (true) {
      final line = await _readLine(deadline);
      if (line == null) return RpcReply.timeout(gone: _peerGone);
      dynamic decoded;
      try {
        decoded = jsonDecode(line);
      } catch (_) {
        continue;
      }
      if (decoded is! Map) continue;
      // Progress and event notifications share the pipe; they have no id.
      if (decoded['id'] != id) continue;
      final error = decoded['error'];
      if (error is Map) {
        final code = (error['code'] as num?)?.toInt();
        return RpcReply.error(code, '${error['message']}');
      }
      return RpcReply.ok(decoded['result']);
    }
  }

  void close() {
    if (_closed) return;
    _closed = true;
    _closeHandle(_handle);
  }

  /// Reads whatever is already on the wire, without waiting for a reply.
  ///
  /// A missed response must not poison the calls after it: the stale line would
  /// be skipped by the next `call` (its id does not match) and every later call
  /// would time out in turn. Draining turns that cascade into one honest
  /// failure plus the evidence that was stuck behind it.
  Future<List<String>> drain(
      {Duration wait = const Duration(milliseconds: 300)}) async {
    final lines = <String>[];
    final deadline = DateTime.now().add(wait);
    while (true) {
      final line = await _readLine(deadline);
      if (line == null) break;
      lines.add(line);
      if (lines.length >= 50) break;
    }
    return lines;
  }

  void _send(String line) {
    final bytes = utf8.encode('$line\n');
    final buffer = malloc<Uint8>(bytes.length);
    final written = malloc<Uint32>();
    try {
      buffer.asTypedList(bytes.length).setAll(0, bytes);
      final ok = _writeFile(_handle, buffer, bytes.length, written, 0);
      if (ok == 0) {
        throw StateError('WriteFile failed (Win32 error ${_getLastError()})');
      }
      if (written.value != bytes.length) {
        throw StateError('short write: ${written.value}/${bytes.length}');
      }
    } finally {
      malloc.free(buffer);
      malloc.free(written);
    }
  }

  /// Returns the next complete line, or null when the deadline passes or the
  /// other end closed. Never blocks indefinitely: the product's own failure mode
  /// under a hung handler is exactly this.
  Future<String?> _readLine(DateTime deadline) async {
    final chunk = malloc<Uint8>(8192);
    final read = malloc<Uint32>();
    final available = malloc<Uint32>();
    final left = malloc<Uint32>();
    try {
      while (true) {
        final end = _buffer.indexOf(10);
        if (end >= 0) {
          final line =
              utf8.decode(_buffer.sublist(0, end), allowMalformed: true).trim();
          _buffer.removeRange(0, end + 1);
          if (line.isNotEmpty) return line;
          continue;
        }
        if (DateTime.now().isAfter(deadline)) return null;
        final peek = _peekNamedPipe(_handle, nullptr, 0, nullptr, available, left);
        if (peek == 0) {
          _peerGone = true; // broken pipe: the engine died
          return null;
        }
        if (available.value > 0) {
          final ok = _readFile(_handle, chunk, 8192, read, 0);
          if (ok == 0 || read.value == 0) {
            _peerGone = true;
            return null;
          }
          _buffer.addAll(chunk.asTypedList(read.value));
        } else {
          await Future<void>.delayed(const Duration(milliseconds: 5));
        }
      }
    } finally {
      malloc.free(chunk);
      malloc.free(read);
      malloc.free(available);
      malloc.free(left);
    }
  }
}