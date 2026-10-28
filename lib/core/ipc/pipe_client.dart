// Named-pipe client for the MI CS engine (Windows).
//
// Why this is not `Process.start` + stdio:
//  * the engine is a single long-lived process (one instance per machine), so
//    the UI must be able to attach to an engine that is already running —
//    started by autostart, or left behind by a previous app session;
//  * closing the UI must not kill the engine or lose an in-flight scan;
//  * the engine pushes `progress` / `event` notifications on the same channel.
//
// Dart has no named-pipe API in `dart:io`, so the handle is opened with
// `CreateFileW` and read/written from two dedicated isolates:
//   - the reader isolate blocks in `ReadFile` and forwards complete lines;
//   - the writer isolate receives strings and blocks in `WriteFile`.
// Two isolates are required: a blocking `ReadFile` would otherwise stop the
// same isolate from ever handling a write.
//
// Framing: UTF-8, one JSON document per line (spec section 5).

import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:isolate';

import 'package:ffi/ffi.dart';

const int _genericRead = 0x80000000;
const int _genericWrite = 0x40000000;
const int _openExisting = 3;

/// `ERROR_FILE_NOT_FOUND` / `ERROR_PIPE_BUSY` are retried; the rest are fatal.
const int _errorFileNotFound = 2;
const int _errorAccessDenied = 5;
const int _errorPipeBusy = 231;

class PipeConnection {
  PipeConnection._(this._handle, this.path);

  final int _handle;
  final String path;

  static const String defaultPath = r'\\.\pipe\mics_engine';

  /// `MICS_PIPE_NAME` isolates a test/dev engine from the real one.
  static String get resolvedPath =>
      Platform.environment['MICS_PIPE_NAME'] ?? defaultPath;

  final _lines = StreamController<String>.broadcast();
  final _closed = StreamController<String>.broadcast();
  SendPort? _writerPort;
  Isolate? _reader;
  Isolate? _writer;
  final _inbox = ReceivePort();
  bool _disposed = false;

  /// Complete JSON lines received from the engine.
  Stream<String> get lines => _lines.stream;

  /// Fires once when the connection drops (payload: reason).
  Stream<String> get onClosed => _closed.stream;

  /// Tries to connect, retrying briefly while the engine is still starting.
  ///
  /// Returns `null` when nothing is listening on the pipe.
  static Future<PipeConnection?> tryConnect({
    String? path,
    Duration timeout = const Duration(milliseconds: 1500),
  }) async {
    final target = path ?? resolvedPath;
    final deadline = DateTime.now().add(timeout);
    var lastError = 0;
    do {
      final handle = _openPipe(target, (e) => lastError = e);
      if (handle != null) {
        final conn = PipeConnection._(handle, target);
        if (await conn._start()) return conn;
        conn.close();
        return null;
      }
      await Future<void>.delayed(const Duration(milliseconds: 120));
    } while (DateTime.now().isBefore(deadline));
    // Keep the last error visible to callers through the returned null.
    if (lastError == _errorAccessDenied) {
      stderr.writeln('pipe access denied — sandbox or ACL blocks the pipe');
    }
    return null;
  }

  /// Spawns both isolates and waits until the writer is ready to accept data
  /// (otherwise the first request could be dropped before the handshake).
  Future<bool> _start() async {
    final ready = Completer<bool>();
    _inbox.listen((message) {
      if (message is SendPort) {
        _writerPort = message;
        if (!ready.isCompleted) ready.complete(true);
        return;
      }
      if (message is String) {
        _lines.add(message);
        return;
      }
      if (message is Map && message['closed'] == true) {
        if (!_closed.isClosed) _closed.add('${message['reason'] ?? 'closed'}');
      }
    });

    _reader = await _spawn(_readerMain, [_handle, _inbox.sendPort]);
    _writer = await _spawn(_writerMain, [_handle, _inbox.sendPort]);
    return ready.future.timeout(const Duration(seconds: 2), onTimeout: () => false);
  }

  static Future<Isolate> _spawn(
          void Function(List<Object?>) entry, List<Object?> args) =>
      Isolate.spawn(entry, args, errorsAreFatal: false);

  /// Writes one JSON line. No-op after close.
  void send(String line) {
    _writerPort?.send(line);
  }

  void close() {
    if (_disposed) return;
    _disposed = true;
    _writerPort?.send(null);
    _reader?.kill(priority: Isolate.immediate);
    _writer?.kill(priority: Isolate.immediate);
    _closeHandle(_handle);
    _inbox.close();
    _lines.close();
    _closed.close();
  }
}

// ---------------- Win32 ----------------

int? _openPipe(String path, void Function(int) onError) {
  final kernel32 = DynamicLibrary.open('kernel32.dll');
  final createFileW = kernel32.lookupFunction<
      IntPtr Function(
          Pointer<Utf16>, Uint32, Uint32, IntPtr, Uint32, Uint32, IntPtr),
      int Function(
          Pointer<Utf16>, int, int, int, int, int, int)>('CreateFileW');
  final getLastError =
      kernel32.lookupFunction<Uint32 Function(), int Function()>('GetLastError');

  final name = path.toNativeUtf16();
  final handle =
      createFileW(name, _genericRead | _genericWrite, 0, 0, _openExisting, 0, 0);
  final err = getLastError();
  malloc.free(name);
  if (handle == -1 || handle == 0) {
    onError(err);
    // Not-found and busy are normal while the engine boots; anything else is
    // reported once by tryConnect.
    if (err == _errorFileNotFound || err == _errorPipeBusy) return null;
    return null;
  }
  return handle;
}

final _kernel32 = DynamicLibrary.open('kernel32.dll');
final _closeHandle = _kernel32
    .lookupFunction<Int32 Function(IntPtr), int Function(int)>('CloseHandle');

// ---------------- isolates ----------------

/// Reads UTF-8 lines forever; sends `{closed: true}` when the pipe ends.
///
/// A synchronous pipe handle cannot have a blocking `ReadFile` and a
/// `WriteFile` in flight at the same time: the pending read holds the file
/// object and the write never completes (this is exactly the deadlock the
/// first version hit). So the reader *peeks* first — `PeekNamedPipe` never
/// blocks — and only issues `ReadFile` when bytes are already available, which
/// makes it return immediately and leave the handle free for writes.
void _readerMain(List<Object?> args) {
  final handle = args[0] as int;
  final out = args[1] as SendPort;
  try {
    final kernel32 = DynamicLibrary.open('kernel32.dll');
    final readFile = kernel32.lookupFunction<
        Int32 Function(IntPtr, Pointer<Uint8>, Uint32, Pointer<Uint32>, IntPtr),
        int Function(int, Pointer<Uint8>, int, Pointer<Uint32>, int)>('ReadFile');
    final peekNamedPipe = kernel32.lookupFunction<
        Int32 Function(IntPtr, Pointer<Uint8>, Uint32, Pointer<Uint32>,
            Pointer<Uint32>, Pointer<Uint32>),
        int Function(int, Pointer<Uint8>, int, Pointer<Uint32>, Pointer<Uint32>,
            Pointer<Uint32>)>('PeekNamedPipe');
    final getLastError = kernel32
        .lookupFunction<Uint32 Function(), int Function()>('GetLastError');

    final buf = malloc<Uint8>(8192);
    final read = malloc<Uint32>();
    final available = malloc<Uint32>();
    var pending = <int>[];

    while (true) {
      // Deliver every complete line already buffered before reading again.
      var end = pending.indexOf(10);
      while (end >= 0) {
        final raw = pending.sublist(0, end);
        pending = pending.sublist(end + 1);
        final line = utf8.decode(raw, allowMalformed: true).trim();
        if (line.isNotEmpty) out.send(line);
        end = pending.indexOf(10);
      }

      final peek = peekNamedPipe(
          handle, nullptr, 0, nullptr, available, nullptr);
      if (peek == 0) {
        out.send({'closed': true, 'reason': 'peek-error ${getLastError()}'});
        break;
      }
      final avail = available.value;
      if (avail == 0) {
        // Idle: yield the isolate briefly. 10 ms keeps latency imperceptible
        // for UI notifications while costing ~100 cheap syscalls per second.
        sleep(const Duration(milliseconds: 10));
        continue;
      }
      final want = avail > 8192 ? 8192 : avail;
      final ok = readFile(handle, buf, want, read, 0);
      if (ok == 0) {
        out.send({'closed': true, 'reason': 'read-error ${getLastError()}'});
        break;
      }
      final n = read.value;
      if (n == 0) {
        out.send({'closed': true, 'reason': 'eof'});
        break;
      }
      pending.addAll(buf.asTypedList(n));
    }
    malloc.free(buf);
    malloc.free(read);
    malloc.free(available);
  } catch (e) {
    out.send({'closed': true, 'reason': 'reader-init-error $e'});
  }
}

/// Serializes every outgoing line (one blocking `WriteFile` at a time).
void _writerMain(List<Object?> args) {
  final handle = args[0] as int;
  final toParent = args[1] as SendPort;
  final port = ReceivePort();
  toParent.send(port.sendPort);

  final debug = Platform.environment['MICS_IPC_DEBUG'] != null;
  try {
    final kernel32 = DynamicLibrary.open('kernel32.dll');
    final writeFile = kernel32.lookupFunction<
        Int32 Function(IntPtr, Pointer<Uint8>, Uint32, Pointer<Uint32>, IntPtr),
        int Function(int, Pointer<Uint8>, int, Pointer<Uint32>, int)>(
        'WriteFile');
    final getLastError = kernel32
        .lookupFunction<Uint32 Function(), int Function()>('GetLastError');

    port.listen((message) {
      if (message == null) {
        port.close();
        return;
      }
      if (debug) stderr.writeln('[ipc] writer got: $message');
      final bytes = utf8.encode('${message as String}\n');
      final buf = malloc<Uint8>(bytes.length);
      buf.asTypedList(bytes.length).setAll(0, bytes);
      final written = malloc<Uint32>();
      var offset = 0;
      var failed = 0;
      while (offset < bytes.length) {
        final rest = bytes.length - offset;
        final chunk = buf + offset;
        final ok = writeFile(handle, chunk, rest, written, 0);
        final n = written.value;
        if (debug) {
          stderr.writeln('[ipc] writeFile ok=$ok n=$n err=${getLastError()}');
        }
        if (ok == 0 || n == 0) {
          failed = getLastError();
          break;
        }
        offset += n;
      }
      malloc.free(buf);
      malloc.free(written);
      if (failed != 0) {
        // Surface the failure instead of silently dropping the request.
        toParent.send({'closed': true, 'reason': 'write-error $failed'});
        port.close();
      }
    });
  } catch (e) {
    toParent.send({'closed': true, 'reason': 'writer-init-error $e'});
  }
}
