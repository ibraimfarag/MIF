import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:logging/logging.dart';

class IpcRequest {
  final String method;
  final Map<String, dynamic>? params;
  final int id;

  IpcRequest({required this.method, this.params, required this.id});

  Map<String, dynamic> toJson() => {
    'jsonrpc': '2.0',
    'method': method,
    'params': params,
    'id': id,
  };
}

class IpcResponse {
  final dynamic result;
  final dynamic error;
  final int id;

  IpcResponse({this.result, this.error, required this.id});

  factory IpcResponse.fromJson(Map<String, dynamic> json) {
    return IpcResponse(
      result: json['result'],
      error: json['error'],
      id: json['id'] as int,
    );
  }
}

class IpcClient {
  final String _pipePath = r'\\.\pipe\mics_engine';
  Socket? _socket;
  final _controller = StreamController<IpcResponse>.broadcast();

  Stream<IpcResponse> get eventStream => _controller.stream;

  Future<void> connect() async {
    try {
      _socket = await Socket.connect(_pipePath, 0);
      _listen();
    } catch (e) {
      throw Exception('Failed to connect to MI CS Engine: $e');
    }
  }

  void _listen() {
    _socket?.listen(
      (List<int> data) {
        final decoded = utf8.decode(data);
        final lines = decoded.split('\n');
        for (var line in lines) {
          if (line.trim().isEmpty) continue;
          try {
            final json = jsonDecode(line);
            _controller.add(IpcResponse.fromJson(json));
          } catch (e) {
            // Log error
          }
        }
      },
      onError: (e) => _handleDisconnect(),
      onDone: () => _handleDisconnect(),
    );
  }

  Future<IpcResponse> send(IpcRequest request) async {
    if (_socket == null) throw Exception('Not connected to engine');

    final encoded = jsonEncode(request.toJson()) + '\n';
    _socket!.write(encoded);

    // In a real implementation, we would match the ID from the stream
    // For now, we'll wait for the next response for simplicity in v1
    return await _controller.stream.first;
  }

  void _handleDisconnect() {
    _socket = null;
    // Implement reconnect logic here
  }

  void dispose() {
    _socket?.destroy();
    _controller.close();
  }
}

final ipcClientProvider = Provider<IpcClient>((ref) {
  return IpcClient();
});
