import 'dart:convert';
import 'dart:math';

import 'package:flutter/services.dart';

import '../model/status.dart';

abstract interface class AccessClient {
  Future<Status> status();

  /// Completes on a response, definite pre-dispatch failure, or typed transport
  /// uncertainty. The latter must not permit another lifecycle in this session.
  Future<void> connect();

  /// Same completion/uncertainty contract as [connect].
  Future<void> disconnect();
  Future<List<ProbeResult>> probe();
}

/// No working local transport is available on this platform.
class UnavailableAccessClient implements AccessClient {
  const UnavailableAccessClient();
  @override
  Future<Status> status() => Future.error(StateError('service unavailable'));
  @override
  Future<void> connect() => Future.error(StateError('service unavailable'));
  @override
  Future<void> disconnect() => Future.error(StateError('service unavailable'));
  @override
  Future<List<ProbeResult>> probe() =>
      Future.error(StateError('service unavailable'));
}

class OperationUncertainException implements Exception {
  const OperationUncertainException();
  @override
  String toString() => 'Operation outcome is unconfirmed';
}

/// Only the native runner can choose the pipe. There is no path/command API.
class WindowsAccessClient implements AccessClient {
  static const _channel = MethodChannel('regen_access/access');
  final _random = Random.secure();
  bool _lifecycle = false, _uncertain = false;

  Future<Status> _request(String action) async {
    final lifecycle = action == 'connect' || action == 'disconnect';
    if (lifecycle && _uncertain) throw const OperationUncertainException();
    if (lifecycle && _lifecycle) throw StateError('Operation pending');
    if (lifecycle) _lifecycle = true;
    final id = List.generate(
      16,
      (_) => _random.nextInt(256).toRadixString(16).padLeft(2, '0'),
    ).join();
    try {
      final frame = await _channel.invokeMethod<String>('request', {
        'id': id,
        'action': action,
      });
      if (frame == null ||
          utf8.encode(frame).length > 65536 ||
          !frame.endsWith('\n') ||
          frame.indexOf('\n') != frame.length - 1) {
        throw const FormatException('Invalid API frame');
      }
      final json = jsonDecode(frame);
      if (json is! Map<String, dynamic> ||
          json['id'] != id ||
          json['version'] != 1) {
        throw const FormatException('Invalid API identity');
      }
      final value = Status.fromResponse(json);
      final error = json['error_code'] ?? '';
      if (error is! String ||
          !const [
            '',
            'probe_unavailable',
            'permission_denied',
            'diagnostic_unavailable',
          ].contains(error)) {
        throw const FormatException('Invalid API error');
      }
      if (error != '') throw PlatformException(code: 'request_rejected');
      // A correlated reply may still describe a transition joined by another
      // client. It does not authorize overlapping operations in this GUI.
      if (lifecycle && value.transitioning) {
        throw const OperationUncertainException();
      }
      return value;
    } catch (error) {
      if (lifecycle &&
          !(error is PlatformException &&
              const [
                'pre_dispatch',
                'request_rejected',
                'busy',
              ].contains(error.code))) {
        _uncertain = true;
        throw const OperationUncertainException();
      }
      rethrow;
    } finally {
      if (lifecycle) _lifecycle = false;
    }
  }

  @override
  Future<Status> status() => _request('status');
  @override
  Future<void> connect() async {
    await _request('connect');
  }

  @override
  Future<void> disconnect() async {
    await _request('disconnect');
  }

  @override
  Future<List<ProbeResult>> probe() async => (await _request('probe')).results;
}
