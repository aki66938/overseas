import 'package:flutter/services.dart';

import '../model/tray_state.dart';

class WindowsShell {
  static const _channel = MethodChannel('regen_access/shell');
  void attach(Future<void> Function() action, {void Function(bool)? navigate}) {
    _channel.setMethodCallHandler((call) async {
      if (call.method == 'action') await action();
      if (call.method == 'home') navigate?.call(false);
      if (call.method == 'details') navigate?.call(true);
    });
  }

  Future<void> update(TrayState state) async {
    try {
      await _channel.invokeMethod<void>('update', state.toMap());
    } on PlatformException {
      // A missing tray must never change service state or expose diagnostics.
    } on MissingPluginException {
      // Allows unsupported hosts to retain the unavailable fallback.
    }
  }

  void dispose() => _channel.setMethodCallHandler(null);
}
