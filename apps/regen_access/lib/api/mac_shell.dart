import 'package:flutter/services.dart';
import 'access_client.dart';
import 'windows_shell.dart';

class MacShell extends WindowsShell {
  MacShell(this.client);
  final AccessClient client;
  static const _channel = MethodChannel('regen_access/shell');

  Future<bool> safeExit() async {
    try {
      await client.disconnect();
      final status = await client.status();
      return status.state == 'idle' && !status.needsRestore;
    } catch (_) {
      return false;
    }
  }

  @override
  void attach(Future<void> Function(String) action, {void Function(bool)? navigate}) {
    _channel.setMethodCallHandler((call) async {
      if (call.method == 'safeExit') return safeExit();
      if (call.method == 'action' && const ['connect', 'disconnect', 'restore'].contains(call.arguments)) {
        await action(call.arguments as String);
      }
      if (call.method == 'home') navigate?.call(false);
      if (call.method == 'details') navigate?.call(true);
      return null;
    });
  }
}
