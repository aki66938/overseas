import 'package:flutter_test/flutter_test.dart';
import 'package:regen_access/api/access_client.dart';
import 'package:regen_access/api/mac_shell.dart';
import 'package:regen_access/model/status.dart';

class Client implements AccessClient {
  bool disconnected = false;
  String state = 'idle';
  String errorCode = '';
  bool failDisconnect = false;
  bool failStatus = false;
  @override Future<void> disconnect() async {
    if (failDisconnect) throw StateError('disconnect failed');
    disconnected = true;
  }
  @override Future<Status> status() async {
    if (failStatus) throw StateError('status failed');
    return Status(state: state, errorCode: errorCode);
  }
  @override Future<void> connect() async {}
  @override Future<List<ProbeResult>> probe() async => [];
}
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  test('safe exit waits for disconnect and confirmed idle', () async {
    final client = Client();
    final shell = MacShell(client);
    expect(await shell.safeExit(), isTrue);
    expect(client.disconnected, isTrue);
    client.state = 'needs_action';
    expect(await shell.safeExit(), isFalse);
  });
  test('idle with incomplete restore cannot exit', () async {
    final client = Client()..errorCode = 'restore_failed';
    expect(await MacShell(client).safeExit(), isFalse);
  });
  test('connected cannot exit', () async {
    final client = Client()..state = 'connected';
    expect(await MacShell(client).safeExit(), isFalse);
  });
  test('disconnect error cannot exit', () async {
    final client = Client()..failDisconnect = true;
    expect(await MacShell(client).safeExit(), isFalse);
  });
  test('status error cannot exit', () async {
    final client = Client()..failStatus = true;
    expect(await MacShell(client).safeExit(), isFalse);
  });
}
