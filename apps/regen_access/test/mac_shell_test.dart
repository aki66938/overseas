import 'package:flutter_test/flutter_test.dart';
import 'package:regen_access/api/access_client.dart';
import 'package:regen_access/api/mac_shell.dart';
import 'package:regen_access/model/status.dart';

class Client implements AccessClient {
  bool disconnected = false;
  String state = 'idle';
  @override Future<void> disconnect() async { disconnected = true; }
  @override Future<Status> status() async => Status(state: state);
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
}
