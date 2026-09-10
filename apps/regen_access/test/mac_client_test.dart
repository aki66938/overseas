import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:regen_access/api/access_client.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('regen_access/access');
  final messenger = TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
  tearDown(() => messenger.setMockMethodCallHandler(channel, null));
  test('platform selection keeps Windows and enables Mac', () {
    expect(createAccessClient('windows'), isA<WindowsAccessClient>());
    expect(createAccessClient('macos'), isA<MacAccessClient>());
    expect(createAccessClient('linux'), isA<UnavailableAccessClient>());
  });
  test('Mac mutation remains blocked after uncertain dispatch', () async {
    var calls = 0;
    messenger.setMockMethodCallHandler(channel, (call) async {
      calls++;
      throw PlatformException(code: 'uncertain');
    });
    final client = MacAccessClient();
    await expectLater(client.connect(), throwsA(isA<OperationUncertainException>()));
    await expectLater(client.disconnect(), throwsA(isA<OperationUncertainException>()));
    expect(calls, 1);
  });
}
