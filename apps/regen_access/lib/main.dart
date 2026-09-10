import 'package:flutter/material.dart';

import 'dart:io';

import 'api/access_client.dart';
import 'api/windows_shell.dart';
import 'api/mac_shell.dart';

import 'app.dart';
export 'app.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  final client = createAccessClient(Platform.operatingSystem);
  runApp(
    MyApp(
      client: client,
      shell: Platform.isWindows ? WindowsShell() : Platform.isMacOS ? MacShell(client) : null,
    ),
  );
}
