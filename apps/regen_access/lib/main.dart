import 'package:flutter/material.dart';

import 'dart:io';

import 'api/access_client.dart';
import 'api/windows_shell.dart';

import 'app.dart';
export 'app.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(
    MyApp(
      client: Platform.isWindows
          ? WindowsAccessClient()
          : const UnavailableAccessClient(),
      shell: Platform.isWindows ? WindowsShell() : null,
    ),
  );
}
