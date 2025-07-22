import 'dart:ffi';
import 'dart:io';

import 'generated_bindings.g.dart';

DnssecProver get lib =>_lib ??= DnssecProver(_getDynamicLibrary());
DnssecProver? _lib;

const _libName = 'dnssec_proof';

DynamicLibrary _getDynamicLibrary() {
  if (Platform.isMacOS || Platform.isIOS) {
    return DynamicLibrary.open('$_libName.framework/$_libName');
  }
  if (Platform.isAndroid || Platform.isLinux) {
    return DynamicLibrary.open('lib$_libName.so');
  }
  if (Platform.isWindows) {
    return DynamicLibrary.open('$_libName.dll');
  }
  throw UnsupportedError('Unsupported platform: ${Platform.operatingSystem}');
}