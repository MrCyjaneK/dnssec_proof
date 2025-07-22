import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:dnssec_proof/ffi.dart';

class DnsProver {
  static Uint8List getTxtProof(String queryName,
      [String socketAddr = "8.8.8.8:53"]) {
    final sockaddrPtr = socketAddr.toNativeUtf8();
    final queryNamePtr = queryName.toNativeUtf8();
    final length = malloc<Int>();
    final errorMsgPtr = calloc<Pointer<Char>>();

    final proof = lib.get_txt_proof(
      sockaddrPtr.cast(),
      queryNamePtr.cast(),
      length,
      errorMsgPtr.cast(),
    );

    if (errorMsgPtr.value.address != 0) {
      final errorMsg = errorMsgPtr.value.cast<Utf8>().toDartString();
      lib.free_error_string(errorMsgPtr.value);
      throw Exception(errorMsg);
    }

    final result = proof.cast<Uint8>().asTypedList(length.value);

    malloc.free(sockaddrPtr);
    malloc.free(queryNamePtr);
    malloc.free(length);

    return result;
  }
}
