import 'dart:convert';
import 'dart:typed_data';

import 'package:dnssec_proof/generated_bindings.g.dart';
import 'package:flutter/material.dart';
import 'dart:async';

import 'package:dnssec_proof/dnssec_proof.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatefulWidget {
  const MyApp({super.key});

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  Uint8List proofData = Uint8List(0);

  @override
  void initState() {
    super.initState();

    final queryName = "tips.user._bitcoin-payment.konsti.cloud.";
    final data = DnsProver.getTxtProof(queryName);

    setState(() {
      proofData = data;
    });
  }

  @override
  Widget build(BuildContext context) {
    const textStyle = TextStyle(fontSize: 25);
    const spacerSmall = SizedBox(height: 10);
    final proofDataString = base64.encode(proofData);
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('Native Packages'),
        ),
        body: SingleChildScrollView(
          child: Container(
            padding: const EdgeInsets.all(10),
            child: Column(
              children: [
                const Text(
                  'This calls a native function through FFI that is shipped as source in the package. '
                  'The native code is built as part of the Flutter Runner build.',
                  style: textStyle,
                  textAlign: TextAlign.center,
                ),
                spacerSmall,
                SelectableText(
                  'proof = $proofDataString',
                  style: textStyle,
                  textAlign: TextAlign.center,
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
