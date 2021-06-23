import 'package:dargon2/dargon2.dart';
import 'package:cryptography/cryptography.dart';
import 'package:convert/convert.dart';
import 'dart:convert';

final s = Salt.newSalt();

Future<List<int>> longEncrypt(psw) async {

  final pbkdf2 = Pbkdf2(
    macAlgorithm: Hmac.sha256(),
    iterations: 100000,
    bits: 128,
  );

  // Password we want to hash
  final secretKey = SecretKey(psw.codeUnits); //SecretKey([1,2,3]);

  // A random salt
  final nonce = [4,5,6];

  // Calculate a hash that can be stored in the database
  final newSecretKey = await pbkdf2.deriveKey(
    secretKey: secretKey,
    nonce: nonce,
  );
  final List<int> list = await newSecretKey.extractBytes();
  return list;
}

encrypt(psw) async {
  List<int> encrypted = await longEncrypt(psw);
  return new String.fromCharCodes(encrypted);
}

Future<bool> verify(psw1, psw2, hashed) async {
  print("[VERIFY] $psw1\t$psw2");
  psw1 = await encrypt(psw1);
  try {
   await argon2.verifyHashString(psw1, hashed);
   return true;
   } on Exception {
    return false;
   }
}

Future<String> hash(psw) async {
  print("[HASH] plainPassword: $psw");
  psw = await encrypt(psw);
  var result = await argon2.hashPasswordString(psw, salt: s);
  String hashed = result.encodedString;
  print("[HASH] hashedPassword: $hashed");
  return hashed;
}

main() async {
  String psw1 = "pass1234";
  String psw2 = "1234pass";
  String hash1 = await hash(psw1);
  String hash2 = await hash(psw2);
  bool first = await verify(psw1, psw2, hash2);
  print("[VERIFY] $first");
  bool second = await verify(psw1, psw1, hash1);
  print("[VERIFY] $second");
}
