import Bench "mo:bench";
import Nat "mo:base/Nat";
import Iter "mo:base/Iter";
import Result "mo:base/Result";
import Debug "mo:base/Debug";
import Blob "mo:base/Blob";
import Runtime "mo:new-base/Runtime";
import RSA "../src";

module {

  public func init() : Bench.Bench {

    let message : Blob = "\48\65\6c\6c\6f\2c\20\77\6f\72\6c\64\21"; // "Hello, world!"

    let testPublicKey = RSA.PublicKey(
      0x10001,
      0x00da5e1e10a1642ec7c502137f3bf50676fe5547fcab7b9acfaa5bdab98ab1478263e1e003ef6a752c0092c62bc027af7d4b74a47e183e5538f22b5b2f7258ec285265d12ade24970473b68806a8b0362a8798ef783ec97056efbb2c381fa38282e911a9bbcc26849ccb10ca95999d0b734ad3b13ecbb53b1e79c4e9e4a7332d3e2d0b35a78e1e87ccfd2d7f2c953ae5d5737b975a23f349e7b5658003d2a67d1f29781ae67c18542a000f0e23d13ba064574aacbcaae2bd369b90ee08e9e9fb634d54cd38859d6068a75e316e739978d4039ef3133e75c3da6ac1b2ca759d1712db3958164baa458fdf6bf51753dd36bc795968acda7531bfbf457d908544c159,
    );
    let signature = RSA.Signature(
      0x057bbb5b514e08c0ecc104c8d14d4237bf7f3aaa4375df39436a0394a5b2f366d33f9cff4d4582d858f082409cedf891dcca8952da79762ce4b2f498eec8bbe5d04d0cb9f814a45651497231efe0632a780856f99a39ce745954ab5ba86b7bb15834b11e818c8dfb1d97957e8acfbde1026a334974874d08374ff6f03eb1c5ec6eeec409bca0a3443004b4d6f1126f122cd6672cfd911767fb5b54fb8c3190d4a02f8478ce7aa223ac4ef20f45c08f2d44801efa21a9914f103a82c0eeb00fc7ae34beca20b159f35f7b83877ec044fe786de6aaa8a41be033955dacb90aded1f681226d961c9283ef30eeacddf64974f14ebe08b961b9d57071387dfdb92b7d,
      #pkcs1v1_5,
    );

    // Pre-computed serialized data for parsing benchmarks
    let publicKeyHex = testPublicKey.toText(#hex({ byteEncoding = #pkcs1; format = { isUpper = false; prefix = #none } }));
    let publicKeyBytes = testPublicKey.toBytes(#pkcs1);
    let signatureBytes = signature.toBytes(#raw);

    let bench = Bench.Bench();

    bench.name("RSA Cryptographic Operations Benchmarks");
    bench.description("Benchmark signature verification, key serialization, and parsing operations for RSA");

    bench.rows([
      "verify",
      "publicKey_toBytes",
      "publicKey_fromBytes",
      "signature_toBytes",
      "signature_fromBytes",
      "publicKey_toText",
      "publicKey_fromText",
    ]);

    bench.cols(["1", "10"]);

    bench.runner(
      func(row, col) {
        let ?n = Nat.fromText(col) else Debug.trap("Cols must only contain numbers: " # col);

        // Define the operation to perform based on the row
        let operation = switch (row) {
          case ("verify") func(_ : Nat) : Result.Result<Any, Text> {
            let isValid = testPublicKey.verify(message.vals(), signature, #sha256);
            if (isValid) #ok else #err("Verify failed");
          };
          case ("publicKey_toBytes") func(_ : Nat) : Result.Result<Any, Text> {
            ignore testPublicKey.toBytes(#pkcs1);
            #ok;
          };
          case ("publicKey_fromBytes") func(_ : Nat) : Result.Result<Any, Text> {
            RSA.publicKeyFromBytes(publicKeyBytes.vals(), #pkcs1);
          };
          case ("signature_toBytes") func(_ : Nat) : Result.Result<Any, Text> {
            ignore signature.toBytes(#raw);
            #ok;
          };
          case ("signature_fromBytes") func(_ : Nat) : Result.Result<Any, Text> {
            RSA.signatureFromBytes(signatureBytes.vals(), #raw({ paddingAlgorithm = #pkcs1v1_5 }));
          };
          case ("publicKey_toText") func(_ : Nat) : Result.Result<Any, Text> {
            ignore testPublicKey.toText(#hex({ byteEncoding = #pkcs1; format = { isUpper = false; prefix = #none } }));
            #ok;
          };
          case ("publicKey_fromText") func(_ : Nat) : Result.Result<Any, Text> {
            RSA.publicKeyFromText(publicKeyHex, #hex({ byteEncoding = #pkcs1; format = { prefix = #none } }));
          };
          case (_) Runtime.trap("Unknown row: " # row);
        };

        // Single shared loop with result checking
        for (i in Iter.range(1, n)) {
          switch (operation(i)) {
            case (#ok(_)) ();
            case (#err(e)) Debug.trap(e);
          };
        };
      }
    );

    bench;
  };

};
