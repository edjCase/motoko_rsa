import { test } "mo:test";
import Runtime "mo:new-base/Runtime";
import Blob "mo:new-base/Blob";
import PublicKey "../src/PublicKey";
import Signature "../src/Signature";
import BaseX "mo:base-x-encoder";

test(
  "RSA Signature Verification",
  func() {

    type TestCase = {
      key : PublicKey.PublicKey;
      signature : Signature.Signature;
      message : Blob;
      hashAlgorithm : PublicKey.HashAlgorithm;
    };

    // Test cases
    let cases : [TestCase] = [
      {
        key = PublicKey.PublicKey(
          0x10001,
          0x00da5e1e10a1642ec7c502137f3bf50676fe5547fcab7b9acfaa5bdab98ab1478263e1e003ef6a752c0092c62bc027af7d4b74a47e183e5538f22b5b2f7258ec285265d12ade24970473b68806a8b0362a8798ef783ec97056efbb2c381fa38282e911a9bbcc26849ccb10ca95999d0b734ad3b13ecbb53b1e79c4e9e4a7332d3e2d0b35a78e1e87ccfd2d7f2c953ae5d5737b975a23f349e7b5658003d2a67d1f29781ae67c18542a000f0e23d13ba064574aacbcaae2bd369b90ee08e9e9fb634d54cd38859d6068a75e316e739978d4039ef3133e75c3da6ac1b2ca759d1712db3958164baa458fdf6bf51753dd36bc795968acda7531bfbf457d908544c159,
        );
        signature = Signature.Signature(
          0x057bbb5b514e08c0ecc104c8d14d4237bf7f3aaa4375df39436a0394a5b2f366d33f9cff4d4582d858f082409cedf891dcca8952da79762ce4b2f498eec8bbe5d04d0cb9f814a45651497231efe0632a780856f99a39ce745954ab5ba86b7bb15834b11e818c8dfb1d97957e8acfbde1026a334974874d08374ff6f03eb1c5ec6eeec409bca0a3443004b4d6f1126f122cd6672cfd911767fb5b54fb8c3190d4a02f8478ce7aa223ac4ef20f45c08f2d44801efa21a9914f103a82c0eeb00fc7ae34beca20b159f35f7b83877ec044fe786de6aaa8a41be033955dacb90aded1f681226d961c9283ef30eeacddf64974f14ebe08b961b9d57071387dfdb92b7d,
          #pkcs1v1_5,
        );
        message = "\48\65\6c\6c\6f\2c\20\77\6f\72\6c\64\21"; // "Hello, world!"
        hashAlgorithm = #sha256;
      },
      {
        key = PublicKey.PublicKey(
          0x10001,
          0x008a217e244c487ac9ba67b5b87902fb75c576692dd6482ae58b39dd6e8ef1106ab0344eb0b0d27333bc842429332bda644cf0778c5ce8ecded5e3db5dd3664b9926aaec01ce13eff5a933a306e786ef2e717bc9ba2b2a5b0b1a3ad306c5df745b4f3bf1027b03b667638f86f198861f60257c708f600bb7a3feae929cff042d66cf5f3e052183dffa3a8af0df991c7f0fabeda4fde327d0c77aed8e90ebe0f09aa5dbcc06ee58a9142fe5ca49d420a28e3b0c46381f4b0ac808fa8a07c49d0b5ffff0a73ecb6721755c855bf87d76dfd468e7a2b9f8ae77619e9bcbff5e9f5a38870b294be1a182dc3c75ccf5416bf13015c9586b47b0f986a6384c3a8912e149,
        );
        signature = Signature.Signature(
          0x2dc538b2908432f33c82577abf2c748e12df77d4fa2d826791a75d2aaefb11d9191ebd5d569c38140943b632eb1a471d00fee28c063ef404b5b4e7df265653543069c4775b7913da042c552c87202da8121fa8795efb2d6f108eb95336e2b1111091bade2e8cfc37a8790fa79ff5d2ed69dfb6887db2b45517421eee8b6a06f34f717a7c99dabf3d9409c898ca1cb9a6bb306599e60b194a17b1e9ece1fecf9f75235b8db60c2405895c7cd145184c70a9aaacad9ae1c70a51201e7d0b52f2851d46c870f44d244093acf63e6fb9bd78e780bd9862300a03de9388d4b8bb7a0f505b338dbc30b9d23afbb121966f8a825ad2649d7156d63b61e67e58ab5831dc,
          #pkcs1v1_5,
        );
        message = "\48\65\6c\6c\6f\2c\20\77\6f\72\6c\64\21"; // "Hello, world!"
        hashAlgorithm = #sha256;
      },
    ];

    // Run all the test cases
    for (testCase in cases.vals()) {
      let isValid = testCase.key.verify(testCase.message.vals(), testCase.signature, testCase.hashAlgorithm);
      if (not isValid) Runtime.trap("Signature verification failed\nKey: " # testCase.key.toText(#hex({ format = { isUpper = true; prefix = #none }; byteEncoding = #spki })) # "\nSignature: " # debug_show (testCase.signature.value) # "\nMessage: " # debug_show testCase.message);
    };
  },
);

test(
  "PublicKey to/fromBytes",
  func() {

    type TestCase = {
      key : PublicKey.PublicKey;
      expectedBytes : Blob;
      byteEncoding : PublicKey.OutputByteEncoding;
    };

    let cases : [TestCase] = [
      {
        key = PublicKey.PublicKey(
          0x10001,
          0x00da5e1e10a1642ec7c502137f3bf50676fe5547fcab7b9acfaa5bdab98ab1478263e1e003ef6a752c0092c62bc027af7d4b74a47e183e5538f22b5b2f7258ec285265d12ade24970473b68806a8b0362a8798ef783ec97056efbb2c381fa38282e911a9bbcc26849ccb10ca95999d0b734ad3b13ecbb53b1e79c4e9e4a7332d3e2d0b35a78e1e87ccfd2d7f2c953ae5d5737b975a23f349e7b5658003d2a67d1f29781ae67c18542a000f0e23d13ba064574aacbcaae2bd369b90ee08e9e9fb634d54cd38859d6068a75e316e739978d4039ef3133e75c3da6ac1b2ca759d1712db3958164baa458fdf6bf51753dd36bc795968acda7531bfbf457d908544c159,
        );
        expectedBytes = "\30\82\01\0A\02\82\01\01\00\DA\5E\1E\10\A1\64\2E\C7\C5\02\13\7F\3B\F5\06\76\FE\55\47\FC\AB\7B\9A\CF\AA\5B\DA\B9\8A\B1\47\82\63\E1\E0\03\EF\6A\75\2C\00\92\C6\2B\C0\27\AF\7D\4B\74\A4\7E\18\3E\55\38\F2\2B\5B\2F\72\58\EC\28\52\65\D1\2A\DE\24\97\04\73\B6\88\06\A8\B0\36\2A\87\98\EF\78\3E\C9\70\56\EF\BB\2C\38\1F\A3\82\82\E9\11\A9\BB\CC\26\84\9C\CB\10\CA\95\99\9D\0B\73\4A\D3\B1\3E\CB\B5\3B\1E\79\C4\E9\E4\A7\33\2D\3E\2D\0B\35\A7\8E\1E\87\CC\FD\2D\7F\2C\95\3A\E5\D5\73\7B\97\5A\23\F3\49\E7\B5\65\80\03\D2\A6\7D\1F\29\78\1A\E6\7C\18\54\2A\00\0F\0E\23\D1\3B\A0\64\57\4A\AC\BC\AA\E2\BD\36\9B\90\EE\08\E9\E9\FB\63\4D\54\CD\38\85\9D\60\68\A7\5E\31\6E\73\99\78\D4\03\9E\F3\13\3E\75\C3\DA\6A\C1\B2\CA\75\9D\17\12\DB\39\58\16\4B\AA\45\8F\DF\6B\F5\17\53\DD\36\BC\79\59\68\AC\DA\75\31\BF\BF\45\7D\90\85\44\C1\59\02\03\01\00\01";
        byteEncoding = #pkcs1;
      },
      {
        key = PublicKey.PublicKey(
          0x10001,
          0x00da5e1e10a1642ec7c502137f3bf50676fe5547fcab7b9acfaa5bdab98ab1478263e1e003ef6a752c0092c62bc027af7d4b74a47e183e5538f22b5b2f7258ec285265d12ade24970473b68806a8b0362a8798ef783ec97056efbb2c381fa38282e911a9bbcc26849ccb10ca95999d0b734ad3b13ecbb53b1e79c4e9e4a7332d3e2d0b35a78e1e87ccfd2d7f2c953ae5d5737b975a23f349e7b5658003d2a67d1f29781ae67c18542a000f0e23d13ba064574aacbcaae2bd369b90ee08e9e9fb634d54cd38859d6068a75e316e739978d4039ef3133e75c3da6ac1b2ca759d1712db3958164baa458fdf6bf51753dd36bc795968acda7531bfbf457d908544c159,
        );
        expectedBytes = "\30\82\01\22\30\0D\06\09\2A\86\48\86\F7\0D\01\01\01\05\00\03\82\01\0F\00\30\82\01\0A\02\82\01\01\00\DA\5E\1E\10\A1\64\2E\C7\C5\02\13\7F\3B\F5\06\76\FE\55\47\FC\AB\7B\9A\CF\AA\5B\DA\B9\8A\B1\47\82\63\E1\E0\03\EF\6A\75\2C\00\92\C6\2B\C0\27\AF\7D\4B\74\A4\7E\18\3E\55\38\F2\2B\5B\2F\72\58\EC\28\52\65\D1\2A\DE\24\97\04\73\B6\88\06\A8\B0\36\2A\87\98\EF\78\3E\C9\70\56\EF\BB\2C\38\1F\A3\82\82\E9\11\A9\BB\CC\26\84\9C\CB\10\CA\95\99\9D\0B\73\4A\D3\B1\3E\CB\B5\3B\1E\79\C4\E9\E4\A7\33\2D\3E\2D\0B\35\A7\8E\1E\87\CC\FD\2D\7F\2C\95\3A\E5\D5\73\7B\97\5A\23\F3\49\E7\B5\65\80\03\D2\A6\7D\1F\29\78\1A\E6\7C\18\54\2A\00\0F\0E\23\D1\3B\A0\64\57\4A\AC\BC\AA\E2\BD\36\9B\90\EE\08\E9\E9\FB\63\4D\54\CD\38\85\9D\60\68\A7\5E\31\6E\73\99\78\D4\03\9E\F3\13\3E\75\C3\DA\6A\C1\B2\CA\75\9D\17\12\DB\39\58\16\4B\AA\45\8F\DF\6B\F5\17\53\DD\36\BC\79\59\68\AC\DA\75\31\BF\BF\45\7D\90\85\44\C1\59\02\03\01\00\01";
        byteEncoding = #spki;
      },
      {
        key = PublicKey.PublicKey(
          0x10001,
          0x008a217e244c487ac9ba67b5b87902fb75c576692dd6482ae58b39dd6e8ef1106ab0344eb0b0d27333bc842429332bda644cf0778c5ce8ecded5e3db5dd3664b9926aaec01ce13eff5a933a306e786ef2e717bc9ba2b2a5b0b1a3ad306c5df745b4f3bf1027b03b667638f86f198861f60257c708f600bb7a3feae929cff042d66cf5f3e052183dffa3a8af0df991c7f0fabeda4fde327d0c77aed8e90ebe0f09aa5dbcc06ee58a9142fe5ca49d420a28e3b0c46381f4b0ac808fa8a07c49d0b5ffff0a73ecb6721755c855bf87d76dfd468e7a2b9f8ae77619e9bcbff5e9f5a38870b294be1a182dc3c75ccf5416bf13015c9586b47b0f986a6384c3a8912e149,
        );
        expectedBytes = "\30\82\01\0A\02\82\01\01\00\8A\21\7E\24\4C\48\7A\C9\BA\67\B5\B8\79\02\FB\75\C5\76\69\2D\D6\48\2A\E5\8B\39\DD\6E\8E\F1\10\6A\B0\34\4E\B0\B0\D2\73\33\BC\84\24\29\33\2B\DA\64\4C\F0\77\8C\5C\E8\EC\DE\D5\E3\DB\5D\D3\66\4B\99\26\AA\EC\01\CE\13\EF\F5\A9\33\A3\06\E7\86\EF\2E\71\7B\C9\BA\2B\2A\5B\0B\1A\3A\D3\06\C5\DF\74\5B\4F\3B\F1\02\7B\03\B6\67\63\8F\86\F1\98\86\1F\60\25\7C\70\8F\60\0B\B7\A3\FE\AE\92\9C\FF\04\2D\66\CF\5F\3E\05\21\83\DF\FA\3A\8A\F0\DF\99\1C\7F\0F\AB\ED\A4\FD\E3\27\D0\C7\7A\ED\8E\90\EB\E0\F0\9A\A5\DB\CC\06\EE\58\A9\14\2F\E5\CA\49\D4\20\A2\8E\3B\0C\46\38\1F\4B\0A\C8\08\FA\8A\07\C4\9D\0B\5F\FF\F0\A7\3E\CB\67\21\75\5C\85\5B\F8\7D\76\DF\D4\68\E7\A2\B9\F8\AE\77\61\9E\9B\CB\FF\5E\9F\5A\38\87\0B\29\4B\E1\A1\82\DC\3C\75\CC\F5\41\6B\F1\30\15\C9\58\6B\47\B0\F9\86\A6\38\4C\3A\89\12\E1\49\02\03\01\00\01";
        byteEncoding = #pkcs1;
      },
      {
        key = PublicKey.PublicKey(
          0x10001,
          0x008a217e244c487ac9ba67b5b87902fb75c576692dd6482ae58b39dd6e8ef1106ab0344eb0b0d27333bc842429332bda644cf0778c5ce8ecded5e3db5dd3664b9926aaec01ce13eff5a933a306e786ef2e717bc9ba2b2a5b0b1a3ad306c5df745b4f3bf1027b03b667638f86f198861f60257c708f600bb7a3feae929cff042d66cf5f3e052183dffa3a8af0df991c7f0fabeda4fde327d0c77aed8e90ebe0f09aa5dbcc06ee58a9142fe5ca49d420a28e3b0c46381f4b0ac808fa8a07c49d0b5ffff0a73ecb6721755c855bf87d76dfd468e7a2b9f8ae77619e9bcbff5e9f5a38870b294be1a182dc3c75ccf5416bf13015c9586b47b0f986a6384c3a8912e149,
        );
        expectedBytes = "\30\82\01\22\30\0D\06\09\2A\86\48\86\F7\0D\01\01\01\05\00\03\82\01\0F\00\30\82\01\0A\02\82\01\01\00\8A\21\7E\24\4C\48\7A\C9\BA\67\B5\B8\79\02\FB\75\C5\76\69\2D\D6\48\2A\E5\8B\39\DD\6E\8E\F1\10\6A\B0\34\4E\B0\B0\D2\73\33\BC\84\24\29\33\2B\DA\64\4C\F0\77\8C\5C\E8\EC\DE\D5\E3\DB\5D\D3\66\4B\99\26\AA\EC\01\CE\13\EF\F5\A9\33\A3\06\E7\86\EF\2E\71\7B\C9\BA\2B\2A\5B\0B\1A\3A\D3\06\C5\DF\74\5B\4F\3B\F1\02\7B\03\B6\67\63\8F\86\F1\98\86\1F\60\25\7C\70\8F\60\0B\B7\A3\FE\AE\92\9C\FF\04\2D\66\CF\5F\3E\05\21\83\DF\FA\3A\8A\F0\DF\99\1C\7F\0F\AB\ED\A4\FD\E3\27\D0\C7\7A\ED\8E\90\EB\E0\F0\9A\A5\DB\CC\06\EE\58\A9\14\2F\E5\CA\49\D4\20\A2\8E\3B\0C\46\38\1F\4B\0A\C8\08\FA\8A\07\C4\9D\0B\5F\FF\F0\A7\3E\CB\67\21\75\5C\85\5B\F8\7D\76\DF\D4\68\E7\A2\B9\F8\AE\77\61\9E\9B\CB\FF\5E\9F\5A\38\87\0B\29\4B\E1\A1\82\DC\3C\75\CC\F5\41\6B\F1\30\15\C9\58\6B\47\B0\F9\86\A6\38\4C\3A\89\12\E1\49\02\03\01\00\01";
        byteEncoding = #spki;
      },
    ];

    for (testCase in cases.vals()) {
      // Serialize
      let actualBytes = testCase.key.toBytes(testCase.byteEncoding);
      let actualBlob = Blob.fromArray(actualBytes);
      if (testCase.expectedBytes != actualBlob) {
        Runtime.trap(
          "toBytes mismatch for " # debug_show testCase.byteEncoding
          # "\nExpected: " # debug_show testCase.expectedBytes
          # "\nActual: " # debug_show actualBlob
        );
      };

      // Deserialize
      let deserializedKey = switch (PublicKey.fromBytes(actualBytes.vals(), testCase.byteEncoding)) {
        case (#ok(key)) key;
        case (#err(e)) Runtime.trap("fromBytes failed for " # debug_show testCase.byteEncoding # ": " # e);
      };

      // Compare
      if (not testCase.key.equal(deserializedKey)) {
        Runtime.trap(
          "Key mismatch after toBytes/fromBytes roundtrip for " # debug_show testCase.byteEncoding
          # "\nOriginal Modulus: " # debug_show testCase.key.modulus
          # "\nDeserialized Modulus: " # debug_show deserializedKey.modulus
          # "\nOriginal Exponent: " # debug_show testCase.key.exponent
          # "\nDeserialized Exponent: " # debug_show deserializedKey.exponent
        );
      };
    };
  },
);

test(
  "PublicKey to/fromText",
  func() {
    let hexOutputFormat : BaseX.HexOutputFormat = {
      isUpper = false;
      prefix = #none;
    };
    let hexInputFormat : BaseX.HexInputFormat = {
      prefix = #none;
    };

    type TestCase = {
      key : PublicKey.PublicKey;
      expectedText : Text; // The pre-computed expected text output
      textFormat : PublicKey.OutputTextFormat; // Format for toText
      // Use optional type '?' for formats that don't have a corresponding 'fromText' implementation (like #jwk)
      inputTextFormat : ?PublicKey.InputTextFormat; // Format for fromText
    };

    let cases : [TestCase] = [
      // --- Key 1 Cases ---
      {
        // Hex PKCS#1
        key = PublicKey.PublicKey(
          0x10001,
          0x00da5e1e10a1642ec7c502137f3bf50676fe5547fcab7b9acfaa5bdab98ab1478263e1e003ef6a752c0092c62bc027af7d4b74a47e183e5538f22b5b2f7258ec285265d12ade24970473b68806a8b0362a8798ef783ec97056efbb2c381fa38282e911a9bbcc26849ccb10ca95999d0b734ad3b13ecbb53b1e79c4e9e4a7332d3e2d0b35a78e1e87ccfd2d7f2c953ae5d5737b975a23f349e7b5658003d2a67d1f29781ae67c18542a000f0e23d13ba064574aacbcaae2bd369b90ee08e9e9fb634d54cd38859d6068a75e316e739978d4039ef3133e75c3da6ac1b2ca759d1712db3958164baa458fdf6bf51753dd36bc795968acda7531bfbf457d908544c159,
        );
        expectedText = "3082010a0282010100da5e1e10a1642ec7c502137f3bf50676fe5547fcab7b9acfaa5bdab98ab1478263e1e003ef6a752c0092c62bc027af7d4b74a47e183e5538f22b5b2f7258ec285265d12ade24970473b68806a8b0362a8798ef783ec97056efbb2c381fa38282e911a9bbcc26849ccb10ca95999d0b734ad3b13ecbb53b1e79c4e9e4a7332d3e2d0b35a78e1e87ccfd2d7f2c953ae5d5737b975a23f349e7b5658003d2a67d1f29781ae67c18542a000f0e23d13ba064574aacbcaae2bd369b90ee08e9e9fb634d54cd38859d6068a75e316e739978d4039ef3133e75c3da6ac1b2ca759d1712db3958164baa458fdf6bf51753dd36bc795968acda7531bfbf457d908544c1590203010001";
        textFormat = #hex({ byteEncoding = #pkcs1; format = hexOutputFormat });
        inputTextFormat = ?#hex({
          byteEncoding = #pkcs1;
          format = hexInputFormat;
        });
      },
      {
        // Hex SPKI
        key = PublicKey.PublicKey(
          0x10001,
          0x00da5e1e10a1642ec7c502137f3bf50676fe5547fcab7b9acfaa5bdab98ab1478263e1e003ef6a752c0092c62bc027af7d4b74a47e183e5538f22b5b2f7258ec285265d12ade24970473b68806a8b0362a8798ef783ec97056efbb2c381fa38282e911a9bbcc26849ccb10ca95999d0b734ad3b13ecbb53b1e79c4e9e4a7332d3e2d0b35a78e1e87ccfd2d7f2c953ae5d5737b975a23f349e7b5658003d2a67d1f29781ae67c18542a000f0e23d13ba064574aacbcaae2bd369b90ee08e9e9fb634d54cd38859d6068a75e316e739978d4039ef3133e75c3da6ac1b2ca759d1712db3958164baa458fdf6bf51753dd36bc795968acda7531bfbf457d908544c159,
        );
        expectedText = "30820122300d06092a864886f70d01010105000382010f003082010a0282010100da5e1e10a1642ec7c502137f3bf50676fe5547fcab7b9acfaa5bdab98ab1478263e1e003ef6a752c0092c62bc027af7d4b74a47e183e5538f22b5b2f7258ec285265d12ade24970473b68806a8b0362a8798ef783ec97056efbb2c381fa38282e911a9bbcc26849ccb10ca95999d0b734ad3b13ecbb53b1e79c4e9e4a7332d3e2d0b35a78e1e87ccfd2d7f2c953ae5d5737b975a23f349e7b5658003d2a67d1f29781ae67c18542a000f0e23d13ba064574aacbcaae2bd369b90ee08e9e9fb634d54cd38859d6068a75e316e739978d4039ef3133e75c3da6ac1b2ca759d1712db3958164baa458fdf6bf51753dd36bc795968acda7531bfbf457d908544c1590203010001";
        textFormat = #hex({ byteEncoding = #spki; format = hexOutputFormat });
        inputTextFormat = ?#hex({
          byteEncoding = #spki;
          format = hexInputFormat;
        });
      },
      {
        // Base64 PKCS#1 (standard)
        key = PublicKey.PublicKey(
          0x10001,
          0x00da5e1e10a1642ec7c502137f3bf50676fe5547fcab7b9acfaa5bdab98ab1478263e1e003ef6a752c0092c62bc027af7d4b74a47e183e5538f22b5b2f7258ec285265d12ade24970473b68806a8b0362a8798ef783ec97056efbb2c381fa38282e911a9bbcc26849ccb10ca95999d0b734ad3b13ecbb53b1e79c4e9e4a7332d3e2d0b35a78e1e87ccfd2d7f2c953ae5d5737b975a23f349e7b5658003d2a67d1f29781ae67c18542a000f0e23d13ba064574aacbcaae2bd369b90ee08e9e9fb634d54cd38859d6068a75e316e739978d4039ef3133e75c3da6ac1b2ca759d1712db3958164baa458fdf6bf51753dd36bc795968acda7531bfbf457d908544c159,
        );
        expectedText = "MIIBCgKCAQEA2l4eEKFkLsfFAhN/O/UGdv5VR/yre5rPqlvauYqxR4Jj4eAD72p1LACSxivAJ699S3Skfhg+VTjyK1svcljsKFJl0SreJJcEc7aIBqiwNiqHmO94PslwVu+7LDgfo4KC6RGpu8wmhJzLEMqVmZ0Lc0rTsT7LtTseecTp5KczLT4tCzWnjh6HzP0tfyyVOuXVc3uXWiPzSee1ZYAD0qZ9Hyl4GuZ8GFQqAA8OI9E7oGRXSqy8quK9NpuQ7gjp6ftjTVTNOIWdYGinXjFuc5l41AOe8xM+dcPaasGyynWdFxLbOVgWS6pFj99r9RdT3Ta8eVlorNp1Mb+/RX2QhUTBWQIDAQAB";
        textFormat = #base64({ byteEncoding = #pkcs1; isUriSafe = false });
        inputTextFormat = ?#base64({ byteEncoding = #pkcs1 });
      },
      {
        // Base64 SPKI (standard)
        key = PublicKey.PublicKey(
          0x10001,
          0x00da5e1e10a1642ec7c502137f3bf50676fe5547fcab7b9acfaa5bdab98ab1478263e1e003ef6a752c0092c62bc027af7d4b74a47e183e5538f22b5b2f7258ec285265d12ade24970473b68806a8b0362a8798ef783ec97056efbb2c381fa38282e911a9bbcc26849ccb10ca95999d0b734ad3b13ecbb53b1e79c4e9e4a7332d3e2d0b35a78e1e87ccfd2d7f2c953ae5d5737b975a23f349e7b5658003d2a67d1f29781ae67c18542a000f0e23d13ba064574aacbcaae2bd369b90ee08e9e9fb634d54cd38859d6068a75e316e739978d4039ef3133e75c3da6ac1b2ca759d1712db3958164baa458fdf6bf51753dd36bc795968acda7531bfbf457d908544c159,
        );
        expectedText = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2l4eEKFkLsfFAhN/O/UGdv5VR/yre5rPqlvauYqxR4Jj4eAD72p1LACSxivAJ699S3Skfhg+VTjyK1svcljsKFJl0SreJJcEc7aIBqiwNiqHmO94PslwVu+7LDgfo4KC6RGpu8wmhJzLEMqVmZ0Lc0rTsT7LtTseecTp5KczLT4tCzWnjh6HzP0tfyyVOuXVc3uXWiPzSee1ZYAD0qZ9Hyl4GuZ8GFQqAA8OI9E7oGRXSqy8quK9NpuQ7gjp6ftjTVTNOIWdYGinXjFuc5l41AOe8xM+dcPaasGyynWdFxLbOVgWS6pFj99r9RdT3Ta8eVlorNp1Mb+/RX2QhUTBWQIDAQAB";
        textFormat = #base64({ byteEncoding = #spki; isUriSafe = false });
        inputTextFormat = ?#base64({ byteEncoding = #spki });
      },
      {
        // Base64 SPKI (URI Safe - serialization check only unless fromText handles it)
        key = PublicKey.PublicKey(
          0x10001,
          0x00da5e1e10a1642ec7c502137f3bf50676fe5547fcab7b9acfaa5bdab98ab1478263e1e003ef6a752c0092c62bc027af7d4b74a47e183e5538f22b5b2f7258ec285265d12ade24970473b68806a8b0362a8798ef783ec97056efbb2c381fa38282e911a9bbcc26849ccb10ca95999d0b734ad3b13ecbb53b1e79c4e9e4a7332d3e2d0b35a78e1e87ccfd2d7f2c953ae5d5737b975a23f349e7b5658003d2a67d1f29781ae67c18542a000f0e23d13ba064574aacbcaae2bd369b90ee08e9e9fb634d54cd38859d6068a75e316e739978d4039ef3133e75c3da6ac1b2ca759d1712db3958164baa458fdf6bf51753dd36bc795968acda7531bfbf457d908544c159,
        );
        expectedText = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2l4eEKFkLsfFAhN_O_UGdv5VR_yre5rPqlvauYqxR4Jj4eAD72p1LACSxivAJ699S3Skfhg-VTjyK1svcljsKFJl0SreJJcEc7aIBqiwNiqHmO94PslwVu-7LDgfo4KC6RGpu8wmhJzLEMqVmZ0Lc0rTsT7LtTseecTp5KczLT4tCzWnjh6HzP0tfyyVOuXVc3uXWiPzSee1ZYAD0qZ9Hyl4GuZ8GFQqAA8OI9E7oGRXSqy8quK9NpuQ7gjp6ftjTVTNOIWdYGinXjFuc5l41AOe8xM-dcPaasGyynWdFxLbOVgWS6pFj99r9RdT3Ta8eVlorNp1Mb-_RX2QhUTBWQIDAQAB";
        textFormat = #base64({ byteEncoding = #spki; isUriSafe = true });
        // Assuming fromText implicitly handles standard/uri-safe, otherwise needs specific inputTextFormat or skip deserialization
        inputTextFormat = ?#base64({ byteEncoding = #spki }); // Check if fromText needs uriSafe info
      },
      {
        // PEM PKCS#1
        key = PublicKey.PublicKey(
          0x10001,
          0x00da5e1e10a1642ec7c502137f3bf50676fe5547fcab7b9acfaa5bdab98ab1478263e1e003ef6a752c0092c62bc027af7d4b74a47e183e5538f22b5b2f7258ec285265d12ade24970473b68806a8b0362a8798ef783ec97056efbb2c381fa38282e911a9bbcc26849ccb10ca95999d0b734ad3b13ecbb53b1e79c4e9e4a7332d3e2d0b35a78e1e87ccfd2d7f2c953ae5d5737b975a23f349e7b5658003d2a67d1f29781ae67c18542a000f0e23d13ba064574aacbcaae2bd369b90ee08e9e9fb634d54cd38859d6068a75e316e739978d4039ef3133e75c3da6ac1b2ca759d1712db3958164baa458fdf6bf51753dd36bc795968acda7531bfbf457d908544c159,
        );
        expectedText = "-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA2l4eEKFkLsfFAhN/O/UGdv5VR/yre5rPqlvauYqxR4Jj4eAD72p1
LACSxivAJ699S3Skfhg+VTjyK1svcljsKFJl0SreJJcEc7aIBqiwNiqHmO94Pslw
Vu+7LDgfo4KC6RGpu8wmhJzLEMqVmZ0Lc0rTsT7LtTseecTp5KczLT4tCzWnjh6H
zP0tfyyVOuXVc3uXWiPzSee1ZYAD0qZ9Hyl4GuZ8GFQqAA8OI9E7oGRXSqy8quK9
NpuQ7gjp6ftjTVTNOIWdYGinXjFuc5l41AOe8xM+dcPaasGyynWdFxLbOVgWS6pF
j99r9RdT3Ta8eVlorNp1Mb+/RX2QhUTBWQIDAQAB
-----END RSA PUBLIC KEY-----
";
        textFormat = #pem({ byteEncoding = #pkcs1 });
        inputTextFormat = ?#pem({ byteEncoding = #pkcs1 });
      },
      {
        // PEM SPKI
        key = PublicKey.PublicKey(
          0x10001,
          0x00da5e1e10a1642ec7c502137f3bf50676fe5547fcab7b9acfaa5bdab98ab1478263e1e003ef6a752c0092c62bc027af7d4b74a47e183e5538f22b5b2f7258ec285265d12ade24970473b68806a8b0362a8798ef783ec97056efbb2c381fa38282e911a9bbcc26849ccb10ca95999d0b734ad3b13ecbb53b1e79c4e9e4a7332d3e2d0b35a78e1e87ccfd2d7f2c953ae5d5737b975a23f349e7b5658003d2a67d1f29781ae67c18542a000f0e23d13ba064574aacbcaae2bd369b90ee08e9e9fb634d54cd38859d6068a75e316e739978d4039ef3133e75c3da6ac1b2ca759d1712db3958164baa458fdf6bf51753dd36bc795968acda7531bfbf457d908544c159,
        );
        expectedText = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2l4eEKFkLsfFAhN/O/UG
dv5VR/yre5rPqlvauYqxR4Jj4eAD72p1LACSxivAJ699S3Skfhg+VTjyK1svcljs
KFJl0SreJJcEc7aIBqiwNiqHmO94PslwVu+7LDgfo4KC6RGpu8wmhJzLEMqVmZ0L
c0rTsT7LtTseecTp5KczLT4tCzWnjh6HzP0tfyyVOuXVc3uXWiPzSee1ZYAD0qZ9
Hyl4GuZ8GFQqAA8OI9E7oGRXSqy8quK9NpuQ7gjp6ftjTVTNOIWdYGinXjFuc5l4
1AOe8xM+dcPaasGyynWdFxLbOVgWS6pFj99r9RdT3Ta8eVlorNp1Mb+/RX2QhUTB
WQIDAQAB
-----END PUBLIC KEY-----
";
        textFormat = #pem({ byteEncoding = #spki });
        inputTextFormat = ?#pem({ byteEncoding = #spki });
      },
      {
        // JWK (Serialization Only Test)
        key = PublicKey.PublicKey(
          0x10001,
          0x00da5e1e10a1642ec7c502137f3bf50676fe5547fcab7b9acfaa5bdab98ab1478263e1e003ef6a752c0092c62bc027af7d4b74a47e183e5538f22b5b2f7258ec285265d12ade24970473b68806a8b0362a8798ef783ec97056efbb2c381fa38282e911a9bbcc26849ccb10ca95999d0b734ad3b13ecbb53b1e79c4e9e4a7332d3e2d0b35a78e1e87ccfd2d7f2c953ae5d5737b975a23f349e7b5658003d2a67d1f29781ae67c18542a000f0e23d13ba064574aacbcaae2bd369b90ee08e9e9fb634d54cd38859d6068a75e316e739978d4039ef3133e75c3da6ac1b2ca759d1712db3958164baa458fdf6bf51753dd36bc795968acda7531bfbf457d908544c159,
        );
        expectedText = "{\"kty\":\"RSA\",\"n\":\"2l4eEKFkLsfFAhN_O_UGdv5VR_yre5rPqlvauYqxR4Jj4eAD72p1LACSxivAJ699S3Skfhg-VTjyK1svcljsKFJl0SreJJcEc7aIBqiwNiqHmO94PslwVu-7LDgfo4KC6RGpu8wmhJzLEMqVmZ0Lc0rTsT7LtTseecTp5KczLT4tCzWnjh6HzP0tfyyVOuXVc3uXWiPzSee1ZYAD0qZ9Hyl4GuZ8GFQqAA8OI9E7oGRXSqy8quK9NpuQ7gjp6ftjTVTNOIWdYGinXjFuc5l41AOe8xM-dcPaasGyynWdFxLbOVgWS6pFj99r9RdT3Ta8eVlorNp1Mb-_RX2QhUTBWQ\",\"e\":\"2l4eEKFkLsfFAhN_O_UGdv5VR_yre5rPqlvauYqxR4Jj4eAD72p1LACSxivAJ699S3Skfhg-VTjyK1svcljsKFJl0SreJJcEc7aIBqiwNiqHmO94PslwVu-7LDgfo4KC6RGpu8wmhJzLEMqVmZ0Lc0rTsT7LtTseecTp5KczLT4tCzWnjh6HzP0tfyyVOuXVc3uXWiPzSee1ZYAD0qZ9Hyl4GuZ8GFQqAA8OI9E7oGRXSqy8quK9NpuQ7gjp6ftjTVTNOIWdYGinXjFuc5l41AOe8xM-dcPaasGyynWdFxLbOVgWS6pFj99r9RdT3Ta8eVlorNp1Mb-_RX2QhUTBWQEAAQ\"}";
        textFormat = #jwk;
        inputTextFormat = null; // Mark that fromText does not support this format
      },

      // --- Key 2 Cases --- (Repeat the pattern)
      {
        // Hex PKCS#1
        key = PublicKey.PublicKey(
          0x10001,
          0x008a217e244c487ac9ba67b5b87902fb75c576692dd6482ae58b39dd6e8ef1106ab0344eb0b0d27333bc842429332bda644cf0778c5ce8ecded5e3db5dd3664b9926aaec01ce13eff5a933a306e786ef2e717bc9ba2b2a5b0b1a3ad306c5df745b4f3bf1027b03b667638f86f198861f60257c708f600bb7a3feae929cff042d66cf5f3e052183dffa3a8af0df991c7f0fabeda4fde327d0c77aed8e90ebe0f09aa5dbcc06ee58a9142fe5ca49d420a28e3b0c46381f4b0ac808fa8a07c49d0b5ffff0a73ecb6721755c855bf87d76dfd468e7a2b9f8ae77619e9bcbff5e9f5a38870b294be1a182dc3c75ccf5416bf13015c9586b47b0f986a6384c3a8912e149,
        );
        expectedText = "3082010a02820101008a217e244c487ac9ba67b5b87902fb75c576692dd6482ae58b39dd6e8ef1106ab0344eb0b0d27333bc842429332bda644cf0778c5ce8ecded5e3db5dd3664b9926aaec01ce13eff5a933a306e786ef2e717bc9ba2b2a5b0b1a3ad306c5df745b4f3bf1027b03b667638f86f198861f60257c708f600bb7a3feae929cff042d66cf5f3e052183dffa3a8af0df991c7f0fabeda4fde327d0c77aed8e90ebe0f09aa5dbcc06ee58a9142fe5ca49d420a28e3b0c46381f4b0ac808fa8a07c49d0b5ffff0a73ecb6721755c855bf87d76dfd468e7a2b9f8ae77619e9bcbff5e9f5a38870b294be1a182dc3c75ccf5416bf13015c9586b47b0f986a6384c3a8912e1490203010001";
        textFormat = #hex({ byteEncoding = #pkcs1; format = hexOutputFormat });
        inputTextFormat = ?#hex({
          byteEncoding = #pkcs1;
          format = hexInputFormat;
        });
      },
      {
        // Hex SPKI
        key = PublicKey.PublicKey(
          0x10001,
          0x008a217e244c487ac9ba67b5b87902fb75c576692dd6482ae58b39dd6e8ef1106ab0344eb0b0d27333bc842429332bda644cf0778c5ce8ecded5e3db5dd3664b9926aaec01ce13eff5a933a306e786ef2e717bc9ba2b2a5b0b1a3ad306c5df745b4f3bf1027b03b667638f86f198861f60257c708f600bb7a3feae929cff042d66cf5f3e052183dffa3a8af0df991c7f0fabeda4fde327d0c77aed8e90ebe0f09aa5dbcc06ee58a9142fe5ca49d420a28e3b0c46381f4b0ac808fa8a07c49d0b5ffff0a73ecb6721755c855bf87d76dfd468e7a2b9f8ae77619e9bcbff5e9f5a38870b294be1a182dc3c75ccf5416bf13015c9586b47b0f986a6384c3a8912e149,
        );
        expectedText = "30820122300d06092a864886f70d01010105000382010f003082010a02820101008a217e244c487ac9ba67b5b87902fb75c576692dd6482ae58b39dd6e8ef1106ab0344eb0b0d27333bc842429332bda644cf0778c5ce8ecded5e3db5dd3664b9926aaec01ce13eff5a933a306e786ef2e717bc9ba2b2a5b0b1a3ad306c5df745b4f3bf1027b03b667638f86f198861f60257c708f600bb7a3feae929cff042d66cf5f3e052183dffa3a8af0df991c7f0fabeda4fde327d0c77aed8e90ebe0f09aa5dbcc06ee58a9142fe5ca49d420a28e3b0c46381f4b0ac808fa8a07c49d0b5ffff0a73ecb6721755c855bf87d76dfd468e7a2b9f8ae77619e9bcbff5e9f5a38870b294be1a182dc3c75ccf5416bf13015c9586b47b0f986a6384c3a8912e1490203010001";
        textFormat = #hex({ byteEncoding = #spki; format = hexOutputFormat });
        inputTextFormat = ?#hex({
          byteEncoding = #spki;
          format = hexInputFormat;
        });
      },
      {
        // Base64 PKCS#1
        key = PublicKey.PublicKey(
          0x10001,
          0x008a217e244c487ac9ba67b5b87902fb75c576692dd6482ae58b39dd6e8ef1106ab0344eb0b0d27333bc842429332bda644cf0778c5ce8ecded5e3db5dd3664b9926aaec01ce13eff5a933a306e786ef2e717bc9ba2b2a5b0b1a3ad306c5df745b4f3bf1027b03b667638f86f198861f60257c708f600bb7a3feae929cff042d66cf5f3e052183dffa3a8af0df991c7f0fabeda4fde327d0c77aed8e90ebe0f09aa5dbcc06ee58a9142fe5ca49d420a28e3b0c46381f4b0ac808fa8a07c49d0b5ffff0a73ecb6721755c855bf87d76dfd468e7a2b9f8ae77619e9bcbff5e9f5a38870b294be1a182dc3c75ccf5416bf13015c9586b47b0f986a6384c3a8912e149,
        );
        expectedText = "MIIBCgKCAQEAiiF+JExIesm6Z7W4eQL7dcV2aS3WSCrlizndbo7xEGqwNE6wsNJzM7yEJCkzK9pkTPB3jFzo7N7V49td02ZLmSaq7AHOE+/1qTOjBueG7y5xe8m6KypbCxo60wbF33RbTzvxAnsDtmdjj4bxmIYfYCV8cI9gC7ej/q6SnP8ELWbPXz4FIYPf+jqK8N+ZHH8Pq+2k/eMn0Md67Y6Q6+DwmqXbzAbuWKkUL+XKSdQgoo47DEY4H0sKyAj6igfEnQtf//CnPstnIXVchVv4fXbf1Gjnorn4rndhnpvL/16fWjiHCylL4aGC3Dx1zPVBa/EwFclYa0ew+YamOEw6iRLhSQIDAQAB";
        textFormat = #base64({ byteEncoding = #pkcs1; isUriSafe = false });
        inputTextFormat = ?#base64({ byteEncoding = #pkcs1 });
      },
      {
        // Base64 SPKI
        key = PublicKey.PublicKey(
          0x10001,
          0x008a217e244c487ac9ba67b5b87902fb75c576692dd6482ae58b39dd6e8ef1106ab0344eb0b0d27333bc842429332bda644cf0778c5ce8ecded5e3db5dd3664b9926aaec01ce13eff5a933a306e786ef2e717bc9ba2b2a5b0b1a3ad306c5df745b4f3bf1027b03b667638f86f198861f60257c708f600bb7a3feae929cff042d66cf5f3e052183dffa3a8af0df991c7f0fabeda4fde327d0c77aed8e90ebe0f09aa5dbcc06ee58a9142fe5ca49d420a28e3b0c46381f4b0ac808fa8a07c49d0b5ffff0a73ecb6721755c855bf87d76dfd468e7a2b9f8ae77619e9bcbff5e9f5a38870b294be1a182dc3c75ccf5416bf13015c9586b47b0f986a6384c3a8912e149,
        );
        expectedText = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiiF+JExIesm6Z7W4eQL7dcV2aS3WSCrlizndbo7xEGqwNE6wsNJzM7yEJCkzK9pkTPB3jFzo7N7V49td02ZLmSaq7AHOE+/1qTOjBueG7y5xe8m6KypbCxo60wbF33RbTzvxAnsDtmdjj4bxmIYfYCV8cI9gC7ej/q6SnP8ELWbPXz4FIYPf+jqK8N+ZHH8Pq+2k/eMn0Md67Y6Q6+DwmqXbzAbuWKkUL+XKSdQgoo47DEY4H0sKyAj6igfEnQtf//CnPstnIXVchVv4fXbf1Gjnorn4rndhnpvL/16fWjiHCylL4aGC3Dx1zPVBa/EwFclYa0ew+YamOEw6iRLhSQIDAQAB";
        textFormat = #base64({ byteEncoding = #spki; isUriSafe = false });
        inputTextFormat = ?#base64({ byteEncoding = #spki });
      },
      {
        // PEM PKCS#1
        key = PublicKey.PublicKey(
          0x10001,
          0x008a217e244c487ac9ba67b5b87902fb75c576692dd6482ae58b39dd6e8ef1106ab0344eb0b0d27333bc842429332bda644cf0778c5ce8ecded5e3db5dd3664b9926aaec01ce13eff5a933a306e786ef2e717bc9ba2b2a5b0b1a3ad306c5df745b4f3bf1027b03b667638f86f198861f60257c708f600bb7a3feae929cff042d66cf5f3e052183dffa3a8af0df991c7f0fabeda4fde327d0c77aed8e90ebe0f09aa5dbcc06ee58a9142fe5ca49d420a28e3b0c46381f4b0ac808fa8a07c49d0b5ffff0a73ecb6721755c855bf87d76dfd468e7a2b9f8ae77619e9bcbff5e9f5a38870b294be1a182dc3c75ccf5416bf13015c9586b47b0f986a6384c3a8912e149,
        );
        expectedText = "-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAiiF+JExIesm6Z7W4eQL7dcV2aS3WSCrlizndbo7xEGqwNE6wsNJz
M7yEJCkzK9pkTPB3jFzo7N7V49td02ZLmSaq7AHOE+/1qTOjBueG7y5xe8m6Kypb
Cxo60wbF33RbTzvxAnsDtmdjj4bxmIYfYCV8cI9gC7ej/q6SnP8ELWbPXz4FIYPf
+jqK8N+ZHH8Pq+2k/eMn0Md67Y6Q6+DwmqXbzAbuWKkUL+XKSdQgoo47DEY4H0sK
yAj6igfEnQtf//CnPstnIXVchVv4fXbf1Gjnorn4rndhnpvL/16fWjiHCylL4aGC
3Dx1zPVBa/EwFclYa0ew+YamOEw6iRLhSQIDAQAB
-----END RSA PUBLIC KEY-----
";
        textFormat = #pem({ byteEncoding = #pkcs1 });
        inputTextFormat = ?#pem({ byteEncoding = #pkcs1 });
      },
      {
        // PEM SPKI
        key = PublicKey.PublicKey(
          0x10001,
          0x008a217e244c487ac9ba67b5b87902fb75c576692dd6482ae58b39dd6e8ef1106ab0344eb0b0d27333bc842429332bda644cf0778c5ce8ecded5e3db5dd3664b9926aaec01ce13eff5a933a306e786ef2e717bc9ba2b2a5b0b1a3ad306c5df745b4f3bf1027b03b667638f86f198861f60257c708f600bb7a3feae929cff042d66cf5f3e052183dffa3a8af0df991c7f0fabeda4fde327d0c77aed8e90ebe0f09aa5dbcc06ee58a9142fe5ca49d420a28e3b0c46381f4b0ac808fa8a07c49d0b5ffff0a73ecb6721755c855bf87d76dfd468e7a2b9f8ae77619e9bcbff5e9f5a38870b294be1a182dc3c75ccf5416bf13015c9586b47b0f986a6384c3a8912e149,
        );
        expectedText = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiiF+JExIesm6Z7W4eQL7
dcV2aS3WSCrlizndbo7xEGqwNE6wsNJzM7yEJCkzK9pkTPB3jFzo7N7V49td02ZL
mSaq7AHOE+/1qTOjBueG7y5xe8m6KypbCxo60wbF33RbTzvxAnsDtmdjj4bxmIYf
YCV8cI9gC7ej/q6SnP8ELWbPXz4FIYPf+jqK8N+ZHH8Pq+2k/eMn0Md67Y6Q6+Dw
mqXbzAbuWKkUL+XKSdQgoo47DEY4H0sKyAj6igfEnQtf//CnPstnIXVchVv4fXbf
1Gjnorn4rndhnpvL/16fWjiHCylL4aGC3Dx1zPVBa/EwFclYa0ew+YamOEw6iRLh
SQIDAQAB
-----END PUBLIC KEY-----
";
        textFormat = #pem({ byteEncoding = #spki });
        inputTextFormat = ?#pem({ byteEncoding = #spki });
      },
      {
        // JWK (Serialization Only Test)
        key = PublicKey.PublicKey(
          0x10001,
          0x008a217e244c487ac9ba67b5b87902fb75c576692dd6482ae58b39dd6e8ef1106ab0344eb0b0d27333bc842429332bda644cf0778c5ce8ecded5e3db5dd3664b9926aaec01ce13eff5a933a306e786ef2e717bc9ba2b2a5b0b1a3ad306c5df745b4f3bf1027b03b667638f86f198861f60257c708f600bb7a3feae929cff042d66cf5f3e052183dffa3a8af0df991c7f0fabeda4fde327d0c77aed8e90ebe0f09aa5dbcc06ee58a9142fe5ca49d420a28e3b0c46381f4b0ac808fa8a07c49d0b5ffff0a73ecb6721755c855bf87d76dfd468e7a2b9f8ae77619e9bcbff5e9f5a38870b294be1a182dc3c75ccf5416bf13015c9586b47b0f986a6384c3a8912e149,
        );
        expectedText = "{\"kty\":\"RSA\",\"n\":\"iiF-JExIesm6Z7W4eQL7dcV2aS3WSCrlizndbo7xEGqwNE6wsNJzM7yEJCkzK9pkTPB3jFzo7N7V49td02ZLmSaq7AHOE-_1qTOjBueG7y5xe8m6KypbCxo60wbF33RbTzvxAnsDtmdjj4bxmIYfYCV8cI9gC7ej_q6SnP8ELWbPXz4FIYPf-jqK8N-ZHH8Pq-2k_eMn0Md67Y6Q6-DwmqXbzAbuWKkUL-XKSdQgoo47DEY4H0sKyAj6igfEnQtf__CnPstnIXVchVv4fXbf1Gjnorn4rndhnpvL_16fWjiHCylL4aGC3Dx1zPVBa_EwFclYa0ew-YamOEw6iRLhSQ\",\"e\":\"iiF-JExIesm6Z7W4eQL7dcV2aS3WSCrlizndbo7xEGqwNE6wsNJzM7yEJCkzK9pkTPB3jFzo7N7V49td02ZLmSaq7AHOE-_1qTOjBueG7y5xe8m6KypbCxo60wbF33RbTzvxAnsDtmdjj4bxmIYfYCV8cI9gC7ej_q6SnP8ELWbPXz4FIYPf-jqK8N-ZHH8Pq-2k_eMn0Md67Y6Q6-DwmqXbzAbuWKkUL-XKSdQgoo47DEY4H0sKyAj6igfEnQtf__CnPstnIXVchVv4fXbf1Gjnorn4rndhnpvL_16fWjiHCylL4aGC3Dx1zPVBa_EwFclYa0ew-YamOEw6iRLhSQEAAQ\"}";
        textFormat = #jwk;
        inputTextFormat = null;
      },
    ];

    // --- Run Test Cases ---
    for (testCase in cases.vals()) {
      // 1. Test Serialization (toText)
      let actualText = testCase.key.toText(testCase.textFormat);

      // Compare serialization result with expected value
      if (testCase.expectedText != actualText) {
        // Use debug_show for potentially complex textFormat structures
        Runtime.trap(
          "toText mismatch for " # debug_show testCase.textFormat
          # "\nExpected:\n" # testCase.expectedText
          # "\nActual:\n" # actualText
        );
      };

      // 2. Test Deserialization (fromText), if applicable
      switch (testCase.inputTextFormat) {
        case (?inputFormat) {
          // Format supports deserialization
          let deserializedKeyResult = PublicKey.fromText(actualText, inputFormat);

          let deserializedKey = switch (deserializedKeyResult) {
            case (#ok(key)) key;
            case (#err(e)) Runtime.trap("fromText failed for " # debug_show inputFormat # ": " # e # "\nInput Text:\n" # actualText);
          };

          // Compare deserialized key with the original key
          if (not testCase.key.equal(deserializedKey)) {
            Runtime.trap(
              "Key mismatch after toText/fromText roundtrip for format " # debug_show testCase.textFormat
              # " / " # debug_show inputFormat
              # "\nOriginal Modulus: " # debug_show testCase.key.modulus
              # "\nDeserialized Modulus: " # debug_show deserializedKey.modulus
              # "\nOriginal Exponent: " # debug_show testCase.key.exponent
              # "\nDeserialized Exponent: " # debug_show deserializedKey.exponent
            );
          };
        };
        case (null) ();
      };
    };
  },
);
