import { test } "mo:test";
import Runtime "mo:core/Runtime";
import Blob "mo:core/Blob";
import Signature "../src/Signature";

test(
  "Signature to/fromBytes",
  func() {

    type TestCase = {
      signature : Signature.Signature;
      expectedBytes : Blob;
      inputByteEncoding : Signature.InputByteEncoding;
      outputByteEncoding : Signature.OutputByteEncoding;
    };

    // Test cases
    let cases : [TestCase] = [
      {
        signature = Signature.Signature(
          0x057bbb5b514e08c0ecc104c8d14d4237bf7f3aaa4375df39436a0394a5b2f366d33f9cff4d4582d858f082409cedf891dcca8952da79762ce4b2f498eec8bbe5d04d0cb9f814a45651497231efe0632a780856f99a39ce745954ab5ba86b7bb15834b11e818c8dfb1d97957e8acfbde1026a334974874d08374ff6f03eb1c5ec6eeec409bca0a3443004b4d6f1126f122cd6672cfd911767fb5b54fb8c3190d4a02f8478ce7aa223ac4ef20f45c08f2d44801efa21a9914f103a82c0eeb00fc7ae34beca20b159f35f7b83877ec044fe786de6aaa8a41be033955dacb90aded1f681226d961c9283ef30eeacddf64974f14ebe08b961b9d57071387dfdb92b7d,
          #pkcs1v1_5,
        );
        expectedBytes = "\05\7B\BB\5B\51\4E\08\C0\EC\C1\04\C8\D1\4D\42\37\BF\7F\3A\AA\43\75\DF\39\43\6A\03\94\A5\B2\F3\66\D3\3F\9C\FF\4D\45\82\D8\58\F0\82\40\9C\ED\F8\91\DC\CA\89\52\DA\79\76\2C\E4\B2\F4\98\EE\C8\BB\E5\D0\4D\0C\B9\F8\14\A4\56\51\49\72\31\EF\E0\63\2A\78\08\56\F9\9A\39\CE\74\59\54\AB\5B\A8\6B\7B\B1\58\34\B1\1E\81\8C\8D\FB\1D\97\95\7E\8A\CF\BD\E1\02\6A\33\49\74\87\4D\08\37\4F\F6\F0\3E\B1\C5\EC\6E\EE\C4\09\BC\A0\A3\44\30\04\B4\D6\F1\12\6F\12\2C\D6\67\2C\FD\91\17\67\FB\5B\54\FB\8C\31\90\D4\A0\2F\84\78\CE\7A\A2\23\AC\4E\F2\0F\45\C0\8F\2D\44\80\1E\FA\21\A9\91\4F\10\3A\82\C0\EE\B0\0F\C7\AE\34\BE\CA\20\B1\59\F3\5F\7B\83\87\7E\C0\44\FE\78\6D\E6\AA\A8\A4\1B\E0\33\95\5D\AC\B9\0A\DE\D1\F6\81\22\6D\96\1C\92\83\EF\30\EE\AC\DD\F6\49\74\F1\4E\BE\08\B9\61\B9\D5\70\71\38\7D\FD\B9\2B\7D";
        outputByteEncoding = #raw;
        inputByteEncoding = #raw({ paddingAlgorithm = #pkcs1v1_5 });
      },
      {
        signature = Signature.Signature(
          0x2dc538b2908432f33c82577abf2c748e12df77d4fa2d826791a75d2aaefb11d9191ebd5d569c38140943b632eb1a471d00fee28c063ef404b5b4e7df265653543069c4775b7913da042c552c87202da8121fa8795efb2d6f108eb95336e2b1111091bade2e8cfc37a8790fa79ff5d2ed69dfb6887db2b45517421eee8b6a06f34f717a7c99dabf3d9409c898ca1cb9a6bb306599e60b194a17b1e9ece1fecf9f75235b8db60c2405895c7cd145184c70a9aaacad9ae1c70a51201e7d0b52f2851d46c870f44d244093acf63e6fb9bd78e780bd9862300a03de9388d4b8bb7a0f505b338dbc30b9d23afbb121966f8a825ad2649d7156d63b61e67e58ab5831dc,
          #pkcs1v1_5,
        );
        expectedBytes = "\2D\C5\38\B2\90\84\32\F3\3C\82\57\7A\BF\2C\74\8E\12\DF\77\D4\FA\2D\82\67\91\A7\5D\2A\AE\FB\11\D9\19\1E\BD\5D\56\9C\38\14\09\43\B6\32\EB\1A\47\1D\00\FE\E2\8C\06\3E\F4\04\B5\B4\E7\DF\26\56\53\54\30\69\C4\77\5B\79\13\DA\04\2C\55\2C\87\20\2D\A8\12\1F\A8\79\5E\FB\2D\6F\10\8E\B9\53\36\E2\B1\11\10\91\BA\DE\2E\8C\FC\37\A8\79\0F\A7\9F\F5\D2\ED\69\DF\B6\88\7D\B2\B4\55\17\42\1E\EE\8B\6A\06\F3\4F\71\7A\7C\99\DA\BF\3D\94\09\C8\98\CA\1C\B9\A6\BB\30\65\99\E6\0B\19\4A\17\B1\E9\EC\E1\FE\CF\9F\75\23\5B\8D\B6\0C\24\05\89\5C\7C\D1\45\18\4C\70\A9\AA\AC\AD\9A\E1\C7\0A\51\20\1E\7D\0B\52\F2\85\1D\46\C8\70\F4\4D\24\40\93\AC\F6\3E\6F\B9\BD\78\E7\80\BD\98\62\30\0A\03\DE\93\88\D4\B8\BB\7A\0F\50\5B\33\8D\BC\30\B9\D2\3A\FB\B1\21\96\6F\8A\82\5A\D2\64\9D\71\56\D6\3B\61\E6\7E\58\AB\58\31\DC";
        outputByteEncoding = #raw;
        inputByteEncoding = #raw({ paddingAlgorithm = #pkcs1v1_5 });
      },
    ];

    // Run all the test cases
    for (testCase in cases.vals()) {
      let actualBytes = testCase.signature.toBytes(testCase.outputByteEncoding);
      let actualBlob = Blob.fromArray(actualBytes);
      if (actualBlob != testCase.expectedBytes) {
        Runtime.trap(
          "Signature toBytes failed:\nExpected\n" # debug_show testCase.expectedBytes # "\nActual\n" # debug_show actualBlob
        );
      };
      let actualSignature = switch (Signature.fromBytes(actualBytes.vals(), testCase.inputByteEncoding)) {
        case (#err(e)) Runtime.trap("Signature fromBytes failed: " # e);
        case (#ok(signature)) signature;
      };
      if (not testCase.signature.equal(actualSignature)) {
        Runtime.trap(
          "Signature fromBytes failed:\nExpected\n" # debug_show testCase.signature.value # "\nActual\n" # debug_show actualSignature.value
        );
      }

    };
  },
);
