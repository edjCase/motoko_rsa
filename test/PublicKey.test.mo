import { test } "mo:test";
import Runtime "mo:new-base/Runtime";
import Blob "mo:new-base/Blob";
import PublicKey "../src/PublicKey";
import Signature "../src/Signature";

type TestCase = {
  key : PublicKey.PublicKey;
  signature : Signature.Signature;
  message : Blob;
};

test(
  "RSA Public Key Tests",
  func() {
    // Test cases
    let cases : [TestCase] = [{
      key = PublicKey.PublicKey(
        0x10001,
        0xc4d62eb9f7850c25b3215434ed5cc1bcd9dff6951b9f1a49c03e055f6031f92a60efd2f99d4ef9051bc3a86a0fbc34b8786638ebcbb80d7c1cc4e9de0fa67cf750651d58e24d8fba82ab973d00be0178fe2b42ed8a7a39b9564d1507c5dd5d4c7d8b0dc3f6a6e70f87ad7248baa96d8d3f396eb90c3ce7382ffddf8a34270fc9f,
      );
      signature = Signature.Signature(
        0x2d513f7fe25adeb050bfdb57a9f6ec254f6528f84a178ba2d93d0e4b46c88d9ca1c8a11e8ac2fb5fb956c4ebffcc9eb32d8dbbcc82a6f592b7d11a3cd71f97b74ea4ab7b3c5bc72fc2d66d242c5381dba5f0a16de8bba7fc7e93b79b8ddec0e06faf8a4e1176e90aa6c7ae19aec335d1b85c918d7a88bb0d7c0c1ba5cce6a3eaeaa49ae3c09d95a38f156bb2a7de40cb9fd32fe5d6ceb4d7af6cf34ab9bd0bfaad2c156f2f0d1a2fafc5a0f53b4c40c6401d90c172a3cb89df0cb6a54e03c0e79f65af1c647ab60b86e19d9d1c45d3f35eb39ef14dcc8b6b2e9f49fe1ef9ee0aef0f7d0d73d368f8fe3b2a21e0bcb8
      );
      message = "\48\65\6c\6c\6f\2c\20\77\6f\72\6c\64\21"; // "Hello, world!"
    }];

    // Run all the test cases
    for (testCase in cases.vals()) {
      let isValid = testCase.key.verify(testCase.message.vals(), testCase.signature, #sha256);
      if (not isValid) Runtime.trap("Signature verification failed\nKey: " # testCase.key.toText(#hex({ format = { isUpper = true; prefix = #none }; byteEncoding = #spki })) # "\nSignature: " # debug_show (testCase.signature.value) # "\nMessage: " # debug_show testCase.message);
    };
  },
);
