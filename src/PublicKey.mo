import Iter "mo:base/Iter";
import Result "mo:new-base/Result";
import Text "mo:new-base/Text";
import Int "mo:new-base/Int";
import Runtime "mo:new-base/Runtime";
import Blob "mo:base/Blob";
import Buffer "mo:base/Buffer";
import Nat "mo:base/Nat";
import Nat8 "mo:base/Nat8";
import BaseX "mo:base-x-encoder";
import ASN1 "mo:asn1";
import Signature "./Signature";
import Sha256 "mo:sha2/Sha256";
import PeekableIter "mo:itertools/PeekableIter";
import IterTools "mo:itertools/Iter";
import NatX "mo:xtended-numbers/NatX";

module Module {
    // Input/Output byte encoding types
    public type PEMInputByteEncoding = {
        #pkcs1; // PKCS#1 format
        #spki; // Subject Public Key Info format
    };

    public type InputByteEncoding = PEMInputByteEncoding; // TODO raw?

    public type PEMOutputEncoding = {
        #pkcs1; // PKCS#1 format
        #spki; // Subject Public Key Info format
    };

    public type OutputByteEncoding = PEMOutputEncoding; // TODO raw?

    public type OutputTextFormat = {
        #base64 : {
            byteEncoding : OutputByteEncoding;
            isUriSafe : Bool;
        };
        #hex : {
            byteEncoding : OutputByteEncoding;
            format : BaseX.HexOutputFormat;
        };
        #jwk;
        #pem : {
            byteEncoding : PEMOutputEncoding;
        };
    };

    public type InputTextFormat = {
        #base64 : {
            byteEncoding : InputByteEncoding;
        };
        #hex : {
            byteEncoding : InputByteEncoding;
            format : BaseX.HexInputFormat;
        };
        #pem : {
            byteEncoding : PEMInputByteEncoding;
        };
    };

    public type BitLength = { #b2048; #b4096 };

    public type HashAlgorithm = Sha256.Algorithm;

    public type PaddingAlgorithm = {
        #pkcs1v1_5;
        // #pss; TODO
    };

    public class PublicKey(
        exponent_ : Nat, // Public exponent
        modulus_ : Nat, // Modulus
    ) {
        public let exponent = exponent_;
        public let modulus = modulus_;
        var bitLengthCache : ?BitLength = null;

        public func equal(other : PublicKey) : Bool {
            return exponent == other.exponent and modulus == other.modulus;
        };

        // Verify a message signature using this public key
        public func verify(
            msg : Iter.Iter<Nat8>,
            signature : Signature.Signature,
            hashAlgorithm : HashAlgorithm,
            paddingAlgorithm : PaddingAlgorithm,
        ) : Bool {
            let hashedMsg = Sha256.fromIter(hashAlgorithm, msg);
            verifyHashed(hashedMsg.vals(), signature, paddingAlgorithm);
        };

        // Verify a pre-hashed message
        public func verifyHashed(
            hashedMsg : Iter.Iter<Nat8>,
            signature : Signature.Signature,
            paddingAlgorithm : PaddingAlgorithm,
        ) : Bool {
            return false; // TODO
        };

        // Convert to various formats
        public func toText(format : OutputTextFormat) : Text {
            switch (format) {
                case (#hex(hex)) {
                    let bytes = toBytes(hex.byteEncoding);
                    BaseX.toHex(bytes.vals(), hex.format);
                };
                case (#base64(base64)) {
                    let bytes = toBytes(base64.byteEncoding);
                    BaseX.toBase64(bytes.vals(), base64.isUriSafe);
                };
                case (#pem({ byteEncoding })) {
                    let bytes = toBytes(byteEncoding);
                    let keyType = switch (byteEncoding) {
                        case (#pkcs1) ("RSA PUBLIC");
                        case (#spki) ("PUBLIC");
                    };
                    let base64 = BaseX.toBase64(bytes.vals(), false);

                    let iter = PeekableIter.fromIter(base64.chars());
                    var formatted = Text.fromIter(IterTools.take(iter, 64));
                    while (iter.peek() != null) {
                        formatted #= "\n" # Text.fromIter(IterTools.take(iter, 64));
                    };

                    "-----BEGIN " # keyType # " KEY-----\n" # formatted # "\n-----END " # keyType # " KEY-----\n";
                };
                case (#jwk) {
                    // Convert the modulus and exponent to base64url
                    let nBytes = toBigEndian(modulus);
                    let eBytes = toBigEndian(exponent);

                    let nB64 = BaseX.toBase64(nBytes.vals(), true);
                    let eB64 = BaseX.toBase64(eBytes.vals(), true);

                    let alg = switch (getBitLength()) {
                        case (#b2048) "RS256";
                        case (#b4096) "RS512";
                    };

                    // Format as JWK JSON
                    "{\"kty\":\"RSA\",\"n\":\"" # nB64 # "\",\"e\":\"" # eB64 # "\",\"alg\":\"" # alg # "\"}";
                };
            };

        };

        private func getBitLength() : BitLength {
            switch (bitLengthCache) {
                case (?bitLength) bitLength;
                case (null) {
                    let bitLength = if (modulus < 2 ** 2048) {
                        #b2048;
                    } else if (modulus < 2 ** 4096) {
                        #b4096;
                    } else Runtime.trap("Bit length above 4096 not supported");
                    bitLengthCache := ?bitLength;
                    bitLength;
                };
            };
        };

        public func toBytes(encoding : OutputByteEncoding) : [Nat8] {
            switch (encoding) {
                case (#pkcs1) {
                    // PKCS#1 format - RSA Public Key
                    let asn1 : ASN1.ASN1Value = #sequence([
                        #integer(modulus), // Modulus
                        #integer(exponent) // Public exponent
                    ]);

                    ASN1.encodeDER(asn1);
                };
                case (#spki) {
                    // Subject Public Key Info format

                    // Inner PKCS#1 key structure
                    let pkcs1Bytes = toBytes(#pkcs1);

                    // Wrap in Subject Public Key Info structure
                    let asn1 : ASN1.ASN1Value = #sequence([
                        #sequence([
                            #objectIdentifier([1, 2, 840, 113549, 1, 1, 1]), // Algorithm
                            #null_ // Parameters
                        ]),
                        #octetString(pkcs1Bytes) // Key data
                    ]);

                    ASN1.encodeDER(asn1);
                };
            };
        };
    };

    public func fromBytes(bytes : Iter.Iter<Nat8>, encoding : InputByteEncoding) : Result.Result<PublicKey, Text> {
        switch (encoding) {
            case (#pkcs1) {
                // Parse PKCS#1 RSA public key
                let asn1 = switch (ASN1.decodeDER(bytes)) {
                    case (#err(e)) return #err("Invalid DER format: " # e);
                    case (#ok(asn1)) asn1;
                };

                let #sequence(sequence) = asn1 else return #err("Invalid PKCS#1 format: expected sequence");

                if (sequence.size() != 2) {
                    return #err("Invalid PKCS#1 format: expected sequence with 2 elements");
                };

                let #integer(n) = sequence[0] else return #err("Invalid PKCS#1 format: expected integer for modulus");
                let #integer(e) = sequence[1] else return #err("Invalid PKCS#1 format: expected integer for exponent");

                if (n <= 0 or e <= 0) {
                    return #err("Invalid RSA key: negative or zero values");
                };

                // Create RSA public key
                #ok(PublicKey(Int.abs(e), Int.abs(n)));
            };
            case (#spki) {
                // Parse PKCS#8 public key info
                let asn1 = switch (ASN1.decodeDER(bytes)) {
                    case (#err(e)) return #err("Invalid DER format: " # e);
                    case (#ok(asn1)) asn1;
                };

                let #sequence(sequence) = asn1 else return #err("Invalid PKCS#8 format: expected sequence");

                if (sequence.size() < 3) {
                    return #err("Invalid PKCS#8 format: expected sequence with at least 3 elements");
                };

                // Check algorithm identifier
                let #sequence(algorithmSeq) = sequence[1] else return #err("Invalid PKCS#8 format: expected algorithm sequence");
                let #objectIdentifier(algorithmOid) = algorithmSeq[0] else return #err("Invalid PKCS#8 format: expected algorithm OID");

                // Verify it's RSA
                let rsaOID : [Nat] = [1, 2, 840, 113549, 1, 1, 1]; // RSA encryption OID
                var isRSA = true;

                if (algorithmOid.size() != rsaOID.size()) {
                    isRSA := false;
                } else {
                    for (i in Iter.range(0, rsaOID.size() - 1)) {
                        if (i < algorithmOid.size() and algorithmOid[i] != rsaOID[i]) {
                            isRSA := false;
                        };
                    };
                };

                if (not isRSA) {
                    return #err("Invalid PKCS#8 format: not an RSA key");
                };

                // Extract key bytes
                let #octetString(keyBytes) = sequence[2] else return #err("Invalid PKCS#8 format: expected key bytes");

                // Parse inner PKCS#1 structure
                fromBytes(keyBytes.vals(), #pkcs1);
            };
        };
    };

    public func fromText(value : Text, format : InputTextFormat) : Result.Result<PublicKey, Text> {
        switch (format) {
            case (#hex({ format; byteEncoding })) {
                // Convert hex to bytes
                switch (BaseX.fromHex(value, format)) {
                    case (#ok(bytes)) {
                        switch (fromBytes(bytes.vals(), byteEncoding)) {
                            case (#ok(key)) #ok(key);
                            case (#err(e)) #err("Invalid key bytes: " # e);
                        };
                    };
                    case (#err(e)) #err("Invalid hex format: " # e);
                };
            };

            case (#base64({ byteEncoding })) {
                // Convert base64 to bytes
                switch (BaseX.fromBase64(value)) {
                    case (#ok(bytes)) {
                        switch (fromBytes(bytes.vals(), byteEncoding)) {
                            case (#ok(key)) #ok(key);
                            case (#err(e)) #err("Invalid key bytes: " # e);
                        };
                    };
                    case (#err(e)) #err("Invalid base64 format: " # e);
                };
            };

            case (#pem({ byteEncoding })) {
                let keyType = switch (byteEncoding) {
                    case (#pkcs1) "RSA PUBLIC";
                    case (#spki) "PUBLIC";
                };
                // Parse PEM format
                switch (extractPEMContent(value, keyType)) {
                    case (#ok(base64Content)) {
                        switch (BaseX.fromBase64(base64Content)) {
                            case (#ok(bytes)) {
                                switch (fromBytes(bytes.vals(), byteEncoding)) {
                                    case (#ok(key)) #ok(key);
                                    case (#err(e)) #err("Invalid key bytes: " # e);
                                };
                            };
                            case (#err(e)) #err("Failed to decode PEM base64: " # e);
                        };
                    };
                    case (#err(e)) #err(e);
                };
            };
        };
    };

    // Helper function to extract content from PEM format for public keys
    private func extractPEMContent(pem : Text, keyType : Text) : Result.Result<Text, Text> {
        let header = "-----BEGIN " # keyType # " KEY-----";
        let ?headerTrimmedPem = Text.stripStart(pem, #text(header)) else return #err("Invalid PEM format: missing header " # header);
        let footer = "-----END " # keyType # " KEY-----\n";
        let ?trimmedPem = Text.stripEnd(headerTrimmedPem, #text(footer)) else return #err("Invalid PEM format: missing footer " # footer);
        #ok(Text.join("", Text.split(trimmedPem, #char('\n'))));
    };

    private func toBigEndian(value : Nat) : [Nat8] {
        let buffer = Buffer.Buffer<Nat8>(4);
        NatX.encodeNat(buffer, value, #msb);
        Buffer.toArray<Nat8>(buffer);
    };

};
