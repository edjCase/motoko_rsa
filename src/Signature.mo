import Nat "mo:base/Nat";
import Nat8 "mo:base/Nat8";
import Buffer "mo:base/Buffer";
import NatX "mo:xtended-numbers/NatX";
import Sha256 "mo:sha2/Sha256";
import Iter "mo:new-base/Iter";
import Result "mo:new-base/Result";
import ASN1 "mo:asn1";

module {
    public type OutputByteEncoding = {
        #raw;
    };
    public type HashAlgorithm = Sha256.Algorithm;
    public type PaddingAlgorithm = {
        #pkcs1v1_5;
        // #pss; TODO
    };

    public class Signature(
        value_ : Nat,
        paddingAlgorithm_ : PaddingAlgorithm,
    ) {
        public let value = value_;
        public let paddingAlgorithm = paddingAlgorithm_;

        public func equal(other : Signature) : Bool {
            return value == other.value;
        };

        public func getHashValue(
            exponent : Nat,
            modulus : Nat,
        ) : Result.Result<[Nat8], Text> {
            // RSA decryption (signature verification)
            let sigDecrypted = modExp(value, exponent, modulus);

            // Convert decrypted signature to bytes
            let decryptedBuffer = Buffer.Buffer<Nat8>(256);
            NatX.encodeNat(decryptedBuffer, sigDecrypted, #msb);

            // Use ASN.1 library to decode the PKCS#1 v1.5 formatted data
            switch (paddingAlgorithm_) {
                case (#pkcs1v1_5) switch (decodePKCS1Signature(decryptedBuffer.vals())) {
                    case (#err(e)) return #err("Failed to decode PKCS#1 v1.5 signature: " # e);
                    case (#ok((hashBytes, _))) #ok(hashBytes);
                };
            };

        };

        // Convert signature to bytes array (big-endian)
        public func toBytes(encoding : OutputByteEncoding) : [Nat8] {
            let buffer = Buffer.Buffer<Nat8>(256);
            switch (encoding) {
                case (#raw) NatX.encodeNat(buffer, value, #msb);
            };
            return Buffer.toArray(buffer);
        };
    };

    // Modular exponentiation (a^b mod n)
    private func modExp(base : Nat, exp : Nat, mod : Nat) : Nat {
        var result : Nat = 1;
        var power : Nat = base % mod;
        var exponent : Nat = exp;

        while (exponent > 0) {
            if (exponent % 2 == 1) {
                result := (result * power) % mod;
            };
            exponent := exponent / 2;
            power := (power * power) % mod;
        };

        return result;
    };

    // Helper function to decode PKCS#1 v1.5 signature and extract the hash
    private func decodePKCS1Signature(bytes : Iter.Iter<Nat8>) : Result.Result<([Nat8], HashAlgorithm), Text> {
        // Expected format:
        // 0x00 || 0x01 || PS || 0x00 || T
        // where PS is a padding string of 0xFF bytes
        // and T is the DER encoding of the DigestInfo structure

        // Check magic bytes
        if (bytes.next() != ?0x00 or bytes.next() != ?0x01) {
            return #err("Invalid PKCS#1 v1.5 signature format");
        };
        // Skip padding bytes (0xFF)
        while (bytes.next() == ?0xFF)();

        // Check for the separator byte (0x00)
        if (bytes.next() != ?0x00) {
            return #err("Invalid PKCS#1 v1.5 padding");
        };

        // Decode the DigestInfo using ASN.1 library
        let digestInfo = switch (ASN1.decodeDER(bytes)) {
            case (#err(msg)) return #err("Failed to decode DigestInfo: " # msg);
            case (#ok(digestInfo)) digestInfo;
        };
        // DigestInfo should be a SEQUENCE with:
        // - digestAlgorithm (SEQUENCE)
        // - digest (OCTET STRING)

        let #sequence(digestInfoSeq) = digestInfo else {
            return #err("DigestInfo is not a SEQUENCE");
        };

        if (digestInfoSeq.size() != 2) {
            return #err("DigestInfo SEQUENCE should have 2 elements");
        };

        // Check algorithm identifier
        let #sequence(algorithmSeq) = digestInfoSeq[0] else {
            return #err("Algorithm identifier is not a SEQUENCE");
        };

        if (algorithmSeq.size() < 1) {
            return #err("Algorithm identifier SEQUENCE is empty");
        };

        let #objectIdentifier(algorithmOid) = algorithmSeq[0] else {
            return #err("Algorithm identifier does not contain an OID");
        };

        let algorithm : HashAlgorithm = if (algorithmOid == [2, 16, 840, 1, 101, 3, 4, 2, 1]) {
            #sha256;
        } else {
            return #err("Unsupported hash algorithm: " # debug_show (algorithmOid));
        };

        // Extract the hash
        let #octetString(hash) = digestInfoSeq[1] else {
            return #err("Digest value is not an OCTET STRING");
        };

        return #ok((hash, algorithm));
    };

};
