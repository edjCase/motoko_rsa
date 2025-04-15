import Nat "mo:base/Nat";
import Nat8 "mo:base/Nat8";
import Iter "mo:base/Iter";
import Result "mo:base/Result";
import ASN1 "mo:asn1";
import Sha256 "mo:sha2/Sha256";
import Int "mo:new-base/Int";
import Signature "./Signature";

module {
    public type HashAlgorithm = Sha256.Algorithm;

    public type InputByteEncoding = {
        #spki;
        #pkcs1;
    };

    public type OutputByteEncoding = {
        #spki;
        #pkcs1;
    };

    let RSA_OID = [1, 2, 840, 113549, 1, 1, 1];

    public class PublicKey(
        exponent_ : Nat,
        modulus_ : Nat,
    ) {
        public let exponent = exponent_;
        public let modulus = modulus_;

        public func equal(other : PublicKey) : Bool {
            return exponent == other.exponent and modulus == other.modulus;
        };

        // Verify a message signature using this public key
        public func verify(
            msg : Iter.Iter<Nat8>,
            signature : Signature.Signature,
            hashAlgorithm : HashAlgorithm,
        ) : Bool {
            // Hash the message
            let hashedMsg = Sha256.fromIter(hashAlgorithm, msg);
            verifyHashed(hashedMsg.vals(), signature);
        };

        public func verifyHashed(
            hashedMsg : Iter.Iter<Nat8>,
            signature : Signature.Signature,
        ) : Bool {
            let hashBytes = switch (signature.getHashValue(exponent, modulus)) {
                case (#err(_)) return false;
                case (#ok(hashBytes)) hashBytes;
            };
            let hashBytesIter = hashBytes.vals();
            for (byte in hashedMsg) {
                let otherByte = hashBytesIter.next();
                if (?byte != otherByte) {
                    return false;
                };
            };
            hashBytesIter.next() == null; // Ensure all bytes were consumed
        };

        // Export public key in PKCS#1 format
        public func toBytes(encoding : OutputByteEncoding) : [Nat8] {
            switch (encoding) {
                case (#pkcs1) ASN1.encodeDER(#sequence([#integer(modulus), #integer(exponent)]));
                case (#spki) {
                    let pkcs1Bytes = toBytes(#pkcs1);

                    // Create ASN.1 structure for SPKI
                    let spki : ASN1.ASN1Value = #sequence([
                        #sequence([
                            #objectIdentifier(RSA_OID),
                            #null_,
                        ]),
                        #bitString({
                            data = pkcs1Bytes;
                            unusedBits = 0;
                        }),
                    ]);

                    ASN1.encodeDER(spki);
                };
            };

        };
    };

    // Create a public key from PKCS#1 encoded data
    public func fromBytes(bytes : Iter.Iter<Nat8>, encoding : InputByteEncoding) : Result.Result<PublicKey, Text> {
        let asn1 = switch (ASN1.decodeDER(bytes)) {
            case (#err(msg)) #err("Failed to decode PKCS#1 data: " # msg);
            case (#ok(asn1)) asn1;
        };
        switch (encoding) {
            case (#pkcs1) {
                let #sequence(seq) = asn1 else {
                    return #err("PKCS#1 data is not a SEQUENCE");
                };

                if (seq.size() != 2) {
                    return #err("PKCS#1 SEQUENCE should have 2 elements");
                };

                let #integer(modulus) = seq[0] else {
                    return #err("Modulus is not an INTEGER");
                };

                let #integer(exponent) = seq[1] else {
                    return #err("Exponent is not an INTEGER");
                };

                #ok(PublicKey(Int.abs(exponent), Int.abs(modulus)));
            };
            case (#spki) {
                let #sequence(seq) = asn1 else {
                    return #err("SPKI data is not a SEQUENCE");
                };

                if (seq.size() != 2) {
                    return #err("SPKI SEQUENCE should have 2 elements");
                };

                // Check algorithm identifier
                let #sequence(algoSeq) = seq[0] else {
                    return #err("Algorithm identifier is not a SEQUENCE");
                };

                if (algoSeq.size() < 1) {
                    return #err("Algorithm identifier SEQUENCE is empty");
                };

                let #objectIdentifier(algoOid) = algoSeq[0] else {
                    return #err("Algorithm identifier does not contain an OID");
                };

                if (algoOid != RSA_OID) {
                    return #err("Unsupported algorithm: not RSA");
                };

                // Extract key data
                let #bitString(keyData) = seq[1] else {
                    return #err("Key data is not a BIT STRING");
                };

                fromBytes(keyData.data.vals(), #pkcs1);
            };
        };
    };
};
