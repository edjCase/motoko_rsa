import PublicKeyModule "./PublicKey";
import SignatureModule "./Signature";
import Iter "mo:base/Iter";
import Result "mo:new-base/Result";

module {
    public type PublicKey = PublicKeyModule.PublicKey;

    public func PublicKey(
        e : Nat,
        n : Nat,
    ) : PublicKey = PublicKeyModule.PublicKey(e, n);

    public func publicKeyFromBytes(
        bytes : Iter.Iter<Nat8>,
        encoding : PublicKeyModule.InputByteEncoding,
    ) : Result.Result<PublicKey, Text> = PublicKeyModule.fromBytes(bytes, encoding);

    public func publicKeyFromText(
        text : Text,
        encoding : PublicKeyModule.InputTextFormat,
    ) : Result.Result<PublicKey, Text> = PublicKeyModule.fromText(text, encoding);

    public type Signature = SignatureModule.Signature;

};
