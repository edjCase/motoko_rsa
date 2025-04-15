import Nat "mo:new-base/Nat";

module {
    public class Signature(value_ : Nat) {
        public let value = value_;

        public func equal(other : Signature) : Bool {
            return value == other.value;
        };
    };
};
