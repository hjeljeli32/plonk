use ark_ec::pairing::{Pairing, PairingOutput};

/// Extracts the inner field element from a pairing output.
pub fn pairing_value<P: Pairing>(output: &PairingOutput<P>) -> &P::TargetField {
    &output.0
}

/// Computes the product of two pairing outputs.
pub fn pairing_product<P: Pairing>(a: &PairingOutput<P>, b: &PairingOutput<P>) -> P::TargetField {
    a.0 * b.0
}
