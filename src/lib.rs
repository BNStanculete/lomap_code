// Copyright Bogdan Stanculete 2026. All Rights Reserved.

use structopt::StructOpt;
use winterfell::{
    math::fields::f252::BaseElement,
    BatchingMethod, FieldExtension, Proof, ProofOptions, VerifierError
};

pub mod sha256;

mod utils;

#[cfg(test)]
mod tests;

// TYPES AND INTERFACES
// ================================================================================================

pub type Blake3_256 = winterfell::crypto::hashers::Blake3_256<BaseElement>;

pub trait Provable {
    fn prove(&self) -> Proof;
}

pub trait Verifiable {
    fn verify(&self, proof: Proof) -> Result<(), VerifierError>;
}

pub trait Testable: Provable + Verifiable {}

// PROTOCOL OPTIONS
// ================================================================================================

#[derive(StructOpt, Debug)]
#[structopt(name = "lomap", about = "Lomap protocol options")]
pub struct ProtocolOptions {
    /// Number of queries to include in a proof
    #[structopt(short = "q", long = "queries")]
    num_queries: Option<usize>,

    /// Blowup factor for low degree extension
    #[structopt(short = "b", long = "blowup")]
    blowup_factor: Option<usize>,

    /// Folding factor for FRI protocol
    #[structopt(short = "f", long = "folding", default_value = "8")]
    folding_factor: usize,
}

impl ProtocolOptions {
    pub fn to_proof_options(&self, q: usize, b: usize) -> ProofOptions {
        let num_queries = self.num_queries.unwrap_or(q);
        let blowup_factor = self.blowup_factor.unwrap_or(b);

        ProofOptions::new(
            num_queries,
            blowup_factor,
            0,
            FieldExtension::None,
            self.folding_factor,
            31,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        )
    }

    /// Returns the conjectured security level of the input proof in bits.
    pub fn get_proof_security_level_conjectured(&self, proof: &Proof) -> u32 {
        proof.conjectured_security::<Blake3_256>().bits()
    }

    /// Returns the proven security level of the input proof in bits.
    pub fn get_proof_security_level_proven(&self, proof: &Proof) -> (u32, u32) {
        let security_level = proof.proven_security::<Blake3_256>();

        (security_level.ldr_bits(), security_level.udr_bits())
    }
}
