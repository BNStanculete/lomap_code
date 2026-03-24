// Copyright Bogdan Stanculete 2026. All Rights Reserved.

use core::marker::PhantomData;

use tracing::{field, info_span};
use winterfell::{
    crypto::{DefaultRandomCoin, ElementHasher, MerkleTree},
    math::{fields::f252::BaseElement, FieldElement},
    Proof, ProofOptions, Prover, Trace, VerifierError,
};

use crate::{
    Verifiable, Provable, Testable,
    Blake3_256
};

mod air;
use air::{PublicInputs,Sha256Air};

mod prover;
use prover::Sha256Prover;

mod constraints;
mod constants;

#[cfg(test)]
mod tests;

// TRACE CONSTANTS
// ================================================================================================

pub const CYCLE_LENGTH: usize = 177;
pub const TRACE_WIDTH: usize = 269;

// SHA-256
// ================================================================================================

pub struct Sha256 {
    options: ProofOptions,

    columns: Vec<Vec<BaseElement>>,
    num_blocks: usize,
    result: [BaseElement; 8],
}

impl Sha256 {
    pub fn new(
        options: ProofOptions,
        columns: Vec<Vec<BaseElement>>,
        num_blocks: usize,
        result: [BaseElement; 8]) -> Self {
        Sha256 {
            options,
            columns,
            num_blocks,
            result: result,
        }
    }
}

// SHA-256 IMPLEMENTATION
// ================================================================================================

impl Verifiable for Sha256 {
    fn verify(&self, proof: Proof) -> Result<(), VerifierError> {
        let trace_size: u64 = (CYCLE_LENGTH * self.num_blocks + 5) as u64;
        let acceptable_options = winterfell::AcceptableOptions::OptionSet(vec![proof.options().clone()]);
        let pub_inputs = PublicInputs { expected_length: BaseElement::from(trace_size),
                                        result: self.result };

        winterfell::verify::<Sha256Air, Blake3_256, DefaultRandomCoin<Blake3_256>, MerkleTree<Blake3_256>>(
            proof,
            pub_inputs,
            &acceptable_options
        )
    }
}

impl Provable for Sha256 {
    fn prove(&self) -> Proof {
        println!("Generating proof for computing a hash of {} blocks. ", self.num_blocks);

        // Create a new prover
        let prover = Sha256Prover::<Blake3_256>::new(self.options.clone());

        // Generate execution trace
        let trace =
            info_span!("generate_execution_trace", num_cols = TRACE_WIDTH, steps = field::Empty)
                .in_scope(|| {
                    let trace = prover.build_trace(self.columns.clone());
                    tracing::Span::current().record("steps", trace.length());
                    trace
                });

        // generate the proof
        prover.prove(trace).unwrap()
    }
}

impl Testable for Sha256 {}
