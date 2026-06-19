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
use air::{PublicInputs, CRLUpdateAir};

mod prover;
use prover::CRLUpdateProver;

mod constraints;
mod constants;

#[cfg(test)]
mod tests;

// TRACE CONSTANTS
// ================================================================================================

pub const CYCLE_LENGTH: usize = 256;
pub const TRACE_WIDTH: usize = 402;

// CRLUpdate Proof
// ================================================================================================

// Generation requires only options & trace columns
pub struct CRLUpdateProvable {
    options: ProofOptions,
    columns: Vec<Vec<BaseElement>>,
}

impl CRLUpdateProvable {
    pub fn new(
        options: ProofOptions,
        columns: Vec<Vec<BaseElement>>) -> Self {
        CRLUpdateProvable {
            options,
            columns
        }
    }
}

// Verification takes separately the public inputs and a claimed height
pub struct CRLUpdateVerifiable {
    options: ProofOptions,
    trace_size: u64
}

impl CRLUpdateVerifiable {
    pub fn new(
        options: ProofOptions,
        trace_size: u64) -> Self {
        CRLUpdateVerifiable {
            options,
            trace_size
        }
    }
}

// CRLUpdate IMPLEMENTATION
// ================================================================================================

impl Verifiable for CRLUpdateVerifiable {
    fn verify(&self, proof: Proof) -> Result<(), VerifierError> {
        let acceptable_options = winterfell::AcceptableOptions::OptionSet(vec![proof.options().clone()]);
        let pub_inputs = PublicInputs { expected_length: BaseElement::from(self.trace_size) };

        winterfell::verify::<CRLUpdateAir, Blake3_256, DefaultRandomCoin<Blake3_256>, MerkleTree<Blake3_256>>(
            proof,
            pub_inputs,
            &acceptable_options
        )
    }
}

impl Provable for CRLUpdateProvable {
    fn prove(&self) -> Proof {
        // Create a new prover
        let prover = CRLUpdateProver::<Blake3_256>::new(self.options.clone());

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
