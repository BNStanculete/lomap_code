// Copyright Bogdan Stanculete 2026. All Rights Reserved.

use std::time::Instant;

use tracing::{field, info_span};
use winterfell::{
    crypto::{DefaultRandomCoin, ElementHasher, MerkleTree},
    math::{fields::f252::BaseElement, FieldElement},
    Proof, ProofOptions, Prover, Trace, VerifierError,
};

use sha2;
use sha2::Digest;

use crate::{
    utils::to_base_element,
    Verifiable, Provable,
    Blake3_256
};

mod air;
use air::{PublicInputs,Sha256Air};

// mod prover;
// use prover::Sha256Prover;

mod constants;

#[cfg(test)]
mod tests;

// CONSTANTS
// ======================================================================================

const CYCLE_LENGTH: usize = 177;
const PADDED_CYCLE_LENGTH: usize = 256;
const TRACE_WIDTH: usize = 271;

// SHA-256
// ======================================================================================

pub struct Sha256 {
    options: ProofOptions,

    message_bytes: Vec<u8>,
    num_blocks: usize,
    result: [BaseElement; 8],
}

impl Sha256 {
    pub fn new(message_bytes: Vec<u8>, options: ProofOptions) -> Self {
        let num_blocks: usize = message_bytes.len() / 512 + 1;
        let mut hasher = sha2::Sha256::new();

        let now = Instant::now();

        hasher.update(message_bytes.as_slice());
        let sha_result = hasher.finalize();
        let result: [BaseElement; 8] = from_digest(sha_result.as_slice()).try_into().expect("Vec must have exactly 8 elements");

        println!(
            "Computed a hash of {} blocks in {} ms.",
            num_blocks,
            now.elapsed().as_millis(),
        );

        Sha256 {
            options,
            message_bytes,
            num_blocks,
            result: result,
        }
    }
}

// SHA-256 IMPLEMENTATION
// ===============================================================================

impl Verifiable for Sha256 {
    fn verify(&self, proof: Proof) -> Result<(), VerifierError> {
        let trace_size = 177 * self.num_blocks + 4;
        let acceptable_options = winterfell::AcceptableOptions::OptionSet(vec![proof.options().clone()]);
        let pub_inputs = PublicInputs { expected_length: trace_size.next_power_of_two(), result: self.result };

        winterfell::verify::<Sha256Air, Blake3_256, DefaultRandomCoin<Blake3_256>, MerkleTree<Blake3_256>>(
            proof,
            pub_inputs,
            &acceptable_options
        )
    }
}

// HELPER FUNCTIONS
// =================================================================================

fn from_digest(digest: &[u8]) -> Vec<BaseElement> {
    let mut result = Vec::new();
    let mut part = 0u32;

    for i in 0..8 {
        part = digest[4*i] as u32;
        part = part << 8 + digest[4*i + 1] as u32;
        part = part << 8 + digest[4*i + 2] as u32;
        part = part << 8 + digest[4*i + 3] as u32;

        result.push(BaseElement::new(to_base_element(part)));
    }

    result
}