// Copyright Bogdan Stanculete 2026. All Rights Reserved.

use core::marker::PhantomData;
use crate::utils::decimal_to_limbs;

use tracing::{field, info_span};
use winterfell::{
    crypto::{DefaultRandomCoin, ElementHasher, MerkleTree},
    math::{fields::f252::BaseElement, FieldElement},
    Proof, ProofOptions, Prover, Trace, VerifierError,
};

use crate::{
    Verifiable, Provable,
    Blake3_256
};

mod air;
use air::{PublicInputs, MessageAuthenticationAir};

mod prover;
use prover::MessageAuthenticationProver;

mod constraints;
mod constants;

#[cfg(test)]
mod tests;

// TRACE CONSTANTS
// ================================================================================================

pub const CYCLE_LENGTH: usize = 256;
pub const TRACE_WIDTH: usize = 402;

// MessageAuthentication Proof
// ================================================================================================

#[derive(Debug)]
#[derive(Clone)]
pub struct MessageAuthenticationData {
    pub pub_key_hash: String,
    pub signature: String,
}

// Generation requires only options & trace columns
pub struct MessageAuthenticationProvable {
    options: ProofOptions,
    columns: Vec<Vec<BaseElement>>,
    expected_hash: Vec<BaseElement>,
    expected_signature: Vec<BaseElement>
}

impl MessageAuthenticationProvable {
    pub fn new(
        options: ProofOptions,
        columns: Vec<Vec<BaseElement>>,
        expected_io: MessageAuthenticationData) -> Self {
        let hash_words: Vec<u128> = decimal_to_limbs::<u128>(expected_io.pub_key_hash.as_str(), 252).unwrap();
        let signature_words: Vec<u64> = decimal_to_limbs::<u64>(expected_io.signature.as_str(), 2048).unwrap();

        let mut expected_hash: Vec<BaseElement> = Vec::with_capacity(2);
        let mut expected_signature: Vec<BaseElement> = Vec::with_capacity(32);

        for i in 0..32 {
            if i < 2 {
                expected_hash.push(BaseElement::from(hash_words[i]));
            }

            expected_signature.push(BaseElement::from(signature_words[i]));
        }

        MessageAuthenticationProvable {
            options,
            columns,
            expected_hash,
            expected_signature
        }
    }
}

// Verification takes separately the public inputs and a claimed height
pub struct MessageAuthenticationVerifiable {
    expected_io: MessageAuthenticationData,
    trace_size: u64,
}

impl MessageAuthenticationVerifiable {
    pub fn new(
        expected_io: MessageAuthenticationData,
        trace_size: u64) -> Self {
        MessageAuthenticationVerifiable {
            expected_io,
            trace_size
        }
    }
}

// MessageAuthentication IMPLEMENTATION
// ================================================================================================

impl Verifiable for MessageAuthenticationVerifiable {
    fn verify(&self, proof: Proof) -> Result<(), VerifierError> {
        let hash_words: Vec<u128> = decimal_to_limbs::<u128>(self.expected_io.pub_key_hash.as_str(), 252).unwrap();
        let signature_words: Vec<u64> = decimal_to_limbs::<u64>(self.expected_io.signature.as_str(), 2048).unwrap();

        let mut expected_hash: Vec<BaseElement> = Vec::with_capacity(2);
        let mut expected_signature: Vec<BaseElement> = Vec::with_capacity(32);

        for i in 0..32 {
            if i < 2 {
                expected_hash.push(BaseElement::from(hash_words[i]));
            }

            expected_signature.push(BaseElement::from(signature_words[i]));
        }

        let acceptable_options = winterfell::AcceptableOptions::OptionSet(vec![proof.options().clone()]);
        let pub_inputs = PublicInputs { 
            expected_length: BaseElement::from(self.trace_size),
            expected_hash: expected_hash,
            expected_signature: expected_signature,
        };

        winterfell::verify::<MessageAuthenticationAir, Blake3_256, DefaultRandomCoin<Blake3_256>, MerkleTree<Blake3_256>>(
            proof,
            pub_inputs,
            &acceptable_options
        )
    }
}

impl Provable for MessageAuthenticationProvable {
    fn prove(&self) -> Proof {
        // Create a new prover
        let prover = MessageAuthenticationProver::<Blake3_256>::new(self.options.clone(), self.expected_hash.clone(), self.expected_signature.clone());

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