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

use crate::crl_update::CRLData;

mod air;
use air::{PublicInputs, AuthenticationAir};

mod prover;
use prover::AuthenticationProver;

mod constraints;
mod constants;

#[cfg(test)]
mod tests;

// TRACE CONSTANTS
// ================================================================================================

pub const CYCLE_LENGTH: usize = 256;
pub const TRACE_WIDTH: usize = 420;

// CRLUpdate Proof
// ================================================================================================

#[derive(Debug)]
#[derive(Clone)]
pub struct CertificateData {
    pub subject_cn: String,
    pub issuer_cn: String,
    pub serial: String,
    pub pub_key_hash: String,
    pub not_before: String,
    pub not_after: String,
    pub hash: String,
}

#[derive(Debug)]
#[derive(Clone)]
pub struct AuthenticationData {
    pub cert: CertificateData,
    pub authorities: Vec<(CertificateData, CRLData)>,
    pub hash: String
}

// Generation requires only options & trace columns
pub struct AuthenticationProvable {
    options: ProofOptions,
    columns: Vec<Vec<BaseElement>>,
    expected_hash: Vec<BaseElement>,
}

impl AuthenticationProvable {
    pub fn new(
        options: ProofOptions,
        columns: Vec<Vec<BaseElement>>,
        expected_io: AuthenticationData) -> Self {
        let hash_words: Vec<u128> = decimal_to_limbs::<u128>(expected_io.hash.as_str(), 252).unwrap();

        let mut expected_hash: Vec<BaseElement> = Vec::with_capacity(2);

        for i in 0..2 {
            expected_hash.push(BaseElement::from(hash_words[i]));
        }

        AuthenticationProvable {
            options,
            columns,
            expected_hash
        }
    }
}

// Verification takes separately the public inputs and a claimed height
pub struct AuthenticationVerifiable {
    expected_io: AuthenticationData,
    trace_size: u64,
}

impl AuthenticationVerifiable {
    pub fn new(
        expected_io: AuthenticationData,
        trace_size: u64) -> Self {
        AuthenticationVerifiable {
            expected_io,
            trace_size
        }
    }
}

// MessageAuthentication IMPLEMENTATION
// ================================================================================================

impl Verifiable for AuthenticationVerifiable {
    fn verify(&self, proof: Proof) -> Result<(), VerifierError> {
        let hash_words: Vec<u128> = decimal_to_limbs::<u128>(self.expected_io.hash.as_str(), 252).unwrap();

        let mut expected_hash: Vec<BaseElement> = Vec::with_capacity(2);

        for i in 0..2 {
            expected_hash.push(BaseElement::from(hash_words[i]));
        }

        let acceptable_options = winterfell::AcceptableOptions::OptionSet(vec![proof.options().clone()]);
        let pub_inputs = PublicInputs { 
            expected_length: BaseElement::from(self.trace_size),
            expected_hash: expected_hash
        };

        winterfell::verify::<AuthenticationAir, Blake3_256, DefaultRandomCoin<Blake3_256>, MerkleTree<Blake3_256>>(
            proof,
            pub_inputs,
            &acceptable_options
        )
    }
}

impl Provable for AuthenticationProvable {
    fn prove(&self) -> Proof {
        // Create a new prover
        let prover = AuthenticationProver::<Blake3_256>::new(self.options.clone(), self.expected_hash.clone());

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
