use winterfell::math::{fields::f252::BaseElement, FieldElement};

use super::constants;
use super::TRACE_WIDTH;

use crate::utils::constraints::ConstraintSpecification;

mod padding;
mod general;
mod serialization;
mod sha256;
mod rsa2048;
mod poseidon;

use padding::padding_without_counter_constraint_specification;
use general::general_constraint_specification;
use sha256::{sha256_general_constraints_specification,
             sha256_first_half_round_constraints_specification,
             sha256_second_half_round_constraints_specification,
             sha256_schedule_word_computation_constraints_specification,
             sha256_hash_computation_constraints_specification};

use rsa2048::{rsa2048_general_constraints_specification,
              rsa2048_attestation_constraints_specification,
              rsa2048_padding_constraints_specification,
              rsa2048_multiplication_constraints_specification,
              rsa2048_conditional_multiplication_constraints_specification};

use poseidon::{poseidon_general_constraints_specification,
               poseidon_round_constraints_specification,
               poseidon_output_constraints_specification,
               poseidon_input_constraints_specification};

pub fn get_constraints<E: FieldElement + From<BaseElement>>(trace_length: usize) -> Vec<ConstraintSpecification<E>> {
    let mut constraints = Vec::new();

    // Padding & General constraints
    constraints.push(padding_without_counter_constraint_specification(trace_length));
    constraints.push(general_constraint_specification(trace_length));

    // Serialization constraints
    constraints.push(serialization::preservation_constraints_specification(trace_length));
    constraints.push(serialization::bookkeeping_constraints_specification(trace_length));
    constraints.push(serialization::accumulator_update_constraints_specification(trace_length));

    // Hash constraints
    constraints.push(sha256_general_constraints_specification(trace_length));
    constraints.push(sha256_first_half_round_constraints_specification(trace_length));
    constraints.push(sha256_second_half_round_constraints_specification(trace_length));
    constraints.push(sha256_schedule_word_computation_constraints_specification(trace_length));
    constraints.push(sha256_hash_computation_constraints_specification(trace_length));

    // Verification constraints
    constraints.push(rsa2048_general_constraints_specification(trace_length));
    constraints.push(rsa2048_attestation_constraints_specification(trace_length));
    constraints.push(rsa2048_padding_constraints_specification(trace_length));
    constraints.push(rsa2048_multiplication_constraints_specification(trace_length));
    // constraints.push(rsa2048_conditional_multiplication_constraints_specification(trace_length));

    // Poseidon constraints
    constraints.push(poseidon_general_constraints_specification(trace_length));
    constraints.push(poseidon_round_constraints_specification(trace_length));
    constraints.push(poseidon_output_constraints_specification(trace_length));
    constraints.push(poseidon_input_constraints_specification(trace_length));

    constraints
}

// HELPER FUNCTIONS
// ================================================================================================

pub const fn get_register_column(offset: usize, index: usize) -> usize {
    offset + index
}

pub const fn get_register_column_with_set(offset: usize, set: usize, index: usize, registers_per_set: usize) -> usize {
    offset + set * registers_per_set + index
}
