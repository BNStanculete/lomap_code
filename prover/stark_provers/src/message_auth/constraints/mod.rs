use winterfell::math::{fields::f252::BaseElement, FieldElement};

use super::constants;
use super::TRACE_WIDTH;

use crate::utils::constraints::ConstraintSpecification;

mod padding;
mod general;
mod sha256;

use padding::padding_without_counter_constraint_specification;
use general::general_constraint_specification;
use sha256::{sha256_general_constraints_specification,
             sha256_first_half_round_constraints_specification,
             sha256_second_half_round_constraints_specification,
             sha256_schedule_word_computation_constraints_specification,
             sha256_hash_computation_constraints_specification};

pub fn get_constraints<E: FieldElement + From<BaseElement>>(trace_length: usize) -> Vec<ConstraintSpecification<E>> {
    let mut constraints = Vec::new();

    // Padding & General constraints
    constraints.push(padding_without_counter_constraint_specification(trace_length));
    constraints.push(general_constraint_specification(trace_length));

    // Hash constraints
    constraints.push(sha256_general_constraints_specification(trace_length));
    constraints.push(sha256_first_half_round_constraints_specification(trace_length));
    constraints.push(sha256_second_half_round_constraints_specification(trace_length));
    constraints.push(sha256_schedule_word_computation_constraints_specification(trace_length));
    constraints.push(sha256_hash_computation_constraints_specification(trace_length));

    // Verification constraints

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
