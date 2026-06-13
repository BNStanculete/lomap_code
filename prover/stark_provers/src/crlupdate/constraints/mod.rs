use winterfell::math::{fields::f252::BaseElement, FieldElement};

use super::constants;
use super::TRACE_WIDTH;

use crate::utils::constraints::ConstraintSpecification;

mod padding;
mod general;

use padding::{padding_without_counter_constraint_specification};
use general::{general_constraint_specification, general_serialization_constraint_specification};

pub fn get_constraints<E: FieldElement + From<BaseElement>>(trace_length: usize) -> Vec<ConstraintSpecification<E>> {
    let mut constraints = Vec::new();

    // Padding constraints
    constraints.push(padding_without_counter_constraint_specification(trace_length));
    constraints.push(general_constraint_specification(trace_length));

    // Serialization constraints
    constraints.push(general_serialization_constraint_specification(trace_length));

    // Hash constraints

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
