// Copyright Bogdan Stanculete 2026. All Rights Reserved.

use winterfell::math::{fields::f252::BaseElement, FieldElement};

use super::constants;
use super::TRACE_WIDTH;

use crate::utils::constraints::ConstraintSpecification;

mod row_counting;
mod schedule_computation;
mod first_half_round;
mod second_half_round;
mod hash_aggregation;

mod general;
mod attestation;
mod padding;

use row_counting::row_counting_constraint_specification;
use schedule_computation::schedule_computation_constraint_specification;
use first_half_round::first_half_round_constraint_specification;
use second_half_round::second_half_round_constraint_specification;
use hash_aggregation::hash_computation_constraint_specification;
use general::general_constraint_specification;
use attestation::attestation_constraint_specification;
use padding::padding_constraint_specification;

pub fn get_constraints<E: FieldElement + From<BaseElement>>(trace_length: usize) -> Vec<ConstraintSpecification<E>> {
    let mut constraints = Vec::new();

    constraints.push(row_counting_constraint_specification(trace_length));
    constraints.push(schedule_computation_constraint_specification(trace_length));
    constraints.push(first_half_round_constraint_specification(trace_length));
    constraints.push(second_half_round_constraint_specification(trace_length));
    constraints.push(hash_computation_constraint_specification(trace_length));

    constraints.push(general_constraint_specification(trace_length));
    constraints.push(attestation_constraint_specification(trace_length));
    constraints.push(padding_constraint_specification(trace_length));

    constraints
}

// HELPER FUNCTIONS
// ================================================================================================

const fn get_alternating_pattern(trace_length: usize) -> [[usize; 2]; 64] {
    let mut array = [[1, trace_length]; 64];
    let mut index = 1;

    while index < 64 {
        array[index][0] = 2;
        index += 2;
    }

    array
}

pub const fn get_register_column(offset: usize, index: usize) -> usize {
    offset + index
}

pub const fn get_register_column_with_set(offset: usize, set: usize, index: usize, registers_per_set: usize) -> usize {
    offset + set * registers_per_set + index
}
