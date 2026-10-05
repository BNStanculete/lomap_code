use winterfell::math::{fields::f252::BaseElement, FieldElement};

use crate::utils::constraints::{
    EvaluationResult, ConstraintSpecification,
    are_equal, is_binary, not, is_linear_decomposition, is_zero
};

use crate::define_constraint;
use super::{get_register_column, get_register_column_with_set};
use super::constants::{U32_REGISTER_LIMIT, POWERS_OF_TWO}

mod constants;

mod general_constraints;
mod round_constraints;
mod alignment_constraints;

use general_constraints::{
    general_constraints_specification,
    state_machine_constraints_specification};

// use round_constraints::{
//     first_half_round_constraints_specification,
//     second_half_round_constraints_specification,
//     schedule_update_constraints_specification};

// use alignment_constraints::{
//     alignment_constraints_specification};

pub fn get_constraints<E: FieldElement + From<BaseElement>>(flag: E, base_offset: usize, trace_length: usize) -> Vec<ConstraintSpecification<E>> {
    let mut constraints = Vec::new();

    // Padding & General constraints
    constraints.push(general_constraints_specification(flag, base_offset, trace_length));
    // constraints.push(state_machine_constraints_specification(flag, base_offset, trace_length));
    // constraints.push(first_half_round_constraints_specification(flag, base_offset, trace_length));
    // constraints.push(second_half_round_constraints_specification(flag, base_offset, trace_length));
    // constraints.push(schedule_update_constraints_specification(flag, base_offset, trace_length));
    // constraints.push(alignment_constraints_specification(flag, base_offset, trace_length));

    constraints
}