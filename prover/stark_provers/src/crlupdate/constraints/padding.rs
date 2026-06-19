// Copyright Bogdan Stanculete 2026. All Rights Reserved.

use winterfell::math::{fields::f252::BaseElement, FieldElement};

use crate::utils::constraints::{
    EvaluationResult, ConstraintSpecification,
    are_equal
};

use crate::define_constraint;
use super::{constants, get_register_column, TRACE_WIDTH};

define_constraint!(
    padding_without_counter_constraint,
    |index, result, current, next, periodic_values, trace_length | {
        // Enforce padding for the rest of the trace
        let flag: E = (current[get_register_column(constants::OPCODE_OFFSET, 0)] - E::ONE) *
                      (current[get_register_column(constants::OPCODE_OFFSET, 1)] - E::ONE) *
                      (current[get_register_column(constants::OPCODE_OFFSET, 2)] - E::ONE) *
                      (current[get_register_column(constants::OPCODE_OFFSET, 3)] - E::ONE) *
                      (current[get_register_column(constants::OPCODE_OFFSET, 4)]);

        for i in 1..TRACE_WIDTH {
            result.aggregate_constraint(*index, are_equal(current[i], next[i]), flag);
            *index += 1;
        }
    },
    vec![[6].to_vec(); TRACE_WIDTH - 1]
);
