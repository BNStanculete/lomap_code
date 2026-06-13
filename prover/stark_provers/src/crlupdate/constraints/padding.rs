// Copyright Bogdan Stanculete 2026. All Rights Reserved.

use winterfell::math::{fields::f252::BaseElement, FieldElement};

use crate::utils::constraints::{
    EvaluationResult, ConstraintSpecification,
    are_equal
};

use crate::define_constraint;
use super::{constants, TRACE_WIDTH};

define_constraint!(
    padding_without_counter_constraint,
    |index, result, current, next, periodic_values, trace_length | {
        // Enforce padding for the rest of the trace
        let flag: E = (current[constants::OPCODE_OFFSET] - E::from(1u32)) *
                      (current[constants::OPCODE_OFFSET] - E::from(2u32)) *
                      (current[constants::OPCODE_OFFSET] - E::from(3u32)) *
                      (current[constants::SUBCODE_OFFSET] - E::from(1u32)) *
                      (current[constants::SUBCODE_OFFSET]);

        for i in 1..TRACE_WIDTH {
            result.aggregate_constraint(*index, are_equal(current[i], next[i]), flag);
            *index += 1;
        }
    },
    vec![[6].to_vec(); TRACE_WIDTH - 1]
);
