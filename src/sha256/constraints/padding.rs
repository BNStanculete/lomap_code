// Copyright Bogdan Stanculete 2026. All Rights Reserved.

use winterfell::math::{fields::f252::BaseElement, FieldElement};

use crate::utils::constraints::{
    EvaluationResult, ConstraintSpecification,
    are_equal
};

use crate::define_constraint;
use super::{constants, TRACE_WIDTH};

define_constraint!(
    padding_constraint,
    |index, result, current, next, periodic_values, trace_length | {
        // Enforce padding for the rest of the trace
        let flag = periodic_values[constants::PADDING_FLAG_INDEX];

        for i in 0..TRACE_WIDTH {
            result.aggregate_constraint(*index, are_equal(current[i], next[i]), flag);
            *index += 1;
        }
    },
    vec![[1, trace_length].to_vec(); TRACE_WIDTH]
);
