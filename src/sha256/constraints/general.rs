// Copyright Bogdan Stanculete 2026. All Rights Reserved.

use winterfell::math::{fields::f252::BaseElement, FieldElement};

use crate::utils::constraints::{
    EvaluationResult, ConstraintSpecification,
    is_binary
};

use crate::define_constraint;
use super::{constants, get_register_column};

define_constraint!(
    general_constraint,
    |index, result, current, next, periodic_values, trace_length | {
        let flag = periodic_values[constants::GENERAL_CONSTRAINT_FLAG_INDEX];

        // All bits are binary values
        for i in 0..224 {
            result.aggregate_constraint(*index, is_binary(current[get_register_column(constants::BITS_OFFSET, i)]), flag);
            *index += 1;
        }

        // The carries are binary values
        for i in 0..8 {
            result.aggregate_constraint(*index, is_binary(next[get_register_column(constants::CARRY_OFFSET, i)]), flag);
            *index += 1;
        }
    },
    vec![[2, trace_length].to_vec(); 232]
);
