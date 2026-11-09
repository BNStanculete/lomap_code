// Copyright Bogdan Stanculete 2026. All Rights Reserved.

use winterfell::math::{fields::f252::BaseElement, FieldElement};

use crate::utils::constraints::{
    EvaluationResult, ConstraintSpecification,
    are_equal, is_binary
};

use crate::define_constraint;
use super::{constants, get_register_column};

define_constraint!(
    general_constraint,
    |index, result, current, next, periodic_values, trace_length | {
        result.aggregate_constraint(*index, are_equal(current[constants::NUM_ROWS_OFFSET] + E::ONE, next[constants::NUM_ROWS_OFFSET]), E::ONE);
        *index += 1;

        // OPBITS are bit values
        for i in 0..5 {
            result.aggregate_constraint(*index, is_binary(current[get_register_column(constants::OPCODE_OFFSET, i)]), E::ONE);
            *index += 1;
        }
    },
    {
        let mut degrees = vec![[1].to_vec(); 70];
        degrees.extend(vec![[2].to_vec(); 5]);
        degrees
    }
);
