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

        // PUBLIC_KEY is preserved
        for i in 4..36 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::PUB_KEY_OFFSET, i)],
                                                          next[get_register_column(constants::PUB_KEY_OFFSET, i)]), E::ONE);
            *index += 1;
        }

        // SIGNATURE_ALGO is preserved
        result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::SIGNATURE_ALGO_OFFSET, 0)],
                                                      next[get_register_column(constants::SIGNATURE_ALGO_OFFSET, 0)]), E::ONE);

        // OPBITS are bit values
        for i in 0..5 {
            result.aggregate_constraint(*index, is_binary(current[get_register_column(constants::OPCODE_OFFSET, i)]), E::ONE);
            *index += 1;
        }
    },
    {
        let mut degrees = vec![[1].to_vec(); 66];
        degrees.extend(vec![[2].to_vec(); 5]);
        degrees
    }
);
