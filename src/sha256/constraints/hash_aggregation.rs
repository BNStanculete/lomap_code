// Copyright Bogdan Stanculete 2026. All Rights Reserved.

use winterfell::math::{fields::f252::BaseElement, FieldElement};

use crate::utils::constraints::{
    EvaluationResult, ConstraintSpecification,
    are_equal
};

use crate::define_constraint;
use super::{constants, get_register_column};

define_constraint!(
    hash_computation_constraint,
    |index, result, current, next, periodic_values, trace_length | {
        let flag = periodic_values[constants::HASH_UPDATE_FLAG_INDEX];
        let register_limit = E::from(constants::REGISTER_LIMIT);

        for i in 0..8 {
            result.aggregate_constraint(*index, are_equal(next[get_register_column(constants::HASH_OFFSET, i)] +
                                                          next[get_register_column(constants::CARRY_OFFSET, i)] * register_limit,

                                                          current[get_register_column(constants::AH_OFFSET, i)] +
                                                          current[get_register_column(constants::HASH_OFFSET, i)]),
                                        flag);
            *index += 1;
                                        
            result.aggregate_constraint(*index, are_equal(next[get_register_column(constants::HASH_OFFSET, i)],
                                                          next[get_register_column(constants::AH_OFFSET, i)]),
                                        flag);
            *index += 1;
        }

        // W, BITS, BITWISE_OUTPUT, T1, T2 are preserved
        for i in 0..16 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::W_OFFSET, i)],
                                                          next[get_register_column(constants::W_OFFSET, i)]),
                                        flag);
            *index += 1;
        }
        for i in 0..224 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::BITS_OFFSET, i)],
                                                          next[get_register_column(constants::BITS_OFFSET, i)]),
                                        flag);
            *index += 1;
        }
        for i in 0..2 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::BITWISE_OUTPUT_OFFSET, i)],
                                                          next[get_register_column(constants::BITWISE_OUTPUT_OFFSET, i)]),
                                        flag);
            *index += 1;
        }
        result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::T1_OFFSET, 0)],
                                                        next[get_register_column(constants::T1_OFFSET, 0)]),
                                    flag);
        *index += 1;

        result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::T2_OFFSET, 0)],
                                                        next[get_register_column(constants::T2_OFFSET, 0)]),
                                    flag);
        *index += 1;
    },
    vec![[1, trace_length].to_vec(); 260]
);
