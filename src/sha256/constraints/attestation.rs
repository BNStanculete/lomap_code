// Copyright Bogdan Stanculete 2026. All Rights Reserved.

use winterfell::math::{fields::f252::BaseElement, FieldElement};

use crate::utils::constraints::{
    EvaluationResult, ConstraintSpecification,
    are_equal, is_binary, is_zero
};

use crate::define_constraint;
use super::{constants, get_register_column, get_register_column_with_set};

define_constraint!(
    attestation_constraint,
    |index, result, current, next, periodic_values, trace_length | {
        let general_flag = periodic_values[constants::ATTESTION_FLAG_INDEX];
        let input_flag = periodic_values[constants::ATTESTION_FLAG_INDEX + 1];
        let middle_flag = periodic_values[constants::ATTESTION_FLAG_INDEX + 2];
        let output_flag = periodic_values[constants::ATTESTION_FLAG_INDEX + 3];
        let two = E::from(constants::POWERS_OF_TWO[1]);

        // General attestation constraints
        for set in 1..8 {
            for i in 0..8 {
                result.aggregate_constraint(*index, are_equal(current[32 + get_register_column_with_set(constants::BITS_OFFSET, set, i, 24)],
                                                              current[32 + get_register_column_with_set(constants::BITS_OFFSET, set - 1, i + 8, 24)]),
                                            general_flag);
                *index += 1;
            }
        }

        for set in 0..8 {
            for i in 0..8 {
                result.aggregate_constraint(*index, are_equal(current[32 + get_register_column_with_set(constants::BITS_OFFSET, set, i, 24)],
                                                              current[32 + get_register_column_with_set(constants::BITS_OFFSET, set, i + 8, 24)] * two +
                                                              current[32 + get_register_column_with_set(constants::BITS_OFFSET, set, i + 16, 24)]),
                                            general_flag);
                *index += 1;
            }
        }

        for set in 0..8 {
            for i in 0..8 {
                result.aggregate_constraint(*index, is_binary(current[32 + get_register_column_with_set(constants::BITS_OFFSET, set, i + 16, 24)]), general_flag);
                *index += 1;
            }
        }
        
        // Input specific constraint
        for i in 0..8 {
            result.aggregate_constraint(*index, are_equal(current[32 + get_register_column_with_set(constants::BITS_OFFSET, 0, i, 24)],
                                                          current[get_register_column(constants::HASH_OFFSET, i)]),
                                        input_flag);
            *index += 1;
        }

        // Middle of the attestation constraints
        for i in 0..8 {
            result.aggregate_constraint(*index, are_equal(current[32 + get_register_column_with_set(constants::BITS_OFFSET, 7, i + 8, 24)],
                                                          next[32 + get_register_column_with_set(constants::BITS_OFFSET, 0, i, 24)]),
                                        middle_flag);
            *index += 1;
        }

        // End of attestation guards
        for i in 0..8 {
            result.aggregate_constraint(*index, is_zero(next[32 + get_register_column_with_set(constants::BITS_OFFSET, 7, i + 8, 24)]), output_flag);
            *index += 1;
        }

        // Preservation constraints for W, A..H, T1, T2, BITS[0..32], CARRY, HASH, BITWISE_OUTPUT
        for i in 0..16 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::W_OFFSET, i)],
                                                          next[get_register_column(constants::W_OFFSET, i)]),
                                        general_flag);
            *index += 1;
        }
        for i in 0..8 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::AH_OFFSET, i)],
                                                          next[get_register_column(constants::AH_OFFSET, i)]),
                                        general_flag);
            *index += 1;

            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::HASH_OFFSET, i)],
                                                          next[get_register_column(constants::HASH_OFFSET, i)]),
                                        general_flag);
            *index += 1;

            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::CARRY_OFFSET, i)],
                                                          next[get_register_column(constants::CARRY_OFFSET, i)]),
                                        general_flag);
            *index += 1;
        }
        for i in 0..32 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::BITS_OFFSET, i)],
                                                          next[get_register_column(constants::BITS_OFFSET, i)]),
                                        general_flag);
            *index += 1;
        }

        result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::BITWISE_OUTPUT_OFFSET, 0)],
                                                        next[get_register_column(constants::BITWISE_OUTPUT_OFFSET, 0)]),
                                    general_flag);
        *index += 1;

        result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::BITWISE_OUTPUT_OFFSET, 1)],
                                                        next[get_register_column(constants::BITWISE_OUTPUT_OFFSET, 1)]),
                                    general_flag);
        *index += 1;
    },
    {
        let mut degrees = vec![[1, trace_length].to_vec(); 120];
        degrees.extend(vec![[2, trace_length].to_vec(); 64]);
        degrees.extend(vec![[1, trace_length].to_vec(); 24]);
        degrees.extend(vec![[1, trace_length].to_vec(); 74]);
        degrees
    }
);
