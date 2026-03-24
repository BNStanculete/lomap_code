// Copyright Bogdan Stanculete 2026. All Rights Reserved.

use winterfell::math::{fields::f252::BaseElement, FieldElement};

use crate::utils::constraints::{
    EvaluationResult, ConstraintSpecification,
    are_equal, is_linear_decomposition
};

use crate::define_constraint;
use super::{constants, get_register_column, get_register_column_with_set};

define_constraint!(
    schedule_computation_constraint,
    |index, result, current, next, periodic_values, trace_length | {
        let flag = periodic_values[constants::MESSAGE_SCHEDULE_COMPUTATION_FLAG_INDEX];
        let register_limit = E::from(constants::REGISTER_LIMIT);

        // Words shift left by 1
        for i in 0..15 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::W_OFFSET, i+1)],
                                                        next[get_register_column(constants::W_OFFSET, i)]),
                                        flag);
            *index += 1;
        }

        // -- Bit decomposition is correct --
        let mut w13_bit_slice = Vec::new();
        let mut w0_bit_slice = Vec::new();
        let mut powers_of_two = Vec::new();
        for i in 0..32 {
            w13_bit_slice.push(next[get_register_column_with_set(constants::BITS_OFFSET, 0, i, 32)]);
            w0_bit_slice.push(next[get_register_column_with_set(constants::BITS_OFFSET, 1, i, 32)]);
            powers_of_two.push(E::from(constants::POWERS_OF_TWO[31 - i]));
        }

        result.aggregate_constraint(*index, is_linear_decomposition(next[get_register_column(constants::W_OFFSET, 13)],
                                                                    w13_bit_slice.as_slice(),
                                                                    powers_of_two.as_slice()),
                                    flag);
        *index += 1;

        result.aggregate_constraint(*index, is_linear_decomposition(next[get_register_column(constants::W_OFFSET, 0)],
                                                                    w0_bit_slice.as_slice(),
                                                                    powers_of_two.as_slice()),
                                    flag);
        *index += 1;

        // Sigma0 and Sigma1 are correctly computed
        for i in 0..32 {
            let right_shift0 = if i >= 3 { next[get_register_column_with_set(constants::BITS_OFFSET, 1, i - 3, 32)] } else { E::ZERO };
            let right_shift1 = if i >= 10 { next[get_register_column_with_set(constants::BITS_OFFSET, 0, i - 10, 32)] } else { E::ZERO };

            let sigma0 = next[get_register_column_with_set(constants::BITS_OFFSET, 1, (i as i32 - 7).rem_euclid(32) as usize, 32)] +
                        next[get_register_column_with_set(constants::BITS_OFFSET, 1, (i as i32 - 18).rem_euclid(32) as usize, 32)] +
                        right_shift0;
            let sigma1 = next[get_register_column_with_set(constants::BITS_OFFSET, 0, (i as i32 - 17).rem_euclid(32) as usize, 32)] +
                        next[get_register_column_with_set(constants::BITS_OFFSET, 0, (i as i32 - 19).rem_euclid(32) as usize, 32)] +
                        right_shift1;
            
            result.aggregate_constraint(*index, are_equal(next[get_register_column_with_set(constants::BITS_OFFSET, 2, i, 32)] + 
                                                        next[get_register_column_with_set(constants::BITS_OFFSET, 4, i, 32)] * powers_of_two[30],
                                                        sigma1),
                                        flag);
            *index += 1;

            result.aggregate_constraint(*index, are_equal(next[get_register_column_with_set(constants::BITS_OFFSET, 3, i, 32)] + 
                                                        next[get_register_column_with_set(constants::BITS_OFFSET, 5, i, 32)] * powers_of_two[30],
                                                        sigma0),
                                        flag);
            *index += 1;
        }

        // -- Bit decomposition is correct --
        let mut sigma1_bit_slice = Vec::new();
        let mut sigma0_bit_slice = Vec::new();
        for i in 0..32 {
            sigma1_bit_slice.push(next[get_register_column_with_set(constants::BITS_OFFSET, 2, i, 32)]);
            sigma0_bit_slice.push(next[get_register_column_with_set(constants::BITS_OFFSET, 3, i, 32)]);
        }

        result.aggregate_constraint(*index, is_linear_decomposition(next[get_register_column(constants::BITWISE_OUTPUT_OFFSET, 0)],
                                                                    sigma1_bit_slice.as_slice(),
                                                                    powers_of_two.as_slice()),
                                    flag);
        *index += 1;

        result.aggregate_constraint(*index, is_linear_decomposition(next[get_register_column(constants::BITWISE_OUTPUT_OFFSET, 1)],
                                                                    sigma0_bit_slice.as_slice(),
                                                                    powers_of_two.as_slice()),
                                    flag);
        *index += 1;

        // The next W is computed correctly
        let w = next[get_register_column(constants::BITWISE_OUTPUT_OFFSET, 0)] +
                next[get_register_column(constants::BITWISE_OUTPUT_OFFSET, 1)] +
                next[get_register_column(constants::W_OFFSET, 8)] +
                current[get_register_column(constants::W_OFFSET, 0)];

        result.aggregate_constraint(*index, are_equal(w, next[get_register_column(constants::W_OFFSET, 15)] +
                                                         next[get_register_column(constants::CARRY_OFFSET, 0)] * register_limit +
                                                         next[get_register_column(constants::CARRY_OFFSET, 1)] * register_limit +
                                                         next[get_register_column(constants::CARRY_OFFSET, 2)] * register_limit),
                                    flag);
        *index += 1;

        // The next W is decomposed correctly into bits
        let mut w15_bit_slice = Vec::new();
        for i in 0..32 {
            w15_bit_slice.push(next[get_register_column_with_set(constants::BITS_OFFSET, 6, i, 32)]);
        }

        result.aggregate_constraint(*index, is_linear_decomposition(next[get_register_column(constants::W_OFFSET, 15)],
                                                                    w15_bit_slice.as_slice(),
                                                                    powers_of_two.as_slice()),
                                    flag);
        *index += 1;

        // Exhausted registers: W, BITS, CARRY[0-2], BITWISE_OUTPUT. The remaining are copied
        for i in 0..8 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::AH_OFFSET, i)],
                                                        next[get_register_column(constants::AH_OFFSET, i)]),
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

        for i in 3..8 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::CARRY_OFFSET, i)],
                                                        next[get_register_column(constants::CARRY_OFFSET, i)]),
                                        flag);
            *index += 1;
        }

        for i in 0..8 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::HASH_OFFSET, i)],
                                                        next[get_register_column(constants::HASH_OFFSET, i)]),
                                        flag);
            *index += 1;
        }
    },
    {
        let mut degrees = vec![[1, trace_length].to_vec(); 85];
        degrees.extend(vec![[1, trace_length].to_vec(); 23]);
        degrees
    }
);
