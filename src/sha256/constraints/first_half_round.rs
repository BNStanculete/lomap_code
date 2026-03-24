// Copyright Bogdan Stanculete 2026. All Rights Reserved.

use winterfell::math::{fields::f252::BaseElement, FieldElement};

use crate::utils::constraints::{
    EvaluationResult, ConstraintSpecification,
    are_equal, is_linear_decomposition, not
};

use crate::define_constraint;
use super::{constants, get_alternating_pattern, get_register_column, get_register_column_with_set};

define_constraint!(
    first_half_round_constraint,
    |index, result, current, next, periodic_values, trace_length | {
        let flag = periodic_values[constants::FIRST_HALF_ROUND_FLAG_INDEX];
        let round_constant = periodic_values[constants::ROUND_CONSTANT_INDEX];
        let round_flags = &periodic_values[constants::ROUND_INDEX..];
        let register_limit = E::from(constants::REGISTER_LIMIT);

        // Bitwise decomposition is correct
        let mut e_bit_slice = Vec::new();
        let mut f_bit_slice = Vec::new();
        let mut g_bit_slice = Vec::new();
        let mut powers_of_two = Vec::new();
        for i in 0..32 {
            e_bit_slice.push(next[get_register_column_with_set(constants::BITS_OFFSET, 0, i, 32)]);
            f_bit_slice.push(next[get_register_column_with_set(constants::BITS_OFFSET, 1, i, 32)]);
            g_bit_slice.push(next[get_register_column_with_set(constants::BITS_OFFSET, 2, i, 32)]);
            powers_of_two.push(E::from(constants::POWERS_OF_TWO[31 - i]));
        }

        result.aggregate_constraint(*index, is_linear_decomposition(current[get_register_column(constants::AH_OFFSET, 4)],
                                                                    e_bit_slice.as_slice(),
                                                                    powers_of_two.as_slice()),
                                    flag);
        *index += 1;

        result.aggregate_constraint(*index, is_linear_decomposition(current[get_register_column(constants::AH_OFFSET, 5)],
                                                                    f_bit_slice.as_slice(),
                                                                    powers_of_two.as_slice()),
                                    flag);
        *index += 1;

        result.aggregate_constraint(*index, is_linear_decomposition(current[get_register_column(constants::AH_OFFSET, 6)],
                                                                    g_bit_slice.as_slice(),
                                                                    powers_of_two.as_slice()),
                                    flag);
        *index += 1;

        // Sum1 and Ch are correctly derived from the bits
        let mut sum1_slice = Vec::new();
        let mut ch_slice = Vec::new();
        for i in 0..32 {
            let sum1 = next[get_register_column_with_set(constants::BITS_OFFSET, 0, (i as i32 - 6).rem_euclid(32) as usize, 32)] +
                       next[get_register_column_with_set(constants::BITS_OFFSET, 0, (i as i32 - 11).rem_euclid(32) as usize, 32)] +
                       next[get_register_column_with_set(constants::BITS_OFFSET, 0, (i as i32 - 25).rem_euclid(32) as usize, 32)];
            
            let ch = next[get_register_column_with_set(constants::BITS_OFFSET, 0, i, 32)] *
                     next[get_register_column_with_set(constants::BITS_OFFSET, 1, i, 32)] +
                     not(next[get_register_column_with_set(constants::BITS_OFFSET, 0, i, 32)]) *
                     next[get_register_column_with_set(constants::BITS_OFFSET, 2, i, 32)];

            result.aggregate_constraint(*index, are_equal(next[get_register_column_with_set(constants::BITS_OFFSET, 3, i, 32)] + 
                                                          next[get_register_column_with_set(constants::BITS_OFFSET, 5, i, 32)] * powers_of_two[30],
                                                          sum1),
                                        flag);
            *index += 1;

            result.aggregate_constraint(*index, are_equal(next[get_register_column_with_set(constants::BITS_OFFSET, 4, i, 32)] + 
                                                          next[get_register_column_with_set(constants::BITS_OFFSET, 6, i, 32)] * powers_of_two[30],
                                                          ch),
                                        flag);
            *index += 1;

            sum1_slice.push(next[get_register_column_with_set(constants::BITS_OFFSET, 3, i, 32)]);
            ch_slice.push(next[get_register_column_with_set(constants::BITS_OFFSET, 4, i, 32)]);
        }

        // Bitwise output stores the 32-bit equivalent
        result.aggregate_constraint(*index, is_linear_decomposition(next[get_register_column(constants::BITWISE_OUTPUT_OFFSET, 0)],
                                                                    sum1_slice.as_slice(),
                                                                    powers_of_two.as_slice()),
                                    flag);
        *index += 1;

        result.aggregate_constraint(*index, is_linear_decomposition(next[get_register_column(constants::BITWISE_OUTPUT_OFFSET, 1)],
                                                                    ch_slice.as_slice(),
                                                                    powers_of_two.as_slice()),
                                    flag);
        *index += 1;

        // T1 is correctly computed and reduced
        let left_side = next[get_register_column(constants::T1_OFFSET, 0)] +
                        next[get_register_column(constants::CARRY_OFFSET, 0)] * register_limit +
                        next[get_register_column(constants::CARRY_OFFSET, 1)] * register_limit +
                        next[get_register_column(constants::CARRY_OFFSET, 2)] * register_limit;

        let right_side = current[get_register_column(constants::AH_OFFSET, 7)] +
                        next[get_register_column(constants::BITWISE_OUTPUT_OFFSET, 0)] +
                        next[get_register_column(constants::BITWISE_OUTPUT_OFFSET, 1)] +
                        round_constant;

        for i in 0..16 {
            result.aggregate_constraint(*index, are_equal(left_side,
                                                        right_side + next[get_register_column(constants::W_OFFSET, i)]),
                                        round_flags[i]);
            *index += 1;
        }
        
        // E,F,G,H Registers are updated accordingly
        result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::AH_OFFSET, 6)], 
                                                      next[get_register_column(constants::AH_OFFSET, 7)]),
                                    flag);
        *index += 1;

        result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::AH_OFFSET, 5)], 
                                                      next[get_register_column(constants::AH_OFFSET, 6)]),
                                    flag);
        *index += 1;
    
        result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::AH_OFFSET, 4)], 
                                                      next[get_register_column(constants::AH_OFFSET, 5)]),
                                    flag);
        *index += 1;

        result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::AH_OFFSET, 3)] +
                                                      next[get_register_column(constants::T1_OFFSET, 0)],

                                                      next[get_register_column(constants::AH_OFFSET, 4)] +
                                                      next[get_register_column(constants::CARRY_OFFSET, 3)] * register_limit),
                                    flag);
        *index += 1;

        // W, A,B,C,D CARRY[4..7], HASH are preserved
        for i in 0..16 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::W_OFFSET, i)],
                                                          next[get_register_column(constants::W_OFFSET, i)]),
                                        flag);
            *index += 1;
        }
        for i in 0..4 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::AH_OFFSET, i)],
                                                          next[get_register_column(constants::AH_OFFSET, i)]),
                                        flag);
            *index += 1;
        }
        for i in 4..8 {
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
        let mut degrees = vec![[1, trace_length].to_vec(); 3];
        let array = get_alternating_pattern(trace_length);
        let mut vec_array = Vec::new();

        for i in 0..64 {
            vec_array.push(array[i].to_vec());
        }

        degrees.extend(vec_array);
        degrees.extend(vec![[1, trace_length].to_vec(); 2]);
        degrees.extend(vec![[1, trace_length].to_vec(); 16]);
        degrees.extend(vec![[1, trace_length].to_vec(); 36]);
        degrees
    }
);
