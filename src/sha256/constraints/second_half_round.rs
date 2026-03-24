// Copyright Bogdan Stanculete 2026. All Rights Reserved.

use winterfell::math::{fields::f252::BaseElement, FieldElement};

use crate::utils::constraints::{
    EvaluationResult, ConstraintSpecification,
    are_equal, is_linear_decomposition
};

use crate::define_constraint;
use super::{constants, get_alternating_pattern, get_register_column, get_register_column_with_set};

define_constraint!(
    second_half_round_constraint,
    |index, result, current, next, periodic_values, trace_length | {
        let flag = periodic_values[constants::SECOND_HALF_ROUND_FLAG_INDEX];
        let register_limit = E::from(constants::REGISTER_LIMIT);

        // Bitwise decomposition is correct
        let mut a_bit_slice = Vec::new();
        let mut b_bit_slice = Vec::new();
        let mut c_bit_slice = Vec::new();
        let mut powers_of_two = Vec::new();
        for i in 0..32 {
            a_bit_slice.push(next[get_register_column_with_set(constants::BITS_OFFSET, 0, i, 32)]);
            b_bit_slice.push(next[get_register_column_with_set(constants::BITS_OFFSET, 1, i, 32)]);
            c_bit_slice.push(next[get_register_column_with_set(constants::BITS_OFFSET, 2, i, 32)]);
            powers_of_two.push(E::from(constants::POWERS_OF_TWO[31 - i]));
        }

        result.aggregate_constraint(*index, is_linear_decomposition(current[get_register_column(constants::AH_OFFSET, 0)],
                                                                    a_bit_slice.as_slice(),
                                                                    powers_of_two.as_slice()),
                                    flag);
        *index += 1;

        result.aggregate_constraint(*index, is_linear_decomposition(current[get_register_column(constants::AH_OFFSET, 1)],
                                                                    b_bit_slice.as_slice(),
                                                                    powers_of_two.as_slice()),
                                    flag);
        *index += 1;

        result.aggregate_constraint(*index, is_linear_decomposition(current[get_register_column(constants::AH_OFFSET, 2)],
                                                                    c_bit_slice.as_slice(),
                                                                    powers_of_two.as_slice()),
                                    flag);
        *index += 1;

        // Sum0 and Maj are correctly derived from the bits
        let mut sum0_slice = Vec::new();
        let mut maj_slice = Vec::new();
        for i in 0..32 {
            let sum0 = next[get_register_column_with_set(constants::BITS_OFFSET, 0, (i as i32 - 2).rem_euclid(32) as usize, 32)] +
                       next[get_register_column_with_set(constants::BITS_OFFSET, 0, (i as i32 - 13).rem_euclid(32) as usize, 32)] +
                       next[get_register_column_with_set(constants::BITS_OFFSET, 0, (i as i32 - 22).rem_euclid(32) as usize, 32)];
            
            let maj = next[get_register_column_with_set(constants::BITS_OFFSET, 0, i, 32)] *
                     next[get_register_column_with_set(constants::BITS_OFFSET, 1, i, 32)] +
                     next[get_register_column_with_set(constants::BITS_OFFSET, 0, i, 32)] *
                     next[get_register_column_with_set(constants::BITS_OFFSET, 2, i, 32)] +
                     next[get_register_column_with_set(constants::BITS_OFFSET, 1, i, 32)] *
                     next[get_register_column_with_set(constants::BITS_OFFSET, 2, i, 32)];

            result.aggregate_constraint(*index, are_equal(next[get_register_column_with_set(constants::BITS_OFFSET, 3, i, 32)] + 
                                                          next[get_register_column_with_set(constants::BITS_OFFSET, 5, i, 32)] * powers_of_two[30],
                                                          sum0),
                                        flag);
            *index += 1;

            result.aggregate_constraint(*index, are_equal(next[get_register_column_with_set(constants::BITS_OFFSET, 4, i, 32)] + 
                                                          next[get_register_column_with_set(constants::BITS_OFFSET, 6, i, 32)] * powers_of_two[30],
                                                          maj),
                                        flag);
            *index += 1;

            sum0_slice.push(next[get_register_column_with_set(constants::BITS_OFFSET, 3, i, 32)]);
            maj_slice.push(next[get_register_column_with_set(constants::BITS_OFFSET, 4, i, 32)]);
        }

        // Bitwise output stores the 32-bit equivalent
        result.aggregate_constraint(*index, is_linear_decomposition(next[get_register_column(constants::BITWISE_OUTPUT_OFFSET, 0)],
                                                                    sum0_slice.as_slice(),
                                                                    powers_of_two.as_slice()),
                                    flag);
        *index += 1;

        result.aggregate_constraint(*index, is_linear_decomposition(next[get_register_column(constants::BITWISE_OUTPUT_OFFSET, 1)],
                                                                    maj_slice.as_slice(),
                                                                    powers_of_two.as_slice()),
                                    flag);
        *index += 1;

        // T2 is computed correctly
        result.aggregate_constraint(*index, are_equal(next[get_register_column(constants::T2_OFFSET, 0)] +
                                                      next[get_register_column(constants::CARRY_OFFSET, 4)] * register_limit,
                                                      next[get_register_column(constants::BITWISE_OUTPUT_OFFSET, 0)] +
                                                      next[get_register_column(constants::BITWISE_OUTPUT_OFFSET, 1)]),
                                    flag);
        *index += 1;

        // A,B,C,D Registers are updated accordingly
        result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::AH_OFFSET, 2)], 
                                                      next[get_register_column(constants::AH_OFFSET, 3)]),
                                    flag);
        *index += 1;

        result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::AH_OFFSET, 1)], 
                                                      next[get_register_column(constants::AH_OFFSET, 2)]),
                                    flag);
        *index += 1;
    
        result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::AH_OFFSET, 0)], 
                                                      next[get_register_column(constants::AH_OFFSET, 1)]),
                                    flag);
        *index += 1;

        result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::T1_OFFSET, 0)] +
                                                      next[get_register_column(constants::T2_OFFSET, 0)],

                                                      next[get_register_column(constants::AH_OFFSET, 0)] +
                                                      next[get_register_column(constants::CARRY_OFFSET, 5)] * register_limit),
                                    flag);
        *index += 1;

        // W, E,F,G,H, CARRY[0..3], CARRY[6..7], HASH are preserved
        for i in 0..16 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::W_OFFSET, i)],
                                                          next[get_register_column(constants::W_OFFSET, i)]),
                                        flag);
            *index += 1;
        }
        for i in 4..8 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::AH_OFFSET, i)],
                                                          next[get_register_column(constants::AH_OFFSET, i)]),
                                        flag);
            *index += 1;
        }
        for i in 0..3 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::CARRY_OFFSET, i)],
                                                          next[get_register_column(constants::CARRY_OFFSET, i)]),
                                        flag);
            *index += 1;
        }
        for i in 6..8 {
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
        degrees.extend(vec![[1, trace_length].to_vec(); 40]);
        degrees
    }
);
