// Copyright Bogdan Stanculete 2026. All Rights Reserved.

use winterfell::math::{fields::f252::BaseElement, FieldElement};

use crate::utils::constraints::{
    EvaluationResult, ConstraintSpecification,
    are_equal, is_binary, not, is_linear_decomposition, is_zero
};

use crate::define_constraint;
use super::{constants, get_register_column, get_register_column_with_set};

define_constraint!(
    sha256_general_constraints,
    |index, result, current, next, periodic_values, trace_length | {
        let flag: E = (current[get_register_column(constants::OPCODE_OFFSET, 0)]) *
                      (current[get_register_column(constants::OPCODE_OFFSET, 1)] - E::ONE);

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
    {
        let mut degrees = vec![[4].to_vec(); 232];
        degrees
    }
);

define_constraint!(
    sha256_first_half_round_constraints,
    |index, result, current, next, periodic_values, trace_length | {
        let flag: E = (next[get_register_column(constants::OPCODE_OFFSET, 0)]) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 1)] - E::ONE) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 2)] - E::ONE) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 3)] - E::ONE) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 4)]);
        let logical_limit = E::from(constants::U32_REGISTER_LIMIT);

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
        let left_side = next[get_register_column(constants::AH_OFFSET, 8)] +    
                        next[get_register_column(constants::CARRY_OFFSET, 0)] * logical_limit +
                        next[get_register_column(constants::CARRY_OFFSET, 1)] * logical_limit +
                        next[get_register_column(constants::CARRY_OFFSET, 2)] * logical_limit;

        let right_side = current[get_register_column(constants::AH_OFFSET, 7)] +
                        next[get_register_column(constants::BITWISE_OUTPUT_OFFSET, 0)] +
                        next[get_register_column(constants::BITWISE_OUTPUT_OFFSET, 1)] +
                        next[get_register_column(constants::CONSTANT_OFFSET, 0)];

        for i in 0..16 {
            result.aggregate_constraint(*index, are_equal(left_side,
                                                        right_side + next[get_register_column(constants::WORK_SCHEDULE_OFFSET, i)]),
                                        flag * next[get_register_column(constants::W_SELECTOR_OFFSET, i)]);
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
                                                      next[get_register_column(constants::AH_OFFSET, 8)],

                                                      next[get_register_column(constants::AH_OFFSET, 4)] +
                                                      next[get_register_column(constants::CARRY_OFFSET, 3)] * logical_limit),
                                    flag);
        *index += 1;

        // W, A,B,C,D CARRY[4..7], HASH are preserved
        for i in 0..16 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::WORK_SCHEDULE_OFFSET, i)],
                                                          next[get_register_column(constants::WORK_SCHEDULE_OFFSET, i)]),
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
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::OUT_HASH_OFFSET, i)],
                                                          next[get_register_column(constants::OUT_HASH_OFFSET, i)]),
                                        flag);
            *index += 1;
        }

        // The selectors are preserved
        for i in 0..16 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::W_SELECTOR_OFFSET, i)],
                                                          next[get_register_column(constants::W_SELECTOR_OFFSET, i)]),
                                        flag);
            *index += 1;
        }

        let flag2: E = (current[get_register_column(constants::OPCODE_OFFSET, 0)]) *
                      (current[get_register_column(constants::OPCODE_OFFSET, 1)] - E::ONE) *
                      (current[get_register_column(constants::OPCODE_OFFSET, 2)] - E::ONE) *
                      (current[get_register_column(constants::OPCODE_OFFSET, 3)] - E::ONE) *
                      (current[get_register_column(constants::OPCODE_OFFSET, 4)]);

        // SELECTORS shift 1 until the last one is set to 1
        result.aggregate_constraint(*index, is_zero(next[get_register_column(constants::W_SELECTOR_OFFSET, 0)]),
                                    flag2 * (E::ONE - current[get_register_column(constants::W_SELECTOR_OFFSET, 15)]));
        *index += 1;

        for i in 0..15 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::W_SELECTOR_OFFSET, i)],
                                                          next[get_register_column(constants::W_SELECTOR_OFFSET, i+1)]),
                                        flag2 * (E::ONE - current[get_register_column(constants::W_SELECTOR_OFFSET, 15)]));
            *index += 1;
        }

        // Otherwise the selectors are preserved
        for i in 0..16 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::W_SELECTOR_OFFSET, i)],
                                                          next[get_register_column(constants::W_SELECTOR_OFFSET, i)]),
                                        flag2 * current[get_register_column(constants::W_SELECTOR_OFFSET, 15)]);
            *index += 1;
        }
    },
    {
        let mut degrees = vec![[6, trace_length].to_vec(); 3];
        let array = get_alternating_pattern(trace_length);
        let mut vec_array = Vec::new();

        for i in 0..64 {
            vec_array.push(array[i].to_vec());
        }

        degrees.extend(vec_array);
        degrees.extend(vec![[6, trace_length].to_vec(); 2]);
        degrees.extend(vec![[6, trace_length].to_vec(); 48]);
        degrees.extend(vec![[6, trace_length].to_vec(); 16]);
        degrees.extend(vec![[6, trace_length].to_vec(); 36]);
        degrees
    }
);

define_constraint!(
    sha256_second_half_round_constraints,
    |index, result, current, next, periodic_values, trace_length | {
        let flag: E = (next[get_register_column(constants::OPCODE_OFFSET, 0)]) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 1)] - E::ONE) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 2)] - E::ONE) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 3)]) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 4)] - E::ONE);
        let logical_limit = E::from(constants::U32_REGISTER_LIMIT);

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
        result.aggregate_constraint(*index, are_equal(next[get_register_column(constants::AH_OFFSET, 9)] +
                                                      next[get_register_column(constants::CARRY_OFFSET, 4)] * logical_limit,
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

        result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::AH_OFFSET, 8)] +
                                                      next[get_register_column(constants::AH_OFFSET, 9)],

                                                      next[get_register_column(constants::AH_OFFSET, 0)] +
                                                      next[get_register_column(constants::CARRY_OFFSET, 5)] * logical_limit),
                                    flag);
        *index += 1;

        // W, E,F,G,H, CARRY[0..3], CARRY[6..7], HASH are preserved
        for i in 0..16 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::WORK_SCHEDULE_OFFSET, i)],
                                                          next[get_register_column(constants::WORK_SCHEDULE_OFFSET, i)]),
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
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::OUT_HASH_OFFSET, i)],
                                                          next[get_register_column(constants::OUT_HASH_OFFSET, i)]),
                                        flag);
            *index += 1;
        }
    },
    {
        let mut degrees = vec![[6, trace_length].to_vec(); 3];
        let array = get_alternating_pattern(trace_length);
        let mut vec_array = Vec::new();

        for i in 0..64 {
            vec_array.push(array[i].to_vec());
        }

        degrees.extend(vec_array);
        degrees.extend(vec![[6, trace_length].to_vec(); 40]);
        degrees
    }
);

define_constraint!(
    sha256_schedule_word_computation_constraints,
    |index, result, current, next, periodic_values, trace_length | {
        let flag: E = (next[get_register_column(constants::OPCODE_OFFSET, 0)]) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 1)] - E::ONE) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 2)] - E::ONE) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 3)]) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 4)]);
        let logical_limit = E::from(constants::U32_REGISTER_LIMIT);

        // Words shift left by 1
        for i in 0..15 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::WORK_SCHEDULE_OFFSET, i+1)],
                                                        next[get_register_column(constants::WORK_SCHEDULE_OFFSET, i)]),
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

        result.aggregate_constraint(*index, is_linear_decomposition(next[get_register_column(constants::WORK_SCHEDULE_OFFSET, 13)],
                                                                    w13_bit_slice.as_slice(),
                                                                    powers_of_two.as_slice()),
                                    flag);
        *index += 1;

        result.aggregate_constraint(*index, is_linear_decomposition(next[get_register_column(constants::WORK_SCHEDULE_OFFSET, 0)],
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
                next[get_register_column(constants::WORK_SCHEDULE_OFFSET, 8)] +
                current[get_register_column(constants::WORK_SCHEDULE_OFFSET, 0)];

        result.aggregate_constraint(*index, are_equal(w, next[get_register_column(constants::WORK_SCHEDULE_OFFSET, 15)] +
                                                         next[get_register_column(constants::CARRY_OFFSET, 0)] * logical_limit +
                                                         next[get_register_column(constants::CARRY_OFFSET, 1)] * logical_limit +
                                                         next[get_register_column(constants::CARRY_OFFSET, 2)] * logical_limit),
                                    flag);
        *index += 1;

        // The next W is decomposed correctly into bits
        let mut w15_bit_slice = Vec::new();
        for i in 0..32 {
            w15_bit_slice.push(next[get_register_column_with_set(constants::BITS_OFFSET, 6, i, 32)]);
        }

        result.aggregate_constraint(*index, is_linear_decomposition(next[get_register_column(constants::WORK_SCHEDULE_OFFSET, 15)],
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

        result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::AH_OFFSET, 8)],
                                                    next[get_register_column(constants::AH_OFFSET, 8)]),
                                    flag);
        *index += 1;

        result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::AH_OFFSET, 9)],
                                                    next[get_register_column(constants::AH_OFFSET, 9)]),
                                    flag);
        *index += 1;

        for i in 3..8 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::CARRY_OFFSET, i)],
                                                        next[get_register_column(constants::CARRY_OFFSET, i)]),
                                        flag);
            *index += 1;
        }

        for i in 0..8 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::OUT_HASH_OFFSET, i)],
                                                        next[get_register_column(constants::OUT_HASH_OFFSET, i)]),
                                        flag);
            *index += 1;
        }

        // The selectors are preserved
        for i in 0..16 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::W_SELECTOR_OFFSET, i)],
                                                          next[get_register_column(constants::W_SELECTOR_OFFSET, i)]),
                                        flag);
            *index += 1;
        }
    },
    {
        let mut degrees = vec![[6, trace_length].to_vec(); 85];
        degrees.extend(vec![[6, trace_length].to_vec(); 23]);
        degrees.extend(vec![[6, trace_length].to_vec(); 16]);
        degrees
    }
);

define_constraint!(
    sha256_hash_computation_constraints,
    |index, result, current, next, periodic_values, trace_length | {
        let flag: E = (next[get_register_column(constants::OPCODE_OFFSET, 0)]) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 1)] - E::ONE) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 2)]) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 3)] - E::ONE) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 4)] - E::ONE);
        let logical_limit = E::from(constants::U32_REGISTER_LIMIT);

        for i in 0..8 {
            result.aggregate_constraint(*index, are_equal(next[get_register_column(constants::OUT_HASH_OFFSET, i)] +
                                                          next[get_register_column(constants::CARRY_OFFSET, i)] * logical_limit,

                                                          current[get_register_column(constants::AH_OFFSET, i)] +
                                                          current[get_register_column(constants::OUT_HASH_OFFSET, i)]),
                                        flag);
            *index += 1;
                                        
            result.aggregate_constraint(*index, are_equal(next[get_register_column(constants::OUT_HASH_OFFSET, i)],
                                                          next[get_register_column(constants::AH_OFFSET, i)]),
                                        flag);
            *index += 1;
        }

        // W, BITS, BITWISE_OUTPUT, T1, T2 are preserved
        for i in 0..16 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::WORK_SCHEDULE_OFFSET, i)],
                                                          next[get_register_column(constants::WORK_SCHEDULE_OFFSET, i)]),
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
        result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::AH_OFFSET, 8)],
                                                        next[get_register_column(constants::AH_OFFSET, 8)]),
                                    flag);
        *index += 1;

        result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::AH_OFFSET, 9)],
                                                        next[get_register_column(constants::AH_OFFSET, 9)]),
                                    flag);
        *index += 1;

        // Also handle the hash cleanup here
        let cleanup_flag: E = (next[get_register_column(constants::OPCODE_OFFSET, 0)]) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 1)] - E::ONE) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 2)]) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 3)] - E::ONE) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 4)]);

        for i in 0..4 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::OUT_HASH_OFFSET, 2 * i)] * logical_limit +
                                                          current[get_register_column(constants::OUT_HASH_OFFSET, 2 * i + 1)],
                                                          next[get_register_column(constants::HASH_OFFSET, i)]),
                                        cleanup_flag);
            *index += 1;
        }
    },
    vec![[6, trace_length].to_vec(); 264]
);

const fn get_alternating_pattern(trace_length: usize) -> [[usize; 2]; 64] {
    let mut array = [[6, trace_length]; 64];
    let mut index = 1;

    while index < 64 {
        array[index][0] = 7;
        index += 2;
    }

    array
}