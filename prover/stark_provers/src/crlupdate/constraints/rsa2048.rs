// Copyright Bogdan Stanculete 2026. All Rights Reserved.

use winterfell::math::{fields::f252::BaseElement, FieldElement};

use crate::utils::constraints::{
    EvaluationResult, ConstraintSpecification,
    are_equal, is_binary, not, is_linear_decomposition, is_zero, is_division_by_two
};

use crate::define_constraint;
use super::{constants, get_register_column, get_register_column_with_set};

define_constraint!(
    rsa2048_general_constraints,
    |index, result, current, next, periodic_values, trace_length | {
        let flag: E = (current[get_register_column(constants::OPCODE_OFFSET, 0)]) *
                      (current[get_register_column(constants::OPCODE_OFFSET, 1)]);

        result.aggregate_constraint(*index, is_binary(current[get_register_column(constants::BIT_E_OFFSET, 0)]), flag);
        *index += 1;

        // The HASH is preserved
        for i in 0..4 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::HASH_OFFSET, i)], next[get_register_column(constants::HASH_OFFSET, i)]), flag);
            *index += 1;
        }

        // The poseidon hash is preserved
        for i in 0..2 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::POSEIDON_HASH_OFFSET, i)],
                                                          next[get_register_column(constants::POSEIDON_HASH_OFFSET, i)]), flag);
            *index += 1;
        }
    },
    {
        let mut degrees = vec![[4].to_vec(); 7];
        degrees
    }
);

define_constraint!(
    rsa2048_attestation_constraints,
    |index, result, current, next, periodic_values, trace_length | {
        let flag: E = (next[get_register_column(constants::OPCODE_OFFSET, 0)]) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 1)]) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 2)] - E::ONE) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 3)]) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 4)]);
        let two: E = E::from(2u32);

        // Attestors are correctly halved each row
        for i in 0..127 {
            result.aggregate_constraint(*index,
                (next[get_register_column(constants::SIGNATURE_ATTESTORS_OFFSET, i)] * two - current[get_register_column(constants::SIGNATURE_ATTESTORS_OFFSET, i)]) *
                (next[get_register_column(constants::SIGNATURE_ATTESTORS_OFFSET, i)] * two + E::ONE - current[get_register_column(constants::SIGNATURE_ATTESTORS_OFFSET, i)]),
                                        flag);
            // result.aggregate_constraint(*index, is_division_by_two(current[get_register_column(constants::SIGNATURE_ATTESTORS_OFFSET, i)],
            //                                                        next[get_register_column(constants::SIGNATURE_ATTESTORS_OFFSET, i)]),
            //                             flag);

            *index += 1;
        }

        // The remainder of the registers are preserved
        result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::NEXT_E_OFFSET, 0)], next[get_register_column(constants::NEXT_E_OFFSET, 0)]), flag);
        *index += 1;

        result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::BIT_E_OFFSET, 0)], next[get_register_column(constants::BIT_E_OFFSET, 0)]), flag);
        *index += 1;

        for i in 0..4 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::PUB_KEY_OFFSET, i)], next[get_register_column(constants::PUB_KEY_OFFSET, i)]), flag);
            *index += 1;
        }

        for i in 0..64 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::RESULT_OFFSET, i)], next[get_register_column(constants::RESULT_OFFSET, i)]), flag);
            *index += 1;

            if i < 63 {
                result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::SIGNATURE_CARRY_OFFSET, i)], next[get_register_column(constants::SIGNATURE_CARRY_OFFSET, i)]), flag);
                *index += 1;
            }
        }

        for i in 0..32 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::REPRESENTATIVE_OFFSETS, i)], next[get_register_column(constants::REPRESENTATIVE_OFFSETS, i)]), flag);
            *index += 1;

            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::QUOTIENT_OFFSET, i)], next[get_register_column(constants::QUOTIENT_OFFSET, i)]), flag);
            *index += 1;
        }
        for i in 0..32 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::SIGNATURE_OFFSET, i)],
                                                          next[get_register_column(constants::SIGNATURE_OFFSET, i)]), flag);
            *index += 1;
        }
    },
    {
        let mut degrees = vec![[7].to_vec(); 127];
        degrees.extend(vec![[6, trace_length].to_vec(); 6]);
        degrees.extend(vec![[6, trace_length].to_vec(); 127]);
        degrees.extend(vec![[6, trace_length].to_vec(); 96]);

        degrees
    }
);

define_constraint!(
    rsa2048_padding_constraints,
    |index, result, current, next, periodic_values, trace_length | {
        let flag: E = (next[get_register_column(constants::OPCODE_OFFSET, 0)]) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 1)]) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 2)]) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 3)] - E::ONE) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 4)] - E::ONE);

        // Everything is preserved
        for i in 0..127 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::SIGNATURE_ATTESTORS_OFFSET, 0)], next[get_register_column(constants::SIGNATURE_ATTESTORS_OFFSET, 0)]), flag);
            *index += 1;
        }

        result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::NEXT_E_OFFSET, 0)], next[get_register_column(constants::NEXT_E_OFFSET, 0)]), flag);
        *index += 1;

        result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::BIT_E_OFFSET, 0)], next[get_register_column(constants::BIT_E_OFFSET, 0)]), flag);
        *index += 1;

        for i in 0..4 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::PUB_KEY_OFFSET, i)], next[get_register_column(constants::PUB_KEY_OFFSET, i)]), flag);
            *index += 1;
        }

        for i in 0..64 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::RESULT_OFFSET, 0)], next[get_register_column(constants::RESULT_OFFSET, 0)]), flag);
            *index += 1;

            if i < 63 {
                result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::CARRY_OFFSET, 0)], next[get_register_column(constants::CARRY_OFFSET, 0)]), flag);
                *index += 1;
            }
        }

        for i in 0..32 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::REPRESENTATIVE_OFFSETS, 0)], next[get_register_column(constants::REPRESENTATIVE_OFFSETS, 0)]), flag);
            *index += 1;

            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::QUOTIENT_OFFSET, 0)], next[get_register_column(constants::QUOTIENT_OFFSET, 0)]), flag);
            *index += 1;
        }
        for i in 0..32 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::SIGNATURE_OFFSET, i)],
                                                          next[get_register_column(constants::SIGNATURE_OFFSET, i)]), flag);
            *index += 1;
        }
    },
    {
        let mut degrees = vec![[7].to_vec(); 127];
        degrees.extend(vec![[6, trace_length].to_vec(); 6]);
        degrees.extend(vec![[6, trace_length].to_vec(); 127]);
        degrees.extend(vec![[6, trace_length].to_vec(); 96]);

        degrees
    }
);

define_constraint!(
    rsa2048_multiplication_constraints,
    |index, result, current, next, periodic_values, trace_length | {
        let flag: E = (next[get_register_column(constants::OPCODE_OFFSET, 0)]) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 1)]) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 2)] - E::ONE) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 3)] - E::ONE) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 4)]);
        let two: E = E::from(2u32);
        let logical_limit: E = E::from(constants::U64_REGISTER_LIMIT);

        // Attestors are half of the result / carry
        for i in 0..64 {
            result.aggregate_constraint(*index,
                (next[get_register_column(constants::SIGNATURE_ATTESTORS_OFFSET, i)] * two - next[get_register_column(constants::RESULT_OFFSET, i)]) *
                (next[get_register_column(constants::SIGNATURE_ATTESTORS_OFFSET, i)] * two + E::ONE - next[get_register_column(constants::RESULT_OFFSET, i)]),
                                        flag);
            *index += 1;
        }

        for i in 0..63 {
            result.aggregate_constraint(*index,
                (next[get_register_column(constants::SIGNATURE_ATTESTORS_OFFSET, 64 + i)] * two - next[get_register_column(constants::SIGNATURE_CARRY_OFFSET, i)]) *
                (next[get_register_column(constants::SIGNATURE_ATTESTORS_OFFSET, 64 + i)] * two + E::ONE - next[get_register_column(constants::SIGNATURE_CARRY_OFFSET, i)]),
                                        flag);
            *index += 1;
        }

        // The limb multiplication is correct
        let mut mul_results: Vec<E> = vec![E::ZERO; 64];
        for i in 0..32 {
            for j in 0..32 {
                mul_results[i + j + 1] += current[get_register_column(constants::SIGNATURE_OFFSET, i)] * current[get_register_column(constants::SIGNATURE_OFFSET, j)];
            }
        }
        
        result.aggregate_constraint(*index, are_equal(next[get_register_column(constants::RESULT_OFFSET, 63)] +
                                                      next[get_register_column(constants::SIGNATURE_CARRY_OFFSET, 62)] * logical_limit,
                                                      mul_results[63]), flag);
        *index += 1;

        for i in 1..63 {
            result.aggregate_constraint(*index, are_equal(next[get_register_column(constants::RESULT_OFFSET, i)] +
                                                        next[get_register_column(constants::SIGNATURE_CARRY_OFFSET, i - 1)] * logical_limit,
                                                        mul_results[i] + next[get_register_column(constants::SIGNATURE_CARRY_OFFSET, i)]), flag);
            *index += 1;
        }

        result.aggregate_constraint(*index, are_equal(next[get_register_column(constants::RESULT_OFFSET, 0)],
                                                      next[get_register_column(constants::SIGNATURE_CARRY_OFFSET, 0)]), flag);
        *index += 1;

        // The previous attestors for RESULT and CARRY[0] are 0 (no overflow in result)
        for i in 0..65 {
            result.aggregate_constraint(*index, is_zero(current[get_register_column(constants::SIGNATURE_ATTESTORS_OFFSET, i)]), flag);
            *index += 1;
        }

        // The Remainder of the registers are preserved
        result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::NEXT_E_OFFSET, 0)], next[get_register_column(constants::NEXT_E_OFFSET, 0)]), flag);
        *index += 1;

        result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::BIT_E_OFFSET, 0)], next[get_register_column(constants::BIT_E_OFFSET, 0)]), flag);
        *index += 1;

        for i in 0..4 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::PUB_KEY_OFFSET, i)], next[get_register_column(constants::PUB_KEY_OFFSET, i)]), flag);
            *index += 1;
        }

        for i in 0..32 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::REPRESENTATIVE_OFFSETS, 0)], next[get_register_column(constants::REPRESENTATIVE_OFFSETS, 0)]), flag);
            *index += 1;

            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::QUOTIENT_OFFSET, 0)], next[get_register_column(constants::QUOTIENT_OFFSET, 0)]), flag);
            *index += 1;
        }
        for i in 0..32 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::SIGNATURE_OFFSET, i)],
                                                          next[get_register_column(constants::SIGNATURE_OFFSET, i)]), flag);
            *index += 1;
        }
    },
    {
        let mut degrees = vec![[7].to_vec(); 127];
        degrees.extend(vec![[6, trace_length].to_vec(); 129]);
        degrees.extend(vec![[6, trace_length].to_vec(); 6]);
        degrees.extend(vec![[6, trace_length].to_vec(); 96]);

        degrees
    }
);

define_constraint!(
    rsa2048_conditional_multiplication_constraints,
    |index, result, current, next, periodic_values, trace_length | {
        let flag: E = (next[get_register_column(constants::OPCODE_OFFSET, 0)]) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 1)]) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 2)]) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 3)] - E::ONE) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 4)]);
        let multi_flag: E = flag * next[get_register_column(constants::BIT_E_OFFSET, 0)];
        let padding_flag: E = flag * not(next[get_register_column(constants::BIT_E_OFFSET, 0)]);

        let two: E = E::from(2u32);
        let logical_limit: E = E::from(constants::U64_REGISTER_LIMIT);


        // for i in 32..64 {
        //     result.aggregate_constraint(*index,
        //         (next[get_register_column(constants::SIGNATURE_ATTESTORS_OFFSET, i)] * two - next[get_register_column(constants::RESULT_OFFSET, i)]) *
        //         (next[get_register_column(constants::SIGNATURE_ATTESTORS_OFFSET, i)] * two + E::ONE - next[get_register_column(constants::RESULT_OFFSET, i)]),
        //                                 multi_flag);
        //     *index += 1;
        // }
        // for i in 0..63 {
        //     result.aggregate_constraint(*index,
        //         (next[get_register_column(constants::SIGNATURE_ATTESTORS_OFFSET, 64 + i)] * two - next[get_register_column(constants::SIGNATURE_CARRY_OFFSET, i)]) *
        //         (next[get_register_column(constants::SIGNATURE_ATTESTORS_OFFSET, 64 + i)] * two + E::ONE - next[get_register_column(constants::SIGNATURE_CARRY_OFFSET, i)]),
        //                                 multi_flag);
        //     *index += 1;
        // }

        // TEST
        result.aggregate_constraint(*index, are_equal(next[get_register_column(constants::BIT_E_OFFSET, 0)], E::ZERO), multi_flag);
        *index += 1;

        // Attestors retain the previous values (SKIP)
        for i in 0..127 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::SIGNATURE_ATTESTORS_OFFSET, i)],
                                                          next[get_register_column(constants::SIGNATURE_ATTESTORS_OFFSET, i)]), padding_flag);
            *index += 1;
        }

        // The carries and results are 0
        for i in 0..64 {
            result.aggregate_constraint(*index, is_zero(next[get_register_column(constants::RESULT_OFFSET, i)]), padding_flag);
            *index += 1;

            if i < 63 {
                result.aggregate_constraint(*index, is_zero(next[get_register_column(constants::SIGNATURE_CARRY_OFFSET, i)]), padding_flag);
                *index += 1;
            }
        }

        // The limb multiplication is correct (MULTIPLICATION)
        // let mut mul_results: Vec<E> = vec![E::ZERO; 64];
        // for i in 0..32 {
        //     for j in 0..32 {
        //         mul_results[i + j + 1] += current[get_register_column(constants::SIGNATURE_OFFSET, i)] * current[get_register_column(constants::REPRESENTATIVE_OFFSETS, j)];
        //     }
        // }
        
        // result.aggregate_constraint(*index, are_equal(next[get_register_column(constants::RESULT_OFFSET, 63)] +
        //                                               next[get_register_column(constants::SIGNATURE_CARRY_OFFSET, 62)] * logical_limit,
        //                                               mul_results[63]), multi_flag);
        // *index += 1;

        // for i in 1..63 {
        //     result.aggregate_constraint(*index, are_equal(next[get_register_column(constants::RESULT_OFFSET, i)] +
        //                                                 next[get_register_column(constants::SIGNATURE_CARRY_OFFSET, i - 1)] * logical_limit,
        //                                                 mul_results[i] + next[get_register_column(constants::SIGNATURE_CARRY_OFFSET, i)]), multi_flag);
        //     *index += 1;
        // }

        // result.aggregate_constraint(*index, are_equal(next[get_register_column(constants::RESULT_OFFSET, 0)],
        //                                               next[get_register_column(constants::SIGNATURE_CARRY_OFFSET, 0)]), multi_flag);
        // *index += 1;

        // The previous attestors for RESULT and CARRY[0] are 0 (no overflow in result)
        for i in 0..65 {
            result.aggregate_constraint(*index, is_zero(current[get_register_column(constants::SIGNATURE_ATTESTORS_OFFSET, i)]), flag);
            *index += 1;
        }

        // The current bit of E is decomposed
        // CURRENTLY THIS IS NOT GENERAL, BUT TAILORED TO THE COMMONE EXPONENT 65537
        result.aggregate_constraint(*index, are_equal(next[get_register_column(constants::PUB_KEY_OFFSET, 3)], next[get_register_column(constants::NEXT_E_OFFSET, 0)]), flag);
        *index += 1;

        result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::PUB_KEY_OFFSET, 3)], 
                                                      next[get_register_column(constants::NEXT_E_OFFSET, 0)] * two + next[get_register_column(constants::BIT_E_OFFSET, 0)]), flag);
        *index += 1;

        // The Remainder of the registers are preserved
        for i in 0..3 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::PUB_KEY_OFFSET, i)], next[get_register_column(constants::PUB_KEY_OFFSET, i)]), flag);
            *index += 1;
        }

        for i in 0..32 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::REPRESENTATIVE_OFFSETS, 0)], next[get_register_column(constants::REPRESENTATIVE_OFFSETS, 0)]), flag);
            *index += 1;

            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::QUOTIENT_OFFSET, 0)], next[get_register_column(constants::QUOTIENT_OFFSET, 0)]), flag);
            *index += 1;
        }
        for i in 0..32 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::SIGNATURE_OFFSET, i)],
                                                          next[get_register_column(constants::SIGNATURE_OFFSET, i)]), flag);
            *index += 1;
        }

        // Attestors are half of the result / carry (MULTIPLICATION)
    },
    {
        let mut degrees = vec![[7].to_vec(); 127];
        degrees.extend(vec![[6, trace_length].to_vec(); 254]);
        degrees.extend(vec![[6, trace_length].to_vec(); 129]);
        degrees.extend(vec![[6, trace_length].to_vec(); 5]);
        degrees.extend(vec![[6, trace_length].to_vec(); 96]);

        degrees
    }
);