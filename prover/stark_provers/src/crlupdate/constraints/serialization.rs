// Copyright Bogdan Stanculete 2026. All Rights Reserved.

use winterfell::math::{fields::f252::BaseElement, FieldElement};

use crate::utils::constraints::{
    EvaluationResult, ConstraintSpecification,
    are_equal, is_zero
};

use crate::define_constraint;
use super::{constants, get_register_column};

define_constraint!(
    preservation_constraints,
    |index, result, current, next, periodic_values, trace_length | {
        let flag: E = (current[get_register_column(constants::OPCODE_OFFSET, 0)] - E::ONE) *
                      (current[get_register_column(constants::OPCODE_OFFSET, 1)]);
        let next_flag: E = (next[get_register_column(constants::OPCODE_OFFSET, 0)] - E::ONE) *
                           (next[get_register_column(constants::OPCODE_OFFSET, 1)]);

        // HASH, SIGNATURE_ALGO, SERIAL, SIGNATURE are preserved
        result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::SIGNATURE_ALGO_OFFSET, 0)],
                                                        next[get_register_column(constants::SIGNATURE_ALGO_OFFSET, 0)]), 
                                    flag * next_flag);
        *index += 1;            

        for i in 0..4 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::HASH_OFFSET, i)],
                                                          next[get_register_column(constants::HASH_OFFSET, i)]), 
                                        flag * next_flag);
            *index += 1;            

            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::SERIAL_OFFSET, i)],
                                                          next[get_register_column(constants::SERIAL_OFFSET, i)]), 
                                        flag * next_flag);
            *index += 1;
        }

        for i in 0..32 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::SIGNATURE_OFFSET, i)],
                                                          next[get_register_column(constants::SIGNATURE_OFFSET, i)]), 
                                        flag * next_flag);
            *index += 1;
        }
        
        //REMAINING registers are all unused (except for the first during alignment steps)
        for i in 11..53 {
            result.aggregate_constraint(*index, is_zero(current[get_register_column(constants::REMAINING_OFFSET, i)]), flag * next_flag);
            *index += 1
        }

        //No round constants during serialization
        result.aggregate_constraint(*index, is_zero(current[constants::CONSTANT_OFFSET]), flag * next_flag);
        *index += 1;
    },
    {
        let mut degrees = vec![[3].to_vec(); 84];
        degrees
    }
);

define_constraint!(
    bookkeeping_constraints,
    |index, result, current, next, periodic_values, trace_length | {
        let flag: E = (current[get_register_column(constants::OPCODE_OFFSET, 0)] - E::ONE) *
                      (current[get_register_column(constants::OPCODE_OFFSET, 1)]);

        // SHA TRIGGER is updated correctly
        result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::TRIGGER_OFFSET, 0)] * E::from(64u32) + current[get_register_column(constants::TRIGGER_OFFSET, 1)],
                                                      current[constants::BYTE_COUNTER_OFFSET]), 
                                    flag);
        *index += 1;

        // The ALIGNMENT COUNTER is updated correctly
        result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::BYTE_COUNTER_OFFSET, 0)] + current[get_register_column(constants::ALIGNMENT_COUNTER_OFFSET, 0)],
                                                      E::from(96u32)), 
                                    flag);
        *index += 1;

        // ATTESTORS check that serialized values are indeed U8
        for i in 0..32 {
            result.aggregate_constraint(*index, is_zero(current[get_register_column(constants::ATTESTORS_OFFSET, 2 * i)]), 
                                        flag);
            *index += 1;

            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::ATTESTORS_OFFSET, 2 * i)] * E::from(256u32) + current[get_register_column(constants::ATTESTORS_OFFSET, 2 * i + 1)],
                                                          current[get_register_column(constants::FIELD_VALUE_OFFSET, i)]), 
                                        flag);
            *index += 1;
        }

        // A SHA round doesn't trigger unless FIELD_LENGTH = 0 AND we have at lesat 64 bytes in accumulator
        result.aggregate_constraint(*index, is_zero(current[get_register_column(constants::TRIGGER_OFFSET, 2)] * current[get_register_column(constants::FIELD_LENGTH_OFFSET, 0)]), 
                                    flag);
        *index += 1;

        result.aggregate_constraint(*index, is_zero(current[get_register_column(constants::TRIGGER_OFFSET, 2)] * (current[get_register_column(constants::TRIGGER_OFFSET, 0)] - E::ONE)), 
                                    flag);
        *index += 1;

        // CRL END cannot be 1 while LENGTH is non-zero
        result.aggregate_constraint(*index, is_zero(current[get_register_column(constants::CRL_LENGTH_OFFSET, 0)] * current[get_register_column(constants::CRL_END_OFFSET, 0)]), flag);
        *index += 1;
    },
    {
        let mut degrees = vec![[3].to_vec(); 66];
        degrees.extend(vec![[4].to_vec(); 3]);
        degrees
    }
);

define_constraint!(
    accumulator_update_constraints,
    |index, result, current, next, periodic_values, trace_length | {
        let flag: E = (current[get_register_column(constants::OPCODE_OFFSET, 0)] - E::ONE) *
                      (current[get_register_column(constants::OPCODE_OFFSET, 1)]);

        // If FIELD_LENGTH > 0, then next row updates the accumulators
        let field_length_flag: E = flag * current[get_register_column(constants::FIELD_LENGTH_OFFSET, 0)];

        for i in 1..96 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::ACCUMULATOR_OFFSET, i)],
                                                          next[get_register_column(constants::ACCUMULATOR_OFFSET, i - 1)]),
                                        field_length_flag);
            *index += 1;            
        }

        for i in 1..32 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::FIELD_VALUE_OFFSET, i)],
                                                          next[get_register_column(constants::FIELD_VALUE_OFFSET, i - 1)]),
                                        field_length_flag);
            *index += 1;            
        }

        result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::FIELD_VALUE_OFFSET, 0)],
                                                        next[get_register_column(constants::ACCUMULATOR_OFFSET, 95)]),
                                    field_length_flag);
        *index += 1;

        // If FIELD_LENGTH > 0, then decrease length by 1 and increment byte counter
        result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::FIELD_LENGTH_OFFSET, 0)],
                                                        next[get_register_column(constants::FIELD_LENGTH_OFFSET, 0)] + E::ONE),
                                    field_length_flag);
        *index += 1;

        result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::BYTE_COUNTER_OFFSET, 0)] + E::ONE,
                                                        next[get_register_column(constants::BYTE_COUNTER_OFFSET, 0)]),
                                    field_length_flag);
        *index += 1;

        let not_crl_end_flag = field_length_flag * (current[get_register_column(constants::CRL_END_OFFSET, 0)] - E::ONE);

        result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::CRL_LENGTH_OFFSET, 0)],
                                                        next[get_register_column(constants::CRL_LENGTH_OFFSET, 0)] + E::ONE),
                                    not_crl_end_flag);
        *index += 1;
    },
    {
        let mut degrees = vec![[4].to_vec(); 129];
        degrees.extend(vec![[5].to_vec(); 1]);
        degrees
    }
);

// define_constraint!(
//     left_allignment_constraints,
//     |index, result, current, next, periodic_values, trace_length | {
//         let flag: E = current[constants::OPCODE_OFFSET] *
//                      (current[constants::OPCODE_OFFSET] - E::from(2u32)) *
//                      (current[constants::OPCODE_OFFSET] - E::from(3u32)) *

//         // SHA TRIGGER is updated correctly
//         result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::TRIGGER_OFFSET, 0)] * E::from(64u32) + current[get_register_column(constants::TRIGGER_OFFSET, 1)],
//                                                       current[constants::BYTE_COUNTER_OFFSET]), 
//                                     flag);
//         *index += 1;

//         // The ALIGNMENT COUNTER is updated correctly
//         result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::BYTE_COUNTER_OFFSET, 0)] + current[get_register_column(constants::ALIGNMENT_COUNTER_OFFSET, 0)],
//                                                       E::from(96u32)), 
//                                     flag);
//         *index += 1;

//         // ATTESTORS check that serialized values are indeed U8
//         for i in 0..32 {
//             result.aggregate_constraint(*index, is_zero(current[get_register_column(constants::ATTESTORS_OFFSET, 2 * i)]), 
//                                         flag);
//             *index += 1;

//             result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::ATTESTORS_OFFSET, 2 * i)] * E::from(256u32) + current[get_register_column(constants::ATTESTORS_OFFSET, 2 * i + 1)],
//                                                           current[get_register_column(constants::FIELD_VALUE_OFFSET, i)]), 
//                                         flag);
//             *index += 1;
//         }

//         // A SHA round doesn't trigger unless FIELD_LENGTH = 0 AND we have at lesat 64 bytes in accumulator
//         result.aggregate_constraint(*index, is_zero(current[get_register_column(constants::TRIGGER_OFFSET, 2)] * current[get_register_column(constants::FIELD_LENGTH_OFFSET, 0)]), 
//                                     flag);
//         *index += 1;

//         result.aggregate_constraint(*index, is_zero(current[get_register_column(constants::TRIGGER_OFFSET, 2)] * (current[get_register_column(constants::TRIGGER_OFFSET, 0)] - E::ONE)), 
//                                     flag);
//         *index += 1;

//         // CRL END cannot be 1 while LENGTH is non-zero
//         result.aggregate_constraint(*index, is_zero(current[get_register_column(constants::CRL_LENGTH_OFFSET, 0)] * current[get_register_column(constants::CRL_END_OFFSET, 0)]), flag);
//         *index += 1;
//     },
//     {
//         let mut degrees = vec![[4].to_vec(); 66];
//         degrees.extend(vec![[5].to_vec(); 3]);
//         degrees
//     }
// );
