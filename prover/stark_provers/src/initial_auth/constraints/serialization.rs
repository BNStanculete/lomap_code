use winterfell::math::{fields::f252::BaseElement, FieldElement};

use crate::utils::constraints::{
    EvaluationResult, ConstraintSpecification,
    are_equal, is_zero
};

use crate::define_constraint;
use super::{constants, get_register_column};

define_constraint!(
    serialization_general_constraints,
    |index, result, current, next, periodic_values, trace_length| {
        let flag: E = (next[get_register_column(constants::OPCODE_OFFSET, 0)] - E::ONE) *
                       next[get_register_column(constants::OPCODE_OFFSET, 1)];

        // // The signature is preserved
        // for i in 0..32 {
        //     result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::SIGNATURE_OFFSET, i)],
        //                                                   next[get_register_column(constants::SIGNATURE_OFFSET, i)]),
        //                                 flag);
        //     *index += 1;
        // }

        // // The public exponent is preserved
        // for i in 0..4 {
        //     result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::PUB_KEY_OFFSET, i)],
        //                                                   next[get_register_column(constants::PUB_KEY_OFFSET, i)]),
        //                                 flag);
        //     *index += 1;
        // }

        // // The Poseidon hash is preserved
        // for i in 0..2 {
        //     result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::POSEIDON_HASH_OFFSET, i)],
        //                                                   next[get_register_column(constants::POSEIDON_HASH_OFFSET, i)]),
        //                                 flag);
        //     *index += 1;
        // }

        // The round constant is zero
        result.aggregate_constraint(*index, is_zero(next[get_register_column(constants::CONSTANT_OFFSET, 0)]), flag);
        *index += 1;

        // The CRL hash is preserved
        // for i in 0..4 {
        //     result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::HASH_OFFSET, i)],
        //                                                   next[get_register_column(constants::HASH_OFFSET, i)]),
        //                                 flag);
        //     *index += 1;
        // }

        // SHA TRIGGER is updated correctly
        result.aggregate_constraint(*index, are_equal(next[get_register_column(constants::SHA_TRIGGER_OFFSET, 0)] * E::from(64u32) + next[get_register_column(constants::SHA_TRIGGER_OFFSET, 1)],
                                                      next[constants::BYTE_COUNTER_OFFSET]), 
                                    flag);
        *index += 1;

        // The ALIGNMENT COUNTER is updated correctly
        result.aggregate_constraint(*index, are_equal(next[get_register_column(constants::BYTE_COUNTER_OFFSET, 0)] + next[get_register_column(constants::ALIGNMENT_COUNTER_OFFSET, 0)],
                                                      E::from(96u32)), 
                                    flag);
        *index += 1;


        // ATTESTORS check that serialized values are indeed U8
        for i in 0..32 {
            result.aggregate_constraint(*index, is_zero(next[get_register_column(constants::SERIALIZER_ATTESTORS_OFFSET, 2 * i)]), 
                                        flag);
            *index += 1;

            result.aggregate_constraint(*index, are_equal(next[get_register_column(constants::SERIALIZER_ATTESTORS_OFFSET, 2 * i)] * E::from(256u32) +
                                                          next[get_register_column(constants::SERIALIZER_ATTESTORS_OFFSET, 2 * i + 1)],
                                                          next[get_register_column(constants::FIELD_VALUE_OFFSET, i)]), 
                                        flag);
            *index += 1;
        }

        // A SHA round doesn't trigger unless FIELD_LENGTH = 0 AND we have at lesat 64 bytes in accumulator
        result.aggregate_constraint(*index, is_zero(next[get_register_column(constants::SHA_TRIGGER_OFFSET, 2)] *
                                                    next[get_register_column(constants::FIELD_LENGTH_OFFSET, 0)]), 
                                    flag);
        *index += 1;

        result.aggregate_constraint(*index, is_zero(next[get_register_column(constants::SHA_TRIGGER_OFFSET, 2)] *
                                                    (next[get_register_column(constants::SHA_TRIGGER_OFFSET, 0)] - E::ONE)), 
                                    flag);
        *index += 1;

        // CRL END cannot be 1 while LENGTH is non-zero
        result.aggregate_constraint(*index, is_zero(next[get_register_column(constants::CRL_LENGTH_OFFSET, 0)] *
                                                    next[get_register_column(constants::CRL_END_OFFSET, 0)]),
                                    flag);
        *index += 1;
    },
    {
        let mut degrees = vec![[3].to_vec(); 45];

        degrees.extend(vec![[3].to_vec(); 64]);
        degrees.extend(vec![[4].to_vec(); 3]);

        degrees
    }
);

// Note: although we usually apply constraints on the "next" row, we cannot enforce ACCUMULATOR updates in this way.
// This is because FIELD_LENGTH is set to a non-zero value in the row where the prover inputs PKI data.
// Hence, we can only enforce this constraints when the current row has a non-zero field length.
define_constraint!(
    serialization_accumulation_constraints,
    |index, result, current, next, periodic_values, trace_length| {
        let flag: E = (current[get_register_column(constants::OPCODE_OFFSET, 0)] - E::ONE) *
                       current[get_register_column(constants::OPCODE_OFFSET, 1)] *
                       current[get_register_column(constants::FIELD_LENGTH_OFFSET, 0)];

        // The accumulators shift left 1 step
        for i in 0..95 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::ACCUMULATORS_OFFSET, i)],
                                                          next[get_register_column(constants::ACCUMULATORS_OFFSET, i+1)]),
                                        flag);
            *index += 1;
        }

        // The current field value is accumulated.
        result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::FIELD_VALUE_OFFSET, 0)],
                                                      next[get_register_column(constants::ACCUMULATORS_OFFSET, 0)]),
                                    flag);
        *index += 1;

        // The field value buffer shifts by 1
        for i in 1..32 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::FIELD_VALUE_OFFSET, i)],
                                                          next[get_register_column(constants::FIELD_VALUE_OFFSET, i - 1)]),
                                        flag);
            *index += 1;            
        }

        // If FIELD_LENGTH > 0, then decrease length by 1 and increment byte counter
        result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::FIELD_LENGTH_OFFSET, 0)],
                                                        next[get_register_column(constants::FIELD_LENGTH_OFFSET, 0)] + E::ONE),
                                    flag);
        *index += 1;

        result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::BYTE_COUNTER_OFFSET, 0)] + E::ONE,
                                                        next[get_register_column(constants::BYTE_COUNTER_OFFSET, 0)]),
                                    flag);
        *index += 1;
    },
    {
        let mut degrees = vec![[4].to_vec(); 130];

        degrees
    }
);

define_constraint!(
    serialization_alignment_constraints,
    |index, result, current, next, periodic_values, trace_length| {
        // Left alignment
        let left_flag: E = (next[get_register_column(constants::OPCODE_OFFSET, 0)] - E::ONE) *
                       next[get_register_column(constants::OPCODE_OFFSET, 1)] *
                       (next[get_register_column(constants::OPCODE_OFFSET, 2)] - E::ONE) *
                       next[get_register_column(constants::OPCODE_OFFSET, 3)] *
                       (next[get_register_column(constants::OPCODE_OFFSET, 4)] - E::ONE);

        for i in 0..95 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::ACCUMULATORS_OFFSET, i+1)],
                                                          next[get_register_column(constants::ACCUMULATORS_OFFSET, i)]),
                                        left_flag);
            *index += 1;
        }

        result.aggregate_constraint(*index, is_zero(next[get_register_column(constants::ACCUMULATORS_OFFSET, 95)]), left_flag);
        *index += 1;

        // Right alignment
        let right_flag: E = (next[get_register_column(constants::OPCODE_OFFSET, 0)] - E::ONE) *
                       next[get_register_column(constants::OPCODE_OFFSET, 1)] *
                       (next[get_register_column(constants::OPCODE_OFFSET, 2)] - E::ONE) *
                       next[get_register_column(constants::OPCODE_OFFSET, 3)] *
                       next[get_register_column(constants::OPCODE_OFFSET, 4)];

        for i in 1..96 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::ACCUMULATORS_OFFSET, i-1)],
                                                          next[get_register_column(constants::ACCUMULATORS_OFFSET, i)]),
                                        right_flag);
            *index += 1;
        }

        result.aggregate_constraint(*index, is_zero(next[get_register_column(constants::ACCUMULATORS_OFFSET, 0)]), right_flag);
        *index += 1;
    },
    {
        let mut degrees = vec![[6].to_vec(); 194];

        degrees
    }
);

define_constraint!(
    serialization_hash_input_output_constraints,
    |index, result, current, next, periodic_values, trace_length| {
        // Constraints controlling the start of the HASH subtrace

        let hash_in_flag: E = next[get_register_column(constants::OPCODE_OFFSET, 0)] *
                       (next[get_register_column(constants::OPCODE_OFFSET, 1)] - E::ONE) *
                       (next[get_register_column(constants::OPCODE_OFFSET, 2)] - E::ONE) *
                       (next[get_register_column(constants::OPCODE_OFFSET, 3)] - E::ONE) *
                       (next[get_register_column(constants::OPCODE_OFFSET, 4)] - E::ONE);
        
        // We combine the rightmost 64 Accumulators into 16 32-bit words.
        for i in 0..16 {
            let combined_input: E = current[get_register_column(constants::ACCUMULATORS_OFFSET, 32 + 4 * i)] * E::from(constants::POWERS_OF_TWO[0]) +
                                    current[get_register_column(constants::ACCUMULATORS_OFFSET, 32 + 4 * i + 1)] * E::from(constants::POWERS_OF_TWO[8]) +
                                    current[get_register_column(constants::ACCUMULATORS_OFFSET, 32 + 4 * i + 2)] * E::from(constants::POWERS_OF_TWO[16]) +
                                    current[get_register_column(constants::ACCUMULATORS_OFFSET, 32 + 4 * i + 3)] * E::from(constants::POWERS_OF_TWO[24]);

            result.aggregate_constraint(*index, are_equal(next[get_register_column(constants::WORK_SCHEDULE_OFFSET, 15 - i)],
                                                          combined_input),
                                        hash_in_flag);
            *index += 1;
        }

        // We enforce that the A..H registers match the OUT_HASH registers
        for i in 0..8 {
            result.aggregate_constraint(*index, are_equal(next[get_register_column(constants::AH_OFFSET, i)],
                                                          next[get_register_column(constants::OUT_HASH_OFFSET, i)]),
                                        hash_in_flag);
            *index += 1;
        }

        // We enforce that the W_SELECTORS are set to the starting position
        result.aggregate_constraint(*index, is_zero(next[get_register_column(constants::W_SELECTOR_OFFSET, 0)] - E::ONE), hash_in_flag);
        *index += 1;

        for i in 1..16 {
            result.aggregate_constraint(*index, is_zero(next[get_register_column(constants::W_SELECTOR_OFFSET, i)]), hash_in_flag);
            *index += 1;
        }

        // We enforce that the OUT_HASH is initialized from the previous hash
        for i in 0..4 {
            result.aggregate_constraint(*index, are_equal(next[get_register_column(constants::OUT_HASH_OFFSET, 2 * i)] * E::from(constants::U32_REGISTER_LIMIT) +
                                                          next[get_register_column(constants::OUT_HASH_OFFSET, 2 * i + 1)],
                                                          next[get_register_column(constants::HASH_OFFSET, i)]),
                                        hash_in_flag);
            *index += 1;
        }

        // After output the BYTE_COUNTER is decreased by 64
        let hash_out_flag: E = (next[get_register_column(constants::OPCODE_OFFSET, 0)] - E::ONE) *
                       next[get_register_column(constants::OPCODE_OFFSET, 1)] *
                       next[get_register_column(constants::OPCODE_OFFSET, 2)] *
                       (next[get_register_column(constants::OPCODE_OFFSET, 3)] - E::ONE) *
                       (next[get_register_column(constants::OPCODE_OFFSET, 4)] - E::ONE);
        
        result.aggregate_constraint(*index, are_equal(next[get_register_column(constants::BYTE_COUNTER_OFFSET, 0)] + E::from(64u32),
                                                      current[get_register_column(constants::BYTE_COUNTER_OFFSET, 0)]),
                                    hash_out_flag);
        *index += 1;

        result.aggregate_constraint(*index, is_zero(next[get_register_column(constants::SHA_TRIGGER_OFFSET, 0)]), hash_out_flag);
        *index += 1;
    },
    {
        let mut degrees = vec![[6].to_vec(); 46];

        degrees
    }    
);

define_constraint!(
    serialization_non_revocation_constraints,
    |index, result, current, next, periodic_values, trace_length| {
        let flag: E = (next[get_register_column(constants::OPCODE_OFFSET, 0)] - E::ONE) *
                       next[get_register_column(constants::OPCODE_OFFSET, 1)] *
                       next[get_register_column(constants::OPCODE_OFFSET, 2)] *
                       (next[get_register_column(constants::OPCODE_OFFSET, 3)] - E::ONE) *
                       next[get_register_column(constants::OPCODE_OFFSET, 4)];
        for i in 0..4 {
            let diff: E = next[get_register_column(constants::SERIAL_OFFSET, i)] -
                          next[get_register_column(constants::REVOCATION_ATTESTORS_OFFSET, i)];
            
            let inverse: E = next[get_register_column(constants::REVOCATION_ATTESTORS_OFFSET, 4 + 2 * i)] * E::from(constants::U128_REGISTER_LIMIT) +
                             next[get_register_column(constants::REVOCATION_ATTESTORS_OFFSET, 5 + 2 * i)];

            result.aggregate_constraint(*index, is_zero(diff * (E::ONE - next[get_register_column(constants::REVOCATION_ATTESTORS_OFFSET, 12 + i)])), flag);
            *index += 1;

            result.aggregate_constraint(*index, are_equal(next[get_register_column(constants::REVOCATION_ATTESTORS_OFFSET, 12 + i)],
                                                          diff * inverse),
                                        flag);
            *index += 1;
        }

        result.aggregate_constraint(*index, are_equal(next[get_register_column(constants::REVOCATION_ATTESTORS_OFFSET, 16)],
                                                      next[get_register_column(constants::REVOCATION_ATTESTORS_OFFSET, 12)] +
                                                      next[get_register_column(constants::REVOCATION_ATTESTORS_OFFSET, 13)] +
                                                      next[get_register_column(constants::REVOCATION_ATTESTORS_OFFSET, 14)] +
                                                      next[get_register_column(constants::REVOCATION_ATTESTORS_OFFSET, 15)]),
                                    flag);
        *index += 1;

        // At least 1 register must have an inverse to prove that the two serials are different.
        result.aggregate_constraint(*index, is_zero((next[get_register_column(constants::REVOCATION_ATTESTORS_OFFSET, 16)] - E::ONE) *
                                                    (next[get_register_column(constants::REVOCATION_ATTESTORS_OFFSET, 16)] - E::from(2u32)) *
                                                    (next[get_register_column(constants::REVOCATION_ATTESTORS_OFFSET, 16)] - E::from(3u32)) *
                                                    (next[get_register_column(constants::REVOCATION_ATTESTORS_OFFSET, 16)] - E::from(4u32))),
                                    flag);
        *index += 1;
    },
    {
        let mut degrees = vec![[7].to_vec(); 8];

        degrees.extend(vec![[6].to_vec(); 1]);
        degrees.extend(vec![[9].to_vec(); 1]);

        degrees
    }
);
