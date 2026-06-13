// Copyright Bogdan Stanculete 2026. All Rights Reserved.

use winterfell::math::{fields::f252::BaseElement, FieldElement};

use crate::utils::constraints::{
    EvaluationResult, ConstraintSpecification,
    are_equal, is_zero
};

use crate::define_constraint;
use super::{constants, get_register_column};

define_constraint!(
    general_constraint,
    |index, result, current, next, periodic_values, trace_length | {
        // All bits are binary values
        result.aggregate_constraint(*index, are_equal(current[constants::NUM_ROWS_OFFSET] + E::ONE, next[constants::NUM_ROWS_OFFSET]), E::ONE);
        *index += 1;
    },
    vec![[1].to_vec(); 1]
);

define_constraint!(
    general_serialization_constraint,
    |index, result, current, next, periodic_values, trace_length | {
        // All bits are binary values
        let flag: E = current[constants::OPCODE_OFFSET] *
                     (current[constants::OPCODE_OFFSET] - E::from(2u32)) *
                     (current[constants::OPCODE_OFFSET] - E::from(3u32));

        result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::TRIGGER_OFFSET, 0)] * E::from(64u32) + current[get_register_column(constants::TRIGGER_OFFSET, 1)],
                                                      current[constants::BYTE_COUNTER_OFFSET]), 
                                    flag);
        *index += 1;

        result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::BYTE_COUNTER_OFFSET, 0)] + current[get_register_column(constants::ALIGNMENT_COUNTER_OFFSET, 0)],
                                                      E::from(96u32)), 
                                    flag);
        *index += 1;

        for i in 0..32 {
            result.aggregate_constraint(*index, is_zero(current[get_register_column(constants::ATTESTORS_OFFSET, 2 * i)]), 
                                        flag);
            *index += 1;

            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::ATTESTORS_OFFSET, 2 * i)] * E::from(256u32) + current[get_register_column(constants::ATTESTORS_OFFSET, 2 * i + 1)],
                                                          current[get_register_column(constants::FIELD_VALUE_OFFSET, i)]), 
                                        flag);
            *index += 1;
        }

        result.aggregate_constraint(*index, is_zero(current[get_register_column(constants::TRIGGER_OFFSET, 2)] * current[get_register_column(constants::FIELD_LENGTH_OFFSET, 0)]), 
                                    flag);
        *index += 1;

        result.aggregate_constraint(*index, is_zero(current[get_register_column(constants::TRIGGER_OFFSET, 2)] * (current[get_register_column(constants::TRIGGER_OFFSET, 0)] - E::ONE)), 
                                    flag);
        *index += 1;
    },
    {
        let mut degrees = vec![[4].to_vec(); 67];
        degrees.extend(vec![[5].to_vec(); 2]);
        degrees
    }
);