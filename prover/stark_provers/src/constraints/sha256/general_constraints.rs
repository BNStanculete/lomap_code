use winterfell::math::{fields::f252::BaseElement, FieldElement};

use crate::utils::constraints::{
    EvaluationResult, ConstraintSpecification,
    are_equal, is_binary, not, is_linear_decomposition, is_zero
};

use crate::define_constraint;
use constants as sha256_constants;
use super::super::{constants, get_register_column, get_register_column_with_set};

define_constraint!(
    general_constraints,
    |index, result, current, next, periodic_values, flag, base_offset, trace_length | {
        // The number of rows is incremented correctly.
        result.aggregate_constraint(*index, are_equal(
            current[get_register_column(base_offset, sha256_constants::NUM_ROWS_OFFSET, 0)],
            next[get_register_column(base_offset, sha256_constants::NUM_ROWS_OFFSET, 0)] + E::ONE
        ), flag);
        *index += 1;

        // The division by 177 is correct
        result.aggregate_constraint(*index, are_equal(
            current[get_register_column(base_offset, sha256_constants::NUM_ROWS_OFFSET, 0)],
            current[get_register_column(base_offset, sha256_constants::QUOTIENT_OFFSET, 0)] * sha256_constants::DIVISION_FACTOR +
            current[get_register_column(base_offset, sha256_constants::REMAINDER_OFFSET, 0)]
        ), flag);
        *index += 1;

        // The inverse is correctly computed
        let to_invert_factor: E = (sha256_constants::SUBTRACTION_TERM - current[get_register_column(base_offset, sha256_constants::REMAINDER_OFFSET, 0)]);
        let inverse: E = (current[get_register_column(base_offset, sha256_constants::INVERSE_OFFSET, 0)] * constants::U128_REGISTER_LIMIT +
                          current[get_register_column(base_offset, sha256_constants::INVERSE_OFFSET, 1)]);

        result.aggregate_constraint(*index, is_zero(to_invert_factor * (E::ONE - to_invert_factor * inverse)), flag);
        *index += 1;

        // The inverse is zero when the factor is zero.
        result.aggregate_constraint(*index, is_zero(inverse * (E::ONE - to_invert_factor * inverse)), flag);
        *index += 1;

        // When the remainder is 176, the next remainder is 0.
        result.aggregate_constraint(*index, is_zero((E::ONE - to_invert_factor * inverse) * next[get_register_column(base_offset, sha256_constants::REMAINDER_OFFSET, 0)]), flag);
        *index += 1;

        // The padding bit is a binary value
        result.aggregate_constraint(*index, is_binary(current[get_register_column(base_offset, sha256_constants::PADDING_BIT_OFFSET, 0)]), flag);
        *index += 1;

        // The Control Codes are binary values
        for i in 0..2 {
            result.aggregate_constraint(*index, is_binary(current[get_register_column(base_offset, sha256_constants::CONTROL_CODE_OFFSET, i)]), flag);
            *index += 1;
        }

        // The word selectors are binary values
        for i in 0..17 {
            result.aggregate_constraint(*index, is_binary(current[get_register_column(base_offset, sha256_constants::W_SELECTOR_OFFSET, i)]), flag);
            *index += 1;
        }

        // All bits are binary values
        for i in 0..224 {
            result.aggregate_constraint(*index, is_binary(current[get_register_column(base_offset, sha256_constants::BITS_OFFSET, i)]), flag);
            *index += 1;
        }

        // The carries are binary values
        for i in 0..8 {
            result.aggregate_constraint(*index, is_binary(current[get_register_column(base_offset, sha256_constants::CARRY_OFFSET, i)]), flag);
            *index += 1;
        }

        // When the padding bit is active, all of the other registers are preserved
        for i in sha256_constants::CONTROL_CODE_OFFSET, sha256_constants::TRACE_WIDTH {
            result.aggregate_constraint(*index, are_equal(
                current[get_register_column(base_offset, sha256_constants::CONTROL_CODE_OFFSET, i)],
                next[get_register_column(base_offset, sha256_constants::CONTROL_CODE_OFFSET, i)]
            ), flag * current[get_register_column(base_offset, sha256_constants::PADDING_BIT_OFFSET)]);
            *index += 1;
        }
    },
    {
        let mut degrees = vec![[1].to_vec(); 2];

        degrees.extend(vec![[3].to_vec(); 3]);
        degrees.extend(vec![[2].to_vec(); 252]);
        degrees.extend(vec![[2].to_vec(); sha256_constants::TRACE_WIDTH - sha256_constants::CONTROL_CODE_OFFSET + 1]);
        
        degrees
    }
);

define_constraint!(
    state_machine_constraints,
    |index, result, current, next, periodic_values, flag, base_offset, trace_length | {
    },
    {
        let mut degrees = vec![[1].to_vec(); 0];
        
        degrees
    }
);