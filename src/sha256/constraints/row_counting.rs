// Copyright Bogdan Stanculete 2026. All Rights Reserved.

use winterfell::math::{fields::f252::BaseElement, FieldElement};

use crate::utils::constraints::{
    EvaluationResult, ConstraintSpecification,
    are_equal
};

use crate::define_constraint;
use super::{
    constants,
    get_register_column
};

define_constraint!(
    row_counting_constraint,
    |index, result, current, next, periodic_values, trace_length | {
        let flag = periodic_values[constants::ROW_UPDATE_FLAG_INDEX];

        // Enforce update of Num_Rows, column
        result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::NUM_ROWS_OFFSET, 0)] + E::ONE,
                                                    next[get_register_column(constants::NUM_ROWS_OFFSET, 0)]),
                                    flag);
        *index += 1;
    },
    vec![[1, trace_length].to_vec()]
);
