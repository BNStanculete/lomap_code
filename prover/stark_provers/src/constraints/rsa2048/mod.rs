use winterfell::math::{fields::f252::BaseElement, FieldElement};

use crate::utils::constraints::{
    EvaluationResult, ConstraintSpecification,
    are_equal, is_binary, not, is_linear_decomposition, is_zero
};

use crate::define_constraint;
use super::{get_register_column, get_register_column_with_set};

mod constants;