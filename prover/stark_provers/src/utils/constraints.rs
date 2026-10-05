// Copyright Bogdan Stanculete 2026. All Rights Reserved.

use winterfell::math::{fields::f252::BaseElement, FieldElement};

// Rustc fails to detect the use of paste::paste, which triggers an unsued import warning.
#[allow(unused_imports)]
use paste;

// CONSTRAINT EVALUATION HELPERS
// ================================================================================================

/// Returns zero when a == b.
pub fn are_equal<E: FieldElement>(a: E, b: E) -> E {
    a - b
}

/// Returns zero when a == zero.
pub fn is_zero<E: FieldElement>(a: E) -> E {
    a
}

/// Returns zero when a == zero || a == one.
pub fn is_binary<E: FieldElement>(a: E) -> E {
    a * a - a
}

/// Returns zero when a and b are multiplicative inverses.
pub fn is_inverse<E: FieldElement>(a: E, b: E) -> E {
    a * b - E::ONE
}

/// Returns zero when a == one.
pub fn not<E: FieldElement>(a: E) -> E {
    E::ONE - a
}

/// Returns zero when a = 2 * b or a = 2 * b + 1
pub fn is_division_by_two<E: FieldElement>(a: E, b: E) -> E {
    (b * E::from(2u32) - a) * (E::ONE + b * E::from(2u32) - a)
}

/// Returns zero when a == Sum_i b[i] * c[i]
pub fn is_linear_decomposition<E: FieldElement>(a: E, b: &[E], c: &[E]) -> E {
    let mut result = a;

    for index in 0..b.len() {
        result -= b[index] * c[index]
    }

    result
}

// CONSTRAINT SPECIFIER
// ================================================================================================

pub struct ConstraintSpecification<E: FieldElement + From<BaseElement>> {
    pub evaluator: fn(&mut usize, &mut [E], &[E], &[E], &[E]),
    pub base_degrees: Vec<Vec<usize>>,
}

impl<E : FieldElement + From<BaseElement>> ConstraintSpecification<E> {
    pub fn new(
        evaluator: fn(&mut usize, &mut [E], &[E], &[E], &[E]),
        degrees: Vec<Vec<usize>>,
    ) -> Self {
        ConstraintSpecification {
            evaluator: evaluator,
            base_degrees: degrees
        }
    }
}

// MACRO FOR EASE OF CREATION
// ================================================================================================

#[macro_export]
macro_rules! define_constraint {
    (
        $name: ident,
        |$index:ident, $result:ident, $current:ident, $next:ident, $periodic_values: ident, $flag: ident, $base_offset: ident, $trace_length: ident | $evaluator_body: block,
        $degrees: expr
    ) => {
        fn $name<E: FieldElement + From<BaseElement>>(
            $index: &mut usize,
            $result: &mut [E],
            $current: &[E],
            $next: &[E],
            $periodic_values: &[E],
        ) {
            $evaluator_body
        }

        paste::paste! {
            pub fn [<$name _specification>]<E: FieldElement + From<BaseElement>>($flag: E, $base_offset: usize, $trace_length: usize) -> ConstraintSpecification<E> {
                ConstraintSpecification::new($name::<E>, $degrees)
            }
        }
    };
}

// TRAIT TO SIMPLIFY CONSTRAINT AGGREGATION
// ================================================================================================

pub trait EvaluationResult<E> {
    fn aggregate_constraint(&mut self, index: usize, value: E, flag: E);
}

impl<E: FieldElement> EvaluationResult<E> for [E] {
    fn aggregate_constraint(&mut self, index: usize, value: E, flag: E) {
        self[index] += flag * value;
    }
}

impl<E: FieldElement> EvaluationResult<E> for Vec<E> {
    fn aggregate_constraint(&mut self, index: usize, value: E, flag: E) {
        self[index] += flag * value;
    }
}
