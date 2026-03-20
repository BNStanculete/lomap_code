// Copyright Bogdan Stanculete 2026. All Rights Reserved.

use core::ops::Range;

use winterfell::{
    math::{FieldElement, StarkField},
    Trace, TraceTable,
};

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
    a - E::ONE
}

// TRAIT TO SIMPLIFY CONSTRAINT AGGREGATION
// ================================================================================================

pub trait EvaluationResult<E> {
    fn aggregate_constraint(&mut self, index: usize, flag: E, value: E);
}

impl<E: FieldElement> EvaluationResult<E> for [E] {
    fn aggregate_constraint(&mut self, index: usize, flag: E, value: E) {
        self[index] += flag * value;
    }
}

impl<E: FieldElement> EvaluationResult<E> for Vec<E> {
    fn aggregate_constraint(&mut self, index: usize, flag: E, value: E) {
        self[index] += flag * value;
    }
}

// OTHER FUNCTIONS
// ================================================================================================

/// Prints out an execution trace.
pub fn print_trace<E: StarkField>(
    trace: &TraceTable<E>,
    multiples_of: usize,
    offset: usize,
    range: Range<usize>,
) {
    let trace_width = trace.width();

    let mut state = vec![E::ZERO; trace_width];
    for i in 0..trace.length() {
        if !(i.wrapping_sub(offset)).is_multiple_of(multiples_of) {
            continue;
        }
        trace.read_row_into(i, &mut state);
        println!(
            "{}\t{:?}",
            i,
            state[range.clone()]
                .iter()
                .map(|v| v.as_int())
                .collect::<Vec<E::PositiveInteger>>()
        );
    }
}

pub fn print_trace_step<E: StarkField>(trace: &[Vec<E>], step: usize) {
    let trace_width = trace.len();
    let mut state = vec![E::ZERO; trace_width];
    for i in 0..trace_width {
        state[i] = trace[i][step];
    }
    println!(
        "{}\t{:?}",
        step,
        state.iter().map(|v| v.as_int()).collect::<Vec<E::PositiveInteger>>()
    );
}

// HELPER FUNCTIONS
// =================================================================================

pub const fn to_base_element(value: u32) -> [u64; 4] {
    [value as u64, 0, 0, 0]
}
