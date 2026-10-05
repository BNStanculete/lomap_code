use winterfell::math::{fields::f252::BaseElement, FieldElement};
use crate::utils::constraints::ConstraintSpecification;

pub mod sha256;
pub mod rsa2048;
pub mod poseidon;

pub mod constants;

// HELPER FUNCTIONS
// ================================================================================================

pub const fn get_register_column(base_offset: usize, relative_offset: usize, index: usize) -> usize {
    base_offset + relative_offset + index
}

pub const fn get_register_column_with_set(base_offset: usize, relative_offset: usize, set: usize, index: usize, registers_per_set: usize) -> usize {
    base_offset + relative_offset + set * registers_per_set + index
}
