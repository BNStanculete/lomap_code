// Copyright Bogdan Stanculete 2026. All Rights Reserved.

pub mod constraints;

// HELPER FUNCTIONS
// =================================================================================

pub const fn to_base_element(value: u32) -> [u64; 4] {
    [value as u64, 0, 0, 0]
}
