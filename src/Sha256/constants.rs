// Copyright Bogdan Stanculete 2026. All Rights Reserved.

use winterfell::math::{fields::f252::BaseElement, FieldElement};
use super::{CYCLE_LENGTH, PADDED_CYCLE_LENGTH};

use crate::utils::to_base_element;

pub const INITIAL_HASHES : [BaseElement; 8] = [
    BaseElement::new(to_base_element(0x6a09e667u32)),
    BaseElement::new(to_base_element(0xbb67ae85u32)),
    BaseElement::new(to_base_element(0x3c6ef372u32)),
    BaseElement::new(to_base_element(0xa54ff53au32)),
    BaseElement::new(to_base_element(0x510e527fu32)),
    BaseElement::new(to_base_element(0x9b05688cu32)),
    BaseElement::new(to_base_element(0x1f83d9abu32)),
    BaseElement::new(to_base_element(0x5be0cd19u32)),
];

pub const ROUND_CONSTANTS : [BaseElement; 64] = [
    BaseElement::new(to_base_element(0x428a2f98u32)),
    BaseElement::new(to_base_element(0x71374491u32)),
    BaseElement::new(to_base_element(0xb5c0fbcfu32)),
    BaseElement::new(to_base_element(0xe9b5dba5u32)),
    BaseElement::new(to_base_element(0x3956c25bu32)),
    BaseElement::new(to_base_element(0x59f111f1u32)),
    BaseElement::new(to_base_element(0x923f82a4u32)),
    BaseElement::new(to_base_element(0xab1c5ed5u32)),
    BaseElement::new(to_base_element(0xd807aa98u32)),
    BaseElement::new(to_base_element(0x12835b01u32)),
    BaseElement::new(to_base_element(0x243185beu32)),
    BaseElement::new(to_base_element(0x550c7dc3u32)),
    BaseElement::new(to_base_element(0x72be5d74u32)),
    BaseElement::new(to_base_element(0x80deb1feu32)),
    BaseElement::new(to_base_element(0x9bdc06a7u32)),
    BaseElement::new(to_base_element(0xc19bf174u32)),
    BaseElement::new(to_base_element(0xe49b69c1u32)),
    BaseElement::new(to_base_element(0xefbe4786u32)),
    BaseElement::new(to_base_element(0x0fc19dc6u32)),
    BaseElement::new(to_base_element(0x240ca1ccu32)),
    BaseElement::new(to_base_element(0x2de92c6fu32)),
    BaseElement::new(to_base_element(0x4a7484aau32)),
    BaseElement::new(to_base_element(0x5cb0a9dcu32)),
    BaseElement::new(to_base_element(0x76f988dau32)),
    BaseElement::new(to_base_element(0x983e5152u32)),
    BaseElement::new(to_base_element(0xa831c66du32)),
    BaseElement::new(to_base_element(0xb00327c8u32)),
    BaseElement::new(to_base_element(0xbf597fc7u32)),
    BaseElement::new(to_base_element(0xc6e00bf3u32)),
    BaseElement::new(to_base_element(0xd5a79147u32)),
    BaseElement::new(to_base_element(0x06ca6351u32)),
    BaseElement::new(to_base_element(0x14292967u32)),
    BaseElement::new(to_base_element(0x27b70a85u32)),
    BaseElement::new(to_base_element(0x2e1b2138u32)),
    BaseElement::new(to_base_element(0x4d2c6dfcu32)),
    BaseElement::new(to_base_element(0x53380d13u32)),
    BaseElement::new(to_base_element(0x650a7354u32)),
    BaseElement::new(to_base_element(0x766a0abbu32)),
    BaseElement::new(to_base_element(0x81c2c92eu32)),
    BaseElement::new(to_base_element(0x92722c85u32)),
    BaseElement::new(to_base_element(0xa2bfe8a1u32)),
    BaseElement::new(to_base_element(0xa81a664bu32)),
    BaseElement::new(to_base_element(0xc24b8b70u32)),
    BaseElement::new(to_base_element(0xc76c51a3u32)),
    BaseElement::new(to_base_element(0xd192e819u32)),
    BaseElement::new(to_base_element(0xd6990624u32)),
    BaseElement::new(to_base_element(0xf40e3585u32)),
    BaseElement::new(to_base_element(0x106aa070u32)),
    BaseElement::new(to_base_element(0x19a4c116u32)),
    BaseElement::new(to_base_element(0x1e376c08u32)),
    BaseElement::new(to_base_element(0x2748774cu32)),
    BaseElement::new(to_base_element(0x34b0bcb5u32)),
    BaseElement::new(to_base_element(0x391c0cb3u32)),
    BaseElement::new(to_base_element(0x4ed8aa4au32)),
    BaseElement::new(to_base_element(0x5b9cca4fu32)),
    BaseElement::new(to_base_element(0x682e6ff3u32)),
    BaseElement::new(to_base_element(0x748f82eeu32)),
    BaseElement::new(to_base_element(0x78a5636fu32)),
    BaseElement::new(to_base_element(0x84c87814u32)),
    BaseElement::new(to_base_element(0x8cc70208u32)),
    BaseElement::new(to_base_element(0x90befffau32)),
    BaseElement::new(to_base_element(0xa4506cebu32)),
    BaseElement::new(to_base_element(0xbef9a3f7u32)),
    BaseElement::new(to_base_element(0xc67178f2u32)),
];

// ROUND CONSTANTS
// ================================================================================================

/// Returns the SHA-256 round constants as a periodic column
pub fn get_round_constants() -> Vec<BaseElement> {
    let mut constants = Vec::new();
    let mut current_constant = 0;

    // Every 2nd row for the first 30 rows we add a round constant
    for _ in 0..15 {
        constants.push(ROUND_CONSTANTS[current_constant]);
        constants.push(BaseElement::ZERO);
        current_constant += 1;
    }

    for _ in 0..48 {
        constants.push(BaseElement::ZERO);
        constants.push(ROUND_CONSTANTS[current_constant]);
        constants.push(BaseElement::ZERO);
    }

    // Check that we exhausted the 177 rows of each cycle
    debug_assert_eq!(constants.len(), CYCLE_LENGTH);

    for _ in CYCLE_LENGTH..PADDED_CYCLE_LENGTH {
        constants.push(BaseElement::ZERO);
    }

    constants
}
