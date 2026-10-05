// Copyright Bogdan Stanculete 2026. All Rights Reserved.

use winterfell::math::{fields::f252::BaseElement, FieldElement};
use super::CYCLE_LENGTH;

use crate::utils::to_base_element;

// REGISTER OFFSETS
// ================================================================================================

// Sub-trace agnostic offsets
pub const NUM_ROWS_OFFSET: usize = 0;
pub const OPCODE_OFFSET: usize = 1;
pub const PUB_KEY_OFFSET: usize = 6;
pub const SIGNATURE_OFFSET: usize = 42;
pub const HASH_OFFSET: usize = 74;
pub const CONSTANT_OFFSET: usize = 78;
pub const SIGNATURE_ALGO_OFFSET: usize = 79;

// Hash trace offsets
pub const WORK_SCHEDULE_OFFSET: usize = 80;
pub const AH_OFFSET: usize = 96;
pub const BITS_OFFSET: usize = 106;

pub const BITWISE_OUTPUT_OFFSET: usize = 330;
pub const CARRY_OFFSET: usize = 332;
pub const OUT_HASH_OFFSET: usize = 340;
pub const W_SELECTOR_OFFSET: usize = 348;

// Signature trace offsets
pub const NEXT_E_OFFSET: usize = 80;
pub const BIT_E_OFFSET: usize = 81;
pub const REPRESENTATIVE_OFFSETS: usize = 82;
pub const RESULT_OFFSET: usize = 114;
pub const SIGNATURE_CARRY_OFFSET: usize = 178;
pub const QUOTIENT_OFFSET: usize = 241;
pub const SIGNATURE_ATTESTORS_OFFSET: usize = 273;

// Poseidon offsets
pub const POSEIDON_START_OFFSET: usize = 80;
pub const POSEIDON_SELECTOR_OFFSET: usize = 242;
pub const POSEIDON_HASH_OFFSET: usize = 400;

// SHA-256 CONSTANTS
// ================================================================================================

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

// POWERS OF 2
// ================================================================================================
pub const U32_REGISTER_LIMIT: BaseElement = BaseElement::new([1 << 32 as u64, 0, 0, 0]);
pub const U64_REGISTER_LIMIT: BaseElement = BaseElement::new([0, 1, 0, 0]);
pub const U128_REGISTER_LIMIT: BaseElement = BaseElement::new([0, 0, 1, 0]);
pub const POWERS_OF_TWO : [BaseElement; 32] = build_powers_of_two_elements();
const fn build_powers_of_two_elements() -> [BaseElement; 32] {
    let mut array = [BaseElement::ONE; 32];
    let mut index = 1;
    let mut power_of_two: u64 = 2;

    while index < 32 {
        array[index] = BaseElement::new([power_of_two, 0, 0, 0]);

        power_of_two *= 2;
        index += 1;
    }

    array
}

