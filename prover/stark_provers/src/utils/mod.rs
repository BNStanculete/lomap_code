// Copyright Bogdan Stanculete 2026. All Rights Reserved.
use num_bigint::BigUint;
use std::fmt::Debug;

pub mod constraints;

// HELPER FUNCTIONS
// =================================================================================

pub const fn to_base_element(value: u32) -> [u64; 4] {
    [value as u64, 0, 0, 0]
}

// Trait to simplify big-int parsing
// ================================================================================================

pub trait Limb:
    Copy + Debug + Default + TryFrom<u128>
{
    const BITS: usize;
}

impl Limb for u32 {
    const BITS: usize = 32;
}

impl Limb for u64 {
    const BITS: usize = 64;
}

impl Limb for u128 {
    const BITS: usize = 128;
}

pub fn decimal_to_limbs<T: Limb>(
    s: &str,
    n_BITS: usize,
) -> Result<Vec<T>, String> {
    let n = BigUint::parse_bytes(s.as_bytes(), 10)
        .ok_or_else(|| "Invalid decimal integer".to_string())?;

    if n.bits() > n_BITS as u64 {
        return Err(format!("Integer exceeds {} BITS", n_BITS));
    }

    let num_limbs = n_BITS.div_ceil(T::BITS);
    let mask = (BigUint::from(1u8) << T::BITS) - BigUint::from(1u8);

    let mut value = n;
    let mut limbs = Vec::with_capacity(num_limbs);

    for _ in 0..num_limbs {
        let limb = &value & &mask;
        
        // Convert the limb to little-endian bytes.
        let bytes = limb.to_bytes_le();

        // Reconstruct a u128 from at most 16 bytes.
        let mut buf = [0u8; 16];
        buf[..bytes.len()].copy_from_slice(&bytes);

        let limb_u128 = u128::from_le_bytes(buf);

        limbs.push(
            T::try_from(limb_u128)
             .map_err(|_| "Limb conversion failed".to_string())?
        );

        value >>= T::BITS;
    }

    // We now reverse for big-endian order
    limbs.reverse();

    Ok(limbs)
}