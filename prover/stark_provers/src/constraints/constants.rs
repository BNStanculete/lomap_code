// These constants are more general, and usable in each sub-trace.

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
