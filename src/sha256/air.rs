// Copyright Bogdan Stanculete 2026. All Rights Reserved.

use winterfell::{
    math::ToElements,
    Air, AirContext, Assertion, EvaluationFrame, TraceInfo, TransitionConstraintDegree,
};

use super::{constants, BaseElement, FieldElement, ProofOptions, TRACE_WIDTH, CYCLE_LENGTH};
use super::constraints::{
    get_register_column,
    get_constraints
};

use crate::utils::constraints::ConstraintSpecification;

// SHA-256 AIR
// ================================================================================================

pub struct PublicInputs {
    pub expected_length: BaseElement,
    pub result: [BaseElement; 8],
}

impl ToElements<BaseElement> for PublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        self.result.to_vec()
    }
}

pub struct Sha256Air {
    context: AirContext<BaseElement>,
    expected_length: BaseElement,
    num_blocks: usize,
    result: [BaseElement; 8],
}

impl Air for Sha256Air {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    // Constructor
    // -----------------------------------------------------------------------------------
    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        let reported_length: usize = pub_inputs.expected_length.base_element(0).to_u256().as_u64() as usize;
        let num_blocks: usize = (reported_length - 5) / CYCLE_LENGTH;
        let trace_length = reported_length.next_power_of_two();

        let constraint_vector: Vec<ConstraintSpecification<BaseElement>> = get_constraints(trace_length);
        let mut degrees = Vec::new();

        for constraint in &constraint_vector {
            for degree in &constraint.base_degrees {
                let (base_degree, periodic_columns) = (degree[0], &degree[1..]);
                degrees.push(TransitionConstraintDegree::with_cycles(base_degree, periodic_columns.to_vec()));
            }
        }

        assert_eq!(trace_length, trace_info.length());
        assert_eq!(TRACE_WIDTH, trace_info.width());
        Sha256Air {
            context: AirContext::new(trace_info, degrees, 26, options),
            expected_length: pub_inputs.expected_length,
            num_blocks: num_blocks,
            result: pub_inputs.result,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();
        let mut index = 0;

        debug_assert_eq!(TRACE_WIDTH, current.len());
        debug_assert_eq!(TRACE_WIDTH, next.len());

        let constraint_vector = get_constraints(self.trace_length());
        for constraint in &constraint_vector {
            (constraint.evaluator)(&mut index, result, current, next, periodic_values);
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last_step = self.trace_length() - 1;
        vec![
            // The row counting register starts at 1.
            Assertion::single(get_register_column(constants::NUM_ROWS_OFFSET, 0), 0, BaseElement::ONE),

            // The A...H registers must store the same initial values as the HASH registers
            Assertion::single(get_register_column(constants::AH_OFFSET, 0), 0, constants::INITIAL_HASHES[0]),
            Assertion::single(get_register_column(constants::AH_OFFSET, 1), 0, constants::INITIAL_HASHES[1]),
            Assertion::single(get_register_column(constants::AH_OFFSET, 2), 0, constants::INITIAL_HASHES[2]),
            Assertion::single(get_register_column(constants::AH_OFFSET, 3), 0, constants::INITIAL_HASHES[3]),
            Assertion::single(get_register_column(constants::AH_OFFSET, 4), 0, constants::INITIAL_HASHES[4]),
            Assertion::single(get_register_column(constants::AH_OFFSET, 5), 0, constants::INITIAL_HASHES[5]),
            Assertion::single(get_register_column(constants::AH_OFFSET, 6), 0, constants::INITIAL_HASHES[6]),
            Assertion::single(get_register_column(constants::AH_OFFSET, 7), 0, constants::INITIAL_HASHES[7]),

            // The initial hash values must be those specified by NIST.
            Assertion::single(get_register_column(constants::HASH_OFFSET, 0), 0, constants::INITIAL_HASHES[0]),
            Assertion::single(get_register_column(constants::HASH_OFFSET, 1), 0, constants::INITIAL_HASHES[1]),
            Assertion::single(get_register_column(constants::HASH_OFFSET, 2), 0, constants::INITIAL_HASHES[2]),
            Assertion::single(get_register_column(constants::HASH_OFFSET, 3), 0, constants::INITIAL_HASHES[3]),
            Assertion::single(get_register_column(constants::HASH_OFFSET, 4), 0, constants::INITIAL_HASHES[4]),
            Assertion::single(get_register_column(constants::HASH_OFFSET, 5), 0, constants::INITIAL_HASHES[5]),
            Assertion::single(get_register_column(constants::HASH_OFFSET, 6), 0, constants::INITIAL_HASHES[6]),
            Assertion::single(get_register_column(constants::HASH_OFFSET, 7), 0, constants::INITIAL_HASHES[7]),

            // The final hash values must match the expected hash
            Assertion::single(get_register_column(constants::HASH_OFFSET, 0), last_step, self.result[0]),
            Assertion::single(get_register_column(constants::HASH_OFFSET, 1), last_step, self.result[1]),
            Assertion::single(get_register_column(constants::HASH_OFFSET, 2), last_step, self.result[2]),
            Assertion::single(get_register_column(constants::HASH_OFFSET, 3), last_step, self.result[3]),
            Assertion::single(get_register_column(constants::HASH_OFFSET, 4), last_step, self.result[4]),
            Assertion::single(get_register_column(constants::HASH_OFFSET, 5), last_step, self.result[5]),
            Assertion::single(get_register_column(constants::HASH_OFFSET, 6), last_step, self.result[6]),
            Assertion::single(get_register_column(constants::HASH_OFFSET, 7), last_step, self.result[7]),

            // The Num_Rows counter must match the expected length
            Assertion::single(get_register_column(constants::NUM_ROWS_OFFSET, 0), last_step, self.expected_length),
        ]
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let general_pattern: [BaseElement; 4] = [BaseElement::ONE; 4];
        let attestation_input_pattern: [BaseElement; 4] = [
            BaseElement::ONE, BaseElement::ZERO, BaseElement::ZERO, BaseElement::ZERO];
        let attestation_output_pattern: [BaseElement; 4] = [
            BaseElement::ZERO, BaseElement::ZERO, BaseElement::ZERO, BaseElement::ONE];
        let attestation_middle_pattern: [BaseElement; 4] = [
            BaseElement::ONE, BaseElement::ONE, BaseElement::ONE, BaseElement::ZERO];

        vec![
            // Apply the round cycle mask over the trace to find where each SHA round constraint is applicable.
            build_cycle(self.num_blocks, constants::MESSAGE_SCHEDULE_MASK, false),
            build_cycle(self.num_blocks, constants::FIRST_HALF_ROUND_MASK, true),
            build_cycle(self.num_blocks, constants::SECOND_HALF_ROUND_MASK, true),
            build_cycle(self.num_blocks, constants::HASH_UPDATE_MASK, true),

            // Build cycles for Num_Rows and padding constraints
            build_row_counting_cycle(self.num_blocks),
            build_attestation_cycle_with_pattern(self.num_blocks, general_pattern),
            build_attestation_cycle_with_pattern(self.num_blocks, attestation_input_pattern),
            build_attestation_cycle_with_pattern(self.num_blocks, attestation_middle_pattern),
            build_attestation_cycle_with_pattern(self.num_blocks, attestation_output_pattern),
            build_padding_cycle(self.num_blocks),

            build_general_constraint_cycle(self.num_blocks),

            // Finally include the round constants as a periodic column
            build_cycle(self.num_blocks, constants::ROUND_CONSTANTS_MASK, true),

            build_cycle(self.num_blocks, constants::ROUND_INDEX_MASKS[0], true),
            build_cycle(self.num_blocks, constants::ROUND_INDEX_MASKS[1], true),
            build_cycle(self.num_blocks, constants::ROUND_INDEX_MASKS[2], true),
            build_cycle(self.num_blocks, constants::ROUND_INDEX_MASKS[3], true),
            build_cycle(self.num_blocks, constants::ROUND_INDEX_MASKS[4], true),
            build_cycle(self.num_blocks, constants::ROUND_INDEX_MASKS[5], true),
            build_cycle(self.num_blocks, constants::ROUND_INDEX_MASKS[6], true),
            build_cycle(self.num_blocks, constants::ROUND_INDEX_MASKS[7], true),
            build_cycle(self.num_blocks, constants::ROUND_INDEX_MASKS[8], true),
            build_cycle(self.num_blocks, constants::ROUND_INDEX_MASKS[9], true),
            build_cycle(self.num_blocks, constants::ROUND_INDEX_MASKS[10], true),
            build_cycle(self.num_blocks, constants::ROUND_INDEX_MASKS[11], true),
            build_cycle(self.num_blocks, constants::ROUND_INDEX_MASKS[12], true),
            build_cycle(self.num_blocks, constants::ROUND_INDEX_MASKS[13], true),
            build_cycle(self.num_blocks, constants::ROUND_INDEX_MASKS[14], true),
            build_cycle(self.num_blocks, constants::ROUND_INDEX_MASKS[15], true),
        ]
    }
}

// HELPER FUNCTIONS
// ================================================================================================

fn build_cycle(num_blocks: usize, mask: [BaseElement; CYCLE_LENGTH], include_first_row: bool) -> Vec<BaseElement> {
    let mut array = Vec::new();
    
    let trace_length = num_blocks * CYCLE_LENGTH + 5;
    let padded_length = trace_length.next_power_of_two();

    if !include_first_row {
        array.push(BaseElement::ZERO);
    
        for index in 1..(trace_length - 4) {
            array.push(mask[(index - 1) % CYCLE_LENGTH])
        }
    } else {
        for index in 0..(trace_length - 5) {
            array.push(mask[index % CYCLE_LENGTH])
        }
        array.push(BaseElement::ZERO);
    }

    for _ in (trace_length - 4)..padded_length {
        array.push(BaseElement::ZERO);
    }

    debug_assert_eq!(array.len(), padded_length);
    array    
}

fn build_general_constraint_cycle(num_blocks: usize) -> Vec<BaseElement> {
    let mut array = Vec::new();

    let trace_length = num_blocks * CYCLE_LENGTH + 5;
    let padded_length = trace_length.next_power_of_two();

    for _ in 0..(trace_length - 5) {
        array.push(BaseElement::ONE);
    }

    for _ in (trace_length - 5)..padded_length {
        array.push(BaseElement::ZERO);
    }

    debug_assert_eq!(array.len(), padded_length);
    array
}

fn build_attestation_cycle_with_pattern(num_blocks: usize, pattern: [BaseElement; 4]) -> Vec<BaseElement> {
    let mut array = Vec::new();

    let trace_length = num_blocks * CYCLE_LENGTH + 5;
    let padded_length = trace_length.next_power_of_two();

    for _ in 0..(trace_length - 4) {
        array.push(BaseElement::ZERO);
    }

    for i in 0..4 {
        array.push(pattern[i]);
    }

    for _ in trace_length..padded_length {
        array.push(BaseElement::ZERO);
    }

    debug_assert_eq!(array.len(), padded_length);
    array
}

fn build_padding_cycle(num_blocks: usize) -> Vec<BaseElement> {
    let mut array = Vec::new();

    let trace_length = num_blocks * CYCLE_LENGTH + 5;
    let padded_length = trace_length.next_power_of_two();

    for _ in 0..trace_length {
        array.push(BaseElement::ZERO);
    }

    for _ in trace_length..padded_length {
        array.push(BaseElement::ONE);
    }

    debug_assert_eq!(array.len(), padded_length);
    array
}

fn build_row_counting_cycle(num_blocks: usize) -> Vec<BaseElement> {
    let mut array = Vec::new();

    let trace_length = num_blocks * CYCLE_LENGTH + 5;
    let padded_length = trace_length.next_power_of_two();

    for _ in 0..(trace_length - 1) {
        array.push(BaseElement::ONE);
    }

    for _ in (trace_length - 1)..padded_length {
        array.push(BaseElement::ZERO);
    }

    debug_assert_eq!(array.len(), padded_length);
    array
}
