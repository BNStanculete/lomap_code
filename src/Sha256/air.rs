// Copyright Bogdan Stanculete 2026. All Rights Reserved.

use winterfell::{
    math::ToElements,
    Air, AirContext, Assertion, EvaluationFrame, TraceInfo, TransitionConstraintDegree,
};

use super::{constants, BaseElement, FieldElement, ProofOptions, TRACE_WIDTH, PADDED_CYCLE_LENGTH};
use crate::utils::{
    are_equal, is_zero
};


// CONSTANTS
// ======================================================================================

const WORD_PRESERVATION_CYCLE: [BaseElement; PADDED_CYCLE_LENGTH] = build_word_preservation_cycle();
const fn build_word_preservation_cycle() -> [BaseElement; PADDED_CYCLE_LENGTH] {
    let mut array = [BaseElement::ZERO; PADDED_CYCLE_LENGTH];
    let mut index = 0;

    while index < 30 {
        array[index] = BaseElement::ONE;
        index += 1;
    }

    array
}

const MESSAGE_SCHEDULE_CYCLE: [BaseElement; PADDED_CYCLE_LENGTH] = build_message_schedule_cycle();
const fn build_message_schedule_cycle() -> [BaseElement; PADDED_CYCLE_LENGTH] {
    let mut array = [BaseElement::ZERO; PADDED_CYCLE_LENGTH];
    let mut index = 32;

    while index < 177 {
        array[index] = BaseElement::ONE;
        index += 3;
    }

    array
}

const FIRST_HALF_ROUND_CYCLE: [BaseElement; PADDED_CYCLE_LENGTH] = build_round_cycle(0);
const SECOND_HALF_ROUND_CYCLE: [BaseElement; PADDED_CYCLE_LENGTH] = build_round_cycle(1);
const fn build_round_cycle(offset: usize) -> [BaseElement; PADDED_CYCLE_LENGTH] {
    let mut array = [BaseElement::ZERO; PADDED_CYCLE_LENGTH];
    let mut index = offset;

    while index <= 30 {
        array[index] = BaseElement::ONE;
        index += 2;
    }

    index = 33 + offset;
    while index < 177 {
        array[index] = BaseElement::ONE;
        index += 3;
    }

    array    
}

// SHA-256 AIR
// ======================================================================================

pub struct PublicInputs {
    pub expected_length: usize,
    pub result: [BaseElement; 8],
}

impl ToElements<BaseElement> for PublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        self.result.to_vec()
    }
}

pub struct Sha256Air {
    context: AirContext<BaseElement>,
    result: [BaseElement; 8],
}

impl Air for Sha256Air {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    // Constructor
    // -----------------------------------------------------------------------------------
    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        let degrees = vec![
            TransitionConstraintDegree::new(1)
        ];

        assert_eq!(pub_inputs.expected_length, trace_info.width());
        Sha256Air {
            context: AirContext::new(trace_info, degrees, 17, options),
            result: pub_inputs.result,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();

        debug_assert_eq!(TRACE_WIDTH, current.len());
        debug_assert_eq!(TRACE_WIDTH, next.len());

        // Enforce row counting column
        result[0] = are_equal(next[0], current[0] + E::ONE);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        vec![
            // The row counting register starts at 1.
            Assertion::single(0, 0, BaseElement::ONE),

            // The initial hash values must be those specified by NIST.
            Assertion::single(263, 0, constants::INITIAL_HASHES[0]),
            Assertion::single(264, 0, constants::INITIAL_HASHES[1]),
            Assertion::single(265, 0, constants::INITIAL_HASHES[2]),
            Assertion::single(266, 0, constants::INITIAL_HASHES[3]),
            Assertion::single(267, 0, constants::INITIAL_HASHES[4]),
            Assertion::single(268, 0, constants::INITIAL_HASHES[5]),
            Assertion::single(269, 0, constants::INITIAL_HASHES[6]),
            Assertion::single(270, 0, constants::INITIAL_HASHES[7]),

            // The final hash valeus match the expected ones
            Assertion::single(263, 0, self.result[0]),
            Assertion::single(264, 0, self.result[1]),
            Assertion::single(265, 0, self.result[2]),
            Assertion::single(266, 0, self.result[3]),
            Assertion::single(267, 0, self.result[4]),
            Assertion::single(268, 0, self.result[5]),
            Assertion::single(269, 0, self.result[6]),
            Assertion::single(270, 0, self.result[7]),
        ]
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        vec![
            WORD_PRESERVATION_CYCLE.to_vec(),
            MESSAGE_SCHEDULE_CYCLE.to_vec(),
            FIRST_HALF_ROUND_CYCLE.to_vec(),
            SECOND_HALF_ROUND_CYCLE.to_vec(),
            constants::get_round_constants(),    
        ]
    }
}
