// Copyright Bogdan Stanculete 2026. All Rights Reserved.

use winterfell::math::{fields::f252::BaseElement, FieldElement};

use crate::utils::constraints::{
    EvaluationResult, ConstraintSpecification,
    are_equal
};

use crate::define_constraint;
use super::{constants, get_register_column};

define_constraint!(
    poseidon_general_constraints,
    |index, result, current, next, periodic_values, trace_length | {
        let flag: E = (current[get_register_column(constants::OPCODE_OFFSET, 0)] - E::ONE) *
                      (current[get_register_column(constants::OPCODE_OFFSET, 1)] - E::ONE);

        // The public key is preserved
        for i in 0..4 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::PUB_KEY_OFFSET, i)],
                                                          next[get_register_column(constants::PUB_KEY_OFFSET, i)]),
                                        flag);
            *index += 1;
        }

        // SIGNATURE is preserved
        for i in 0..32 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::SIGNATURE_OFFSET, i)],
                                                          next[get_register_column(constants::SIGNATURE_OFFSET, i)]), flag);
            *index += 1;
        }

        // The HASH is preserved
        for i in 0..4 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::HASH_OFFSET, i)], next[get_register_column(constants::HASH_OFFSET, i)]), flag);
            *index += 1;
        }
    },
    {
        let mut degrees = vec![[4].to_vec(); 40];
        degrees
    }
);

define_constraint!(
    poseidon_round_constraints,
    |index, result, current, next, periodic_values, trace_length | {
        let flag: E = (next[get_register_column(constants::OPCODE_OFFSET, 0)] - E::ONE) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 1)] - E::ONE) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 2)]) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 3)] - E::ONE) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 4)] - E::ONE);
        let two128: E = E::from(constants::U128_REGISTER_LIMIT);

        // The poseidon digest is preserved
        for i in 0..2 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::POSEIDON_HASH_OFFSET, i)],
                                                          next[get_register_column(constants::POSEIDON_HASH_OFFSET, i)]),
                                        flag);
            *index += 1;
        }

        // In sets of 12, the poseidon rounds are executed correctly.
        for set in 0..15 {
            // 1. Reconstruct input state
            let input_state: [E; 3] = [
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 1)],

                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 2)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 3)],

                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 4)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 5)],
            ];

            let round_constants: [E; 3] = [
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 6)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 7)],

                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 8)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 9)],

                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 10)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 11)],
            ];

            let output_state: [E; 3] = [
                next[get_register_column(constants::POSEIDON_START_OFFSET, (set + 1) * 12)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, (set + 1) * 12 + 1)],

                next[get_register_column(constants::POSEIDON_START_OFFSET, (set + 1) * 12 + 2)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, (set + 1) * 12 + 3)],

                next[get_register_column(constants::POSEIDON_START_OFFSET, (set + 1) * 12 + 4)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, (set + 1) * 12 + 5)],
            ];

            // 2. Ensure a correct application of the round
            let intermediaries: [E; 3] = [
                input_state[0] + round_constants[0],
                input_state[1] + round_constants[1],
                input_state[2] + round_constants[2]
            ];
            
            result.aggregate_constraint(*index, are_equal(
                intermediaries[0] * (E::ONE + E::ONE + E::ONE) + intermediaries[1] + (intermediaries[2] * intermediaries[2] * intermediaries[2]),
                output_state[0]
            ), flag);
            *index += 1;

            result.aggregate_constraint(*index, are_equal(
                intermediaries[0] - intermediaries[1] + (intermediaries[2] * intermediaries[2] * intermediaries[2]),
                output_state[1]
            ), flag);
            *index += 1;

            result.aggregate_constraint(*index, are_equal(
                intermediaries[0] + intermediaries[1] - (E::ONE + E::ONE) * (intermediaries[2] * intermediaries[2] * intermediaries[2]),
                output_state[2]
            ), flag);
            *index += 1;
        }

        // The first set is dependent on the last set of the previous row
        let output_state: [E; 3] = [
            next[get_register_column(constants::POSEIDON_START_OFFSET, 0)] * two128 +
            next[get_register_column(constants::POSEIDON_START_OFFSET, 1)],

            next[get_register_column(constants::POSEIDON_START_OFFSET, 2)] * two128 +
            next[get_register_column(constants::POSEIDON_START_OFFSET, 3)],

            next[get_register_column(constants::POSEIDON_START_OFFSET, 4)] * two128 +
            next[get_register_column(constants::POSEIDON_START_OFFSET, 5)],
        ];

        let round_constants: [E; 3] = [
            current[get_register_column(constants::POSEIDON_START_OFFSET, 15 * 12 + 6)] * two128 +
            current[get_register_column(constants::POSEIDON_START_OFFSET, 15 * 12 + 7)],

            current[get_register_column(constants::POSEIDON_START_OFFSET, 15 * 12 + 8)] * two128 +
            current[get_register_column(constants::POSEIDON_START_OFFSET, 15 * 12 + 9)],

            current[get_register_column(constants::POSEIDON_START_OFFSET, 15 * 12 + 10)] * two128 +
            current[get_register_column(constants::POSEIDON_START_OFFSET, 15 * 12 + 11)],
        ];

        let input_state: [E; 3] = [
            current[get_register_column(constants::POSEIDON_START_OFFSET, 15 * 12)] * two128 +
            current[get_register_column(constants::POSEIDON_START_OFFSET, 15 * 12 + 1)],

            current[get_register_column(constants::POSEIDON_START_OFFSET, 15 * 12 + 2)] * two128 +
            current[get_register_column(constants::POSEIDON_START_OFFSET, 15 * 12 + 3)],

            current[get_register_column(constants::POSEIDON_START_OFFSET, 15 * 12 + 4)] * two128 +
            current[get_register_column(constants::POSEIDON_START_OFFSET, 15 * 12 + 5)],
        ];

        // 2. Ensure a correct application of the round
        let intermediaries: [E; 3] = [
            input_state[0] + round_constants[0],
            input_state[1] + round_constants[1],
            input_state[2] + round_constants[2]
        ];
        
        result.aggregate_constraint(*index, are_equal(
            intermediaries[0] * (E::ONE + E::ONE + E::ONE) + intermediaries[1] + (intermediaries[2] * intermediaries[2] * intermediaries[2]),
            output_state[0]
        ), flag);
        *index += 1;

        result.aggregate_constraint(*index, are_equal(
            intermediaries[0] - intermediaries[1] + (intermediaries[2] * intermediaries[2] * intermediaries[2]),
            output_state[1]
        ), flag);
        *index += 1;

        result.aggregate_constraint(*index, are_equal(
            intermediaries[0] + intermediaries[1] - (E::ONE + E::ONE) * (intermediaries[2] * intermediaries[2] * intermediaries[2]),
            output_state[2]
        ), flag);
        *index += 1;
    },
    {
        let mut degrees = vec![[9].to_vec(); 98];
        degrees
    }
);

define_constraint!(
    poseidon_output_constraints,
    |index, result, current, next, periodic_values, trace_length | {
        let flag: E = (next[get_register_column(constants::OPCODE_OFFSET, 0)] - E::ONE) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 1)] - E::ONE) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 2)] - E::ONE) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 3)]) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 4)]);
        let two128: E = E::from(constants::U128_REGISTER_LIMIT);

        // The poseidon digest is the first element of the last output state
        for i in 0..2 {
            result.aggregate_constraint(*index, are_equal(next[get_register_column(constants::POSEIDON_START_OFFSET, 11 * 12 + i)],
                                                          next[get_register_column(constants::POSEIDON_HASH_OFFSET, i)]),
                                        flag);
            *index += 1;
        }

        // In sets of 12, the poseidon rounds are executed correctly.
        for set in 0..7 {
            // 1. Reconstruct input state
            let input_state: [E; 3] = [
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 1)],

                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 2)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 3)],

                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 4)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 5)],
            ];

            let round_constants: [E; 3] = [
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 6)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 7)],

                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 8)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 9)],

                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 10)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 11)],
            ];

            let output_state: [E; 3] = [
                next[get_register_column(constants::POSEIDON_START_OFFSET, (set + 1) * 12)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, (set + 1) * 12 + 1)],

                next[get_register_column(constants::POSEIDON_START_OFFSET, (set + 1) * 12 + 2)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, (set + 1) * 12 + 3)],

                next[get_register_column(constants::POSEIDON_START_OFFSET, (set + 1) * 12 + 4)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, (set + 1) * 12 + 5)],
            ];

            // 2. Ensure a correct application of the round
            let intermediaries: [E; 3] = [
                input_state[0] + round_constants[0],
                input_state[1] + round_constants[1],
                input_state[2] + round_constants[2]
            ];
            
            result.aggregate_constraint(*index, are_equal(
                intermediaries[0] * (E::ONE + E::ONE + E::ONE) + intermediaries[1] + (intermediaries[2] * intermediaries[2] * intermediaries[2]),
                output_state[0]
            ), flag);
            *index += 1;

            result.aggregate_constraint(*index, are_equal(
                intermediaries[0] - intermediaries[1] + (intermediaries[2] * intermediaries[2] * intermediaries[2]),
                output_state[1]
            ), flag);
            *index += 1;

            result.aggregate_constraint(*index, are_equal(
                intermediaries[0] + intermediaries[1] - (E::ONE + E::ONE) * (intermediaries[2] * intermediaries[2] * intermediaries[2]),
                output_state[2]
            ), flag);
            *index += 1;
        }

        for set in 7..11 {
            // 1. Reconstruct input state
            let input_state: [E; 3] = [
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 1)],

                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 2)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 3)],

                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 4)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 5)],
            ];

            let round_constants: [E; 3] = [
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 6)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 7)],

                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 8)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 9)],

                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 10)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 11)],
            ];

            let output_state: [E; 3] = [
                next[get_register_column(constants::POSEIDON_START_OFFSET, (set + 1) * 12)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, (set + 1) * 12 + 1)],

                next[get_register_column(constants::POSEIDON_START_OFFSET, (set + 1) * 12 + 2)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, (set + 1) * 12 + 3)],

                next[get_register_column(constants::POSEIDON_START_OFFSET, (set + 1) * 12 + 4)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, (set + 1) * 12 + 5)],
            ];

            // 2. Ensure a correct application of the round
            let intermediaries: [E; 3] = [
                (input_state[0] + round_constants[0]) * (input_state[0] + round_constants[0]) * (input_state[0] + round_constants[0]),
                (input_state[1] + round_constants[1]) * (input_state[1] + round_constants[1]) * (input_state[1] + round_constants[1]),
                (input_state[2] + round_constants[2]) * (input_state[2] + round_constants[2]) * (input_state[2] + round_constants[2])
            ];

            result.aggregate_constraint(*index, are_equal(
                intermediaries[0] * (E::ONE + E::ONE + E::ONE) + intermediaries[1] + intermediaries[2],
                output_state[0]
            ), flag);
            *index += 1;

            result.aggregate_constraint(*index, are_equal(
                intermediaries[0] - intermediaries[1] + intermediaries[2],
                output_state[1]
            ), flag);
            *index += 1;

            result.aggregate_constraint(*index, are_equal(
                intermediaries[0] + intermediaries[1] - (E::ONE + E::ONE) * intermediaries[2],
                output_state[2]
            ), flag);
            *index += 1;
        }

        // The first set is dependent on the last set of the previous row
        let output_state: [E; 3] = [
            next[get_register_column(constants::POSEIDON_START_OFFSET, 0)] * two128 +
            next[get_register_column(constants::POSEIDON_START_OFFSET, 1)],

            next[get_register_column(constants::POSEIDON_START_OFFSET, 2)] * two128 +
            next[get_register_column(constants::POSEIDON_START_OFFSET, 3)],

            next[get_register_column(constants::POSEIDON_START_OFFSET, 4)] * two128 +
            next[get_register_column(constants::POSEIDON_START_OFFSET, 5)],
        ];

        let round_constants: [E; 3] = [
            current[get_register_column(constants::POSEIDON_START_OFFSET, 15 * 12 + 6)] * two128 +
            current[get_register_column(constants::POSEIDON_START_OFFSET, 15 * 12 + 7)],

            current[get_register_column(constants::POSEIDON_START_OFFSET, 15 * 12 + 8)] * two128 +
            current[get_register_column(constants::POSEIDON_START_OFFSET, 15 * 12 + 9)],

            current[get_register_column(constants::POSEIDON_START_OFFSET, 15 * 12 + 10)] * two128 +
            current[get_register_column(constants::POSEIDON_START_OFFSET, 15 * 12 + 11)],
        ];

        let input_state: [E; 3] = [
            current[get_register_column(constants::POSEIDON_START_OFFSET, 15 * 12)] * two128 +
            current[get_register_column(constants::POSEIDON_START_OFFSET, 15 * 12 + 1)],

            current[get_register_column(constants::POSEIDON_START_OFFSET, 15 * 12 + 2)] * two128 +
            current[get_register_column(constants::POSEIDON_START_OFFSET, 15 * 12 + 3)],

            current[get_register_column(constants::POSEIDON_START_OFFSET, 15 * 12 + 4)] * two128 +
            current[get_register_column(constants::POSEIDON_START_OFFSET, 15 * 12 + 5)],
        ];

        // 2. Ensure a correct application of the round
        let intermediaries: [E; 3] = [
            input_state[0] + round_constants[0],
            input_state[1] + round_constants[1],
            input_state[2] + round_constants[2]
        ];
        
        result.aggregate_constraint(*index, are_equal(
            intermediaries[0] * (E::ONE + E::ONE + E::ONE) + intermediaries[1] + (intermediaries[2] * intermediaries[2] * intermediaries[2]),
            output_state[0]
        ), flag);
        *index += 1;

        result.aggregate_constraint(*index, are_equal(
            intermediaries[0] - intermediaries[1] + (intermediaries[2] * intermediaries[2] * intermediaries[2]),
            output_state[1]
        ), flag);
        *index += 1;

        result.aggregate_constraint(*index, are_equal(
            intermediaries[0] + intermediaries[1] - (E::ONE + E::ONE) * (intermediaries[2] * intermediaries[2] * intermediaries[2]),
            output_state[2]
        ), flag);
        *index += 1;
    },
    {
        let mut degrees = vec![[9].to_vec(); 44];
        degrees
    }
);

define_constraint!(
    poseidon_input_constraints,
    |index, result, current, next, periodic_values, trace_length | {
        let flag: E = (next[get_register_column(constants::OPCODE_OFFSET, 0)] - E::ONE) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 1)] - E::ONE) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 2)] - E::ONE) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 3)]) *
                      (next[get_register_column(constants::OPCODE_OFFSET, 4)] - E::ONE);
        let two128: E = E::from(constants::U128_REGISTER_LIMIT);

        // The poseidon digest is preserved
        for i in 0..2 {
            result.aggregate_constraint(*index, are_equal(current[get_register_column(constants::POSEIDON_HASH_OFFSET, i)],
                                                          next[get_register_column(constants::POSEIDON_HASH_OFFSET, i)]),
                                        flag);
            *index += 1;
        }

        // In sets of 12, the poseidon rounds are executed correctly.
        for set in 4..15 {
            // 1. Reconstruct input state
            let input_state: [E; 3] = [
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 1)],

                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 2)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 3)],

                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 4)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 5)],
            ];

            let round_constants: [E; 3] = [
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 6)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 7)],

                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 8)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 9)],

                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 10)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 11)],
            ];

            let output_state: [E; 3] = [
                next[get_register_column(constants::POSEIDON_START_OFFSET, (set + 1) * 12)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, (set + 1) * 12 + 1)],

                next[get_register_column(constants::POSEIDON_START_OFFSET, (set + 1) * 12 + 2)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, (set + 1) * 12 + 3)],

                next[get_register_column(constants::POSEIDON_START_OFFSET, (set + 1) * 12 + 4)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, (set + 1) * 12 + 5)],
            ];

            // 2. Ensure a correct application of the round
            let intermediaries: [E; 3] = [
                input_state[0] + round_constants[0],
                input_state[1] + round_constants[1],
                input_state[2] + round_constants[2]
            ];
            
            result.aggregate_constraint(*index, are_equal(
                intermediaries[0] * (E::ONE + E::ONE + E::ONE) + intermediaries[1] + (intermediaries[2] * intermediaries[2] * intermediaries[2]),
                output_state[0]
            ), flag);
            *index += 1;

            result.aggregate_constraint(*index, are_equal(
                intermediaries[0] - intermediaries[1] + (intermediaries[2] * intermediaries[2] * intermediaries[2]),
                output_state[1]
            ), flag);
            *index += 1;

            result.aggregate_constraint(*index, are_equal(
                intermediaries[0] + intermediaries[1] - (E::ONE + E::ONE) * (intermediaries[2] * intermediaries[2] * intermediaries[2]),
                output_state[2]
            ), flag);
            *index += 1;
        }

        for set in 0..4 {
            // 1. Reconstruct input state
            let input_state: [E; 3] = [
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 1)],

                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 2)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 3)],

                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 4)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 5)],
            ];

            let round_constants: [E; 3] = [
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 6)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 7)],

                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 8)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 9)],

                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 10)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, set * 12 + 11)],
            ];

            let output_state: [E; 3] = [
                next[get_register_column(constants::POSEIDON_START_OFFSET, (set + 1) * 12)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, (set + 1) * 12 + 1)],

                next[get_register_column(constants::POSEIDON_START_OFFSET, (set + 1) * 12 + 2)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, (set + 1) * 12 + 3)],

                next[get_register_column(constants::POSEIDON_START_OFFSET, (set + 1) * 12 + 4)] * two128 +
                next[get_register_column(constants::POSEIDON_START_OFFSET, (set + 1) * 12 + 5)],
            ];

            // 2. Ensure a correct application of the round
            let intermediaries: [E; 3] = [
                (input_state[0] + round_constants[0]) * (input_state[0] + round_constants[0]) * (input_state[0] + round_constants[0]),
                (input_state[1] + round_constants[1]) * (input_state[1] + round_constants[1]) * (input_state[1] + round_constants[1]),
                (input_state[2] + round_constants[2]) * (input_state[2] + round_constants[2]) * (input_state[2] + round_constants[2])
            ];

            result.aggregate_constraint(*index, are_equal(
                intermediaries[0] * (E::ONE + E::ONE + E::ONE) + intermediaries[1] + intermediaries[2],
                output_state[0]
            ), flag);
            *index += 1;

            result.aggregate_constraint(*index, are_equal(
                intermediaries[0] - intermediaries[1] + intermediaries[2],
                output_state[1]
            ), flag);
            *index += 1;

            result.aggregate_constraint(*index, are_equal(
                intermediaries[0] + intermediaries[1] - (E::ONE + E::ONE) * intermediaries[2],
                output_state[2]
            ), flag);
            *index += 1;
        }
    },
    {
        let mut degrees = vec![[9].to_vec(); 120];
        degrees
    }
);
