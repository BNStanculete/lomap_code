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

// CRLUpdate AIR
// ================================================================================================

pub struct PublicInputs {
    pub expected_length: BaseElement,
}

impl ToElements<BaseElement> for PublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![]
    }
}

pub struct CRLUpdateAir {
    context: AirContext<BaseElement>,
}

impl Air for CRLUpdateAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    // Constructor
    // -----------------------------------------------------------------------------------
    fn new(trace_info: TraceInfo, public_inputs: PublicInputs, options: ProofOptions) -> Self {
        let usize_length: usize = public_inputs.expected_length.base_element(0).to_u256().as_u64() as usize;

        let constraint_vector: Vec<ConstraintSpecification<BaseElement>> = get_constraints(usize_length);
        let mut degrees = Vec::new();

        for constraint in &constraint_vector {
            for degree in &constraint.base_degrees {
                let (base_degree, periodic_columns) = (degree[0], &degree[1..]);
                degrees.push(TransitionConstraintDegree::new(base_degree));
            }
        }

        CRLUpdateAir {
            context: AirContext::new(trace_info, degrees, 1, options),
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

        let constraint_vector = get_constraints(self.trace_length());
        for constraint in &constraint_vector {
            (constraint.evaluator)(&mut index, result, current, next, periodic_values);
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        // let last_step = self.trace_length() - 1;
        vec![
            Assertion::single(get_register_column(constants::NUM_ROWS_OFFSET, 0), 0, BaseElement::ZERO),
        ]
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        vec![
            // Finally include the round constants as a periodic column
            // build_cycle(self.num_blocks, constants::ROUND_CONSTANTS_MASK, true),
        ]
    }
}
