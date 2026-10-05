use winterfell::{
    math::ToElements,
    Air, AirContext, Assertion, EvaluationFrame, TraceInfo, TransitionConstraintDegree,
};

use super::{BaseElement, FieldElement, ProofOptions};
use super::constraints::{
    get_register_column,
    sha256::get_constraints as get_sha256_constraints
};

use crate::utils::constraints::ConstraintSpecification;

pub mod message_authentication;
pub mod initial_authentication;
pub mod crl_update;
