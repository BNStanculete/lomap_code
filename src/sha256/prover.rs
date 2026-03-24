// Copyright Bogdan Stanculete 2026. All Rights Reserved.

use winterfell::{
    crypto::MerkleTree, matrix::ColMatrix, AuxRandElements, CompositionPoly, CompositionPolyTrace,
    ConstraintCompositionCoefficients, DefaultConstraintCommitment, DefaultConstraintEvaluator,
    DefaultTraceLde, PartitionOptions, StarkDomain, Trace, TraceInfo, TracePolyTable, TraceTable,
};

use super::{
    BaseElement, DefaultRandomCoin, ElementHasher, FieldElement, PhantomData, ProofOptions,
    Prover, PublicInputs, Sha256Air, constants, constraints::get_register_column
};

// SHA-256 PROVER
// ================================================================================================

pub struct Sha256Prover<H: ElementHasher> {
    options: ProofOptions,
    _hasher: PhantomData<H>
}

impl <H: ElementHasher> Sha256Prover<H> {
    pub fn new(options: ProofOptions) -> Self {
        Self { options, _hasher: PhantomData }
    }

    pub fn build_trace(
        &self,
        columns: Vec<Vec<BaseElement>>,
    ) -> TraceTable<BaseElement> {
        TraceTable::init(columns)
    }
}

impl <H: ElementHasher> Prover for Sha256Prover<H>
where H: ElementHasher<BaseField = BaseElement> + Sync {
 type BaseField = BaseElement;
    type Air = Sha256Air;
    type Trace = TraceTable<BaseElement>;
    type HashFn = H;
    type VC = MerkleTree<H>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, H, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> PublicInputs {
        let last_step = trace.length() - 1;

        // An expected length of 2^{64} is more than enough for most digital certificates and CRLs.
        PublicInputs {
            expected_length: trace.get(get_register_column(constants::NUM_ROWS_OFFSET, 0), last_step),
            result: [
                trace.get(get_register_column(constants::HASH_OFFSET, 0), last_step),
                trace.get(get_register_column(constants::HASH_OFFSET, 1), last_step),
                trace.get(get_register_column(constants::HASH_OFFSET, 2), last_step),
                trace.get(get_register_column(constants::HASH_OFFSET, 3), last_step),
                trace.get(get_register_column(constants::HASH_OFFSET, 4), last_step),
                trace.get(get_register_column(constants::HASH_OFFSET, 5), last_step),
                trace.get(get_register_column(constants::HASH_OFFSET, 6), last_step),
                trace.get(get_register_column(constants::HASH_OFFSET, 7), last_step),
            ]
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }
}