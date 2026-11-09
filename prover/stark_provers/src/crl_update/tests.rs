// Copyright Bogdan Stanculete 2026. All Rights Reserved

use winterfell::{BatchingMethod, FieldExtension, ProofOptions};
use winterfell::math::{fields::f252::BaseElement};

use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::env;
use std::time::Instant;

use super::TRACE_WIDTH;
use crate::{Provable, Verifiable};

#[test]
fn crl_update_basic_proof_verification() -> Result<(), Box<dyn std::error::Error>> {
    let path_str = env::current_dir()
        .unwrap()
        .to_string_lossy()
        .into_owned() + "/trace.txt";

    println!("{}", path_str);

    let columns = load_columns(&path_str)?;
    let prover = Box::new(super::MessageAuthenticationProvable::new(
        build_options(),
        columns));

    let mut start = Instant::now();
    let proof = prover.prove();
    println!("Proof finalization took {:?}.", start.elapsed());

    let verifier = Box::new(super::MessageAuthenticationVerifiable::new(
        build_options(),
        proof.context.trace_info().length() as u64
    ));

    start = Instant::now();
    assert!(verifier.verify(proof).is_ok());
    println!("Verification took {:?}", start.elapsed());

    Ok(())
}

// HELPER FUNCTION
// ================================================================================================

fn load_columns(path: &str) -> io::Result<Vec<Vec<BaseElement>>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let mut columns: Vec<Vec<BaseElement>> = Vec::new();

    for (row_idx, line) in reader.lines().enumerate() {
        let line = line?;
        let values: Vec<BaseElement> = line
            .split_whitespace()
            .map(|s| {
                let n = s.parse::<u128>()
                    .unwrap_or_else(|e| panic!("Failed to parse '{}': {:?}", s, e));
                BaseElement::from(n)
            })
            .collect();

        if row_idx == 0 {
            // Initialize columns based on first row
            columns = vec![Vec::with_capacity(TRACE_WIDTH); values.len()];
        }

        if values.len() != columns.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Row {} has {} columns, expected {}",
                    row_idx,
                    values.len(),
                    columns.len()
                ),
            ));
        }

        for (col_idx, value) in values.into_iter().enumerate() {
            columns[col_idx].push(value);
        }
    }

    Ok(columns)
}

fn build_options() -> ProofOptions {
    ProofOptions::new(72, 16, 0, FieldExtension::None, 4, 31, BatchingMethod::Linear, BatchingMethod::Linear)
}