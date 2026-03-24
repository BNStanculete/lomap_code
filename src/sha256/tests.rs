// Copyright Bogdan Stanculete 2026. All Rights Reserved

use winterfell::{BatchingMethod, FieldExtension, ProofOptions};
use winterfell::math::{fields::f252::BaseElement};

use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::env;

use super::TRACE_WIDTH;

#[test]
fn sha_test_basic_proof_verification() -> Result<(), Box<dyn std::error::Error>> {
    let expected_result: [BaseElement; 8] = [
        BaseElement::from(3128432319u32),
        BaseElement::from(2399260650u32),
        BaseElement::from(1094795486u32),
        BaseElement::from(1571693091u32),
        BaseElement::from(2953011619u32),
        BaseElement::from(2518121116u32),
        BaseElement::from(3021012833u32),
        BaseElement::from(4060091821u32),
    ];
    
    let path_str = env::current_dir()
        .unwrap()
        .to_string_lossy()
        .into_owned() + "/tests/sha256/sha256.trace.txt";

    let columns = load_columns(&path_str)?;
    let hash_eg = Box::new(super::Sha256::new(
        build_options(),
        columns,
        1,
        expected_result));
    crate::tests::test_basic_proof_verification(hash_eg);
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
            .map(|s| BaseElement::from(s.parse::<u32>().expect("Invalid u32")))
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