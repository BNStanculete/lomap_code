use winterfell::{BatchingMethod, FieldExtension, ProofOptions};
use winterfell::math::{fields::f252::BaseElement};

use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::env;

use std::time::Instant;

use lomap::crlupdate::{CRLUpdateProvable, CRLUpdateVerifiable};
use lomap::crlupdate::TRACE_WIDTH;
use lomap::{Provable, Verifiable};

use jemallocator::Jemalloc;
use jemalloc_ctl::stats;
use jemalloc_ctl::epoch;

#[global_allocator]
static ALLOC: Jemalloc = Jemalloc;

fn main() -> Result<(), Box<dyn std::error::Error>>{
    let proof_options = ProofOptions::new(100, 8, 0, FieldExtension::None, 4, 31, BatchingMethod::Linear, BatchingMethod::Linear);

    let path_str = env::current_dir()
        .unwrap()
        .to_string_lossy()
        .into_owned() + "/trace.txt";
    println!("{}", path_str);

    let columns = load_columns(&path_str)?;

    epoch::advance().unwrap();
    let _ = stats::allocated::read().unwrap();

    let hash_eg = Box::new(CRLUpdateProvable::new(proof_options.clone(), columns));

    epoch::advance().unwrap();
    println!("Starting proof...");
    let before_prove = stats::allocated::read().unwrap();
    let start = std::time::Instant::now();
    let proof = hash_eg.prove();
    println!("Proof finalization took {:?}", start.elapsed());
    epoch::advance().unwrap();
    let after_prove = stats::allocated::read().unwrap();
    println!("Heap used during proof: {} bytes", after_prove - before_prove);
    println!("Proof size: {}", proof.to_bytes().len());

    let verifier = Box::new(CRLUpdateVerifiable::new(
        proof_options,
        proof.context.trace_info().length() as u64
    ));

    epoch::advance().unwrap();
    let start = std::time::Instant::now();
    assert!(verifier.verify(proof).is_ok());
    println!("Verification took {:?}", start.elapsed());
    epoch::advance().unwrap();
    let after_verify = stats::allocated::read().unwrap();
    println!("Heap used during verification: {} bytes", after_verify - before_prove);
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
            .map(|s| BaseElement::from(s.parse::<u128>().expect("Invalid u128")))
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
