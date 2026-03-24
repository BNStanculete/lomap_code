// Copyright 2026 Bogdan Stanculete. All Rights Reserved.

use crate::Testable;

use std::time::Instant;

pub fn test_basic_proof_verification(e: Box<dyn Testable>) {
    let mut start = Instant::now();
    let proof = e.prove();
    println!("Proof finalization took {:?}.", start.elapsed());

    start = Instant::now();
    assert!(e.verify(proof).is_ok());

    println!("Verification took {:?}", start.elapsed());
}
