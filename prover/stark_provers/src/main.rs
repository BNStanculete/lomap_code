use winterfell::{BatchingMethod, FieldExtension, ProofOptions};
use winterfell::math::{fields::f252::BaseElement};

use std::fs;
use std::io::{self, BufRead, BufReader};
use std::env;

use loap_stark::crl_update::{CRLUpdateData, CRLData, CRLUpdateProvable, CRLUpdateVerifiable, TRACE_WIDTH};
use loap_stark::message_auth::{MessageAuthenticationProvable, MessageAuthenticationVerifiable, MessageAuthenticationData};
use loap_stark::{Provable, Verifiable};

use jemallocator::Jemalloc;
use jemalloc_ctl::stats;
use jemalloc_ctl::epoch;

#[global_allocator]
static ALLOC: Jemalloc = Jemalloc;

// #[derive(Debug)]
// struct CertificateData {
//     subject_cn: String,
//     issuer_cn: String,
//     serial: String,
//     pub_key_hash: String,
//     not_before: String,
//     not_after: String,
//     hash: String,
// }

// #[derive(Debug)]
// struct AuthenticationData {
//     cert: CertificateData,
//     authorities: Vec<(CertificateData, CRLData)>,
//     hash: String
// }

enum Message {
    // Authentication(AuthenticationData),
    CRLUpdate(CRLUpdateData),
    MessageAuthentication(MessageAuthenticationData)
}

// ---- Reading Prover Messages from file ----
fn next_line<'a>(lines: &mut impl Iterator<Item = &'a str>) -> Result<String, &'static str> {
    lines.next()
         .map(str::to_owned)
         .ok_or("Unexpected EOF")
}

// fn read_certificate<'a>(lines: &mut impl Iterator<Item = &'a str>) -> Result<CertificateData, &'static str> {
//     Ok(CertificateData {
//         subject_cn: next_line(lines)?,
//         issuer_cn: next_line(lines)?,
//         serial: next_line(lines)?,
//         pub_key_hash: next_line(lines)?,
//         not_before: next_line(lines)?,
//         not_after: next_line(lines)?,
//         hash: next_line(lines)?
//     })
// }

fn read_crl<'a>(lines: &mut impl Iterator<Item = &'a str>) -> Result<CRLData, &'static str> {
    Ok(CRLData {
        cn: next_line(lines)?,
        this_update: next_line(lines)?,
        next_update: next_line(lines)?,
        hash: next_line(lines)?,
    })
}

fn read_message<'a>(lines: &mut impl Iterator<Item = &'a str>) -> Result<MessageAuthenticationData, &'static str> {
    Ok(MessageAuthenticationData {
        pub_key_hash: next_line(lines)?,
        signature: next_line(lines)?,
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>>{
    println!("[+] Running STARK prover & verifier");
    println!("[+] ===============================");

    let proof_options = ProofOptions::new(101, 8, 0, FieldExtension::None, 4, 31, BatchingMethod::Linear, BatchingMethod::Linear);
    let mut runtime_path: String = "".to_string();

    // Extract Paths
    println!("[+] Extracting LOAP paths...");
    match env::var("LOAP_RUNTIME_PATH") {
        Ok(value) => runtime_path = value,
        Err(_) => std::process::exit(1),
    }

    let args: Vec<_> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <auth|crlupdate|message>", args[0]);
        std::process::exit(1);
    }

    let trace_path = runtime_path.to_owned() + "/proofs/trace.txt";
    let message_path = runtime_path.to_owned() + "/message.txt";

    println!("[+] Loading raw trace columns...");
    let columns = load_columns(&trace_path)?;

    println!("[+] Loading prover message...");
    let content = fs::read_to_string(message_path)?;
    let mut lines = content.lines();
    let mut message: Option<Message> = None;

    // if args[1] == "auth" {
    //     let prover_cert = read_certificate(&mut lines)?;
    //     let mut authorities_vec = Vec::new();
    //     println!("[+] Prover Certificate loaded.");

    //     while lines.clone().count() > 1 {
    //         let authority_cert = read_certificate(&mut lines)?;
    //         println!("[+] CA Cert loaded.");
    //         let authority_crl = read_crl(&mut lines)?;
    //         println!("[+] CRL Cert loaded");

    //         authorities_vec.push((authority_cert, authority_crl));
    //     }

    //     let hash_data = next_line(&mut lines)?;
    //     message = Some(Message::Authentication(AuthenticationData {
    //         cert: prover_cert,
    //         authorities: authorities_vec,
    //         hash: hash_data
    //     }));
    // } else 
    if args[1] == "crlupdate" {
        let crl_data = read_crl(&mut lines)?;
        message = Some(Message::CRLUpdate(CRLUpdateData {
            crl: crl_data
        }));
    } else if args[1] == "message" {
        let signature_data = read_message(&mut lines)?;
        message = Some(Message::MessageAuthentication(signature_data));
    } else {
        eprintln!("Invalid argument {}", args[1]);
        std::process::exit(1);
    }

    match message {
        // Some(Message::Authentication(auth_data)) => {
        //     println!("[+] Received Authentication Message");
        //     println!("[+] Prover subject: {}", auth_data.cert.subject_cn);
            
        //     // TODO: Replace classes with authentication specific
        //     epoch::advance().unwrap();
        //     let _ = stats::allocated::read().unwrap();

        //     let hash_eg = Box::new(CRLUpdateProvable::new(proof_options.clone(), columns));

        //     epoch::advance().unwrap();
        //     println!("[+] Starting proof...");
        //     let before_prove = stats::allocated::read().unwrap();
        //     let start = std::time::Instant::now();
        //     let proof = hash_eg.prove();
        //     println!("[+] Proof finalization took {:?}", start.elapsed());
        //     epoch::advance().unwrap();
        //     let after_prove = stats::allocated::read().unwrap();
        //     println!("[+] Heap used during proof: {}", after_prove - before_prove);
        //     println!("[+] Proof size: {}", proof.to_bytes().len());

        //     let verifier = Box::new(CRLUpdateVerifiable::new(
        //         proof_options,
        //         proof.context.trace_info().length() as u64
        //     ));

        //     epoch::advance().unwrap();
        //     let start = std::time::Instant::now();
        //     assert!(verifier.verify(proof).is_ok());
        //     println!("[+] Verification took {:?}", start.elapsed());
        //     epoch::advance().unwrap();
        //     let after_verify = stats::allocated::read().unwrap();
        //     println!("[+] Heap used during verification: {}", after_verify - before_prove);

        // }
        Some(Message::CRLUpdate(update_data)) => {
            println!("[+] Received CRLUpdate Message");
            println!("[+] CRL Issuer: {}", update_data.crl.cn);

            epoch::advance().unwrap();
            let _ = stats::allocated::read().unwrap();

            let hash_eg = Box::new(CRLUpdateProvable::new(proof_options, columns, update_data.clone()));

            epoch::advance().unwrap();
            println!("[+] Starting proof...");
            let before_prove = stats::allocated::read().unwrap();
            let start = std::time::Instant::now();
            let proof = hash_eg.prove();
            println!("[+] Proof finalization took {:?}", start.elapsed());
            epoch::advance().unwrap();
            let after_prove = stats::allocated::read().unwrap();
            println!("[+] Heap used during proof: {}", after_prove - before_prove);
            println!("[+] Proof size: {}", proof.to_bytes().len());

            let verifier = Box::new(CRLUpdateVerifiable::new(
                update_data,
                proof.context.trace_info().length() as u64
            ));

            epoch::advance().unwrap();
            let start = std::time::Instant::now();
            assert!(verifier.verify(proof).is_ok());
            println!("[+] Verification took {:?}", start.elapsed());
            epoch::advance().unwrap();
            let after_verify = stats::allocated::read().unwrap();
            println!("[+] Heap used during verification: {}", after_verify - before_prove);
        }
        Some(Message::MessageAuthentication(signature_data)) => {
            println!("[+] Received MessageAuthentication Message");
            epoch::advance().unwrap();
            let _ = stats::allocated::read().unwrap();

            let hash_eg = Box::new(MessageAuthenticationProvable::new(proof_options, columns, signature_data.clone()));

            epoch::advance().unwrap();
            println!("[+] Starting proof...");
            let before_prove = stats::allocated::read().unwrap();
            let start = std::time::Instant::now();
            let proof = hash_eg.prove();

            println!("[+] Proof finalization took {:?}", start.elapsed());            
            epoch::advance().unwrap();
            let after_prove = stats::allocated::read().unwrap();
            println!("[+] Heap used during proof: {}", after_prove - before_prove);
            println!("[+] Proof size: {}", proof.to_bytes().len());

            let verifier = Box::new(MessageAuthenticationVerifiable::new(
                signature_data,
                proof.context.trace_info().length() as u64,
            ));

            epoch::advance().unwrap();
            let start = std::time::Instant::now();
            assert!(verifier.verify(proof).is_ok());
            
            println!("[+] Verification took {:?}", start.elapsed());
            epoch::advance().unwrap();
            let after_verify = stats::allocated::read().unwrap();
            println!("[+] Heap used during verification: {}", after_verify - before_prove);
        }
        None => {
            eprintln!("[-] No message received.");
            std::process::exit(1);
        }
    }

    Ok(())
}

// HELPER FUNCTION
// ================================================================================================

fn load_columns(path: &str) -> io::Result<Vec<Vec<BaseElement>>> {
    let file = std::fs::File::open(path)?;
    let reader = BufReader::new(file);

    let mut columns: Vec<Vec<BaseElement>> = Vec::new();

    for (row_idx, line) in reader.lines().enumerate() {
        let read_line: String = line?;
        let values: Vec<BaseElement> = read_line
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
