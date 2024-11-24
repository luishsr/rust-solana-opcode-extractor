use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use goblin::elf::Elf;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs::File;
use std::io::{Read, Write};
use memmap2::Mmap;
use thiserror::Error;
use std::{fs};
use std::collections::HashMap;
use solana_rbpf::ebpf;

const SOLANA_RPC_URL: &str = "https://api.mainnet-beta.solana.com";

#[derive(Error, Debug)]
pub enum CustomError {
    #[error("Request error: {0}")]
    ReqwestError(#[from] reqwest::Error),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerdeError(#[from] serde_json::Error),

    #[error("Base64 decoding error: {0}")]
    Base64Error(#[from] base64::DecodeError),

    #[error("Transaction not found")]
    NotFound,
}

#[derive(Debug, Serialize, Deserialize)]
struct AccountInfo {
    executable: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct SolanaTransaction {
    transaction: SolanaMessage,
}

#[derive(Debug, Serialize, Deserialize)]
struct SolanaMessage {
    message: SolanaInstructions,
}

#[derive(Debug, Serialize, Deserialize)]
struct SolanaInstructions {
    #[serde(rename = "accountKeys")]
    account_keys: Vec<String>,
    instructions: Vec<Instruction>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Instruction {
    #[serde(rename = "programIdIndex")]
    program_id_index: usize,
}

async fn get_transaction(
    signature: &str,
    log: &mut Vec<Value>,
) -> Result<SolanaTransaction, CustomError> {
    let client = Client::new();
    let response = client
        .post(SOLANA_RPC_URL)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTransaction",
            "params": [
                signature,
                {
                    "encoding": "json",
                    "maxSupportedTransactionVersion": 0
                }
            ]
        }))
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    log.push(json!({ "type": "RawResponse", "data": response }));

    if let Some(result) = response.get("result") {
        Ok(serde_json::from_value(result.clone())?)
    } else {
        Err(CustomError::NotFound)
    }
}

async fn fetch_account_info(
    account: &str,
    log: &mut Vec<serde_json::Value>,
) -> Result<AccountInfo, CustomError> {
    let client = Client::new();
    let response = client
        .post(SOLANA_RPC_URL)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getAccountInfo",
            "params": [account, {"encoding": "jsonParsed"}]
        }))
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    log.push(json!({
        "type": "AccountInfo",
        "account": account,
        "data": response,
    }));

    if let Some(account_info) = response.get("result").and_then(|result| result.get("value")) {
        Ok(serde_json::from_value(account_info.clone())?)
    } else {
        Err(CustomError::NotFound)
    }
}

fn is_elf_format(data: &[u8]) -> bool {
    data.len() >= 4 && &data[0..4] == b"\x7FELF"
}

fn parse_bpf_instructions(file_path: &str, log: &mut Vec<serde_json::Value>) {
    let file = match File::open(file_path) {
        Ok(file) => file,
        Err(err) => {
            log.push(json!({
                "type": "Error",
                "message": format!("Failed to open file {}: {}", file_path, err),
            }));
            return;
        }
    };

    let mmap = unsafe { Mmap::map(&file).expect("Failed to map the file") };

    if !is_elf_format(&mmap) {
        log.push(json!({
            "type": "Error",
            "message": format!("File {} is not a valid ELF format.", file_path),
        }));
        return;
    } else {
        log.push(json!({
            "type": "ValidELF",
            "file": file_path,
        }));
    }

    let elf = match Elf::parse(&mmap) {
        Ok(elf) => elf,
        Err(err) => {
            log.push(json!({
                "type": "Error",
                "message": format!("Failed to parse ELF file: {}", err),
            }));
            return;
        }
    };

    log.push(json!({
        "type": "ELFSections",
        "file": file_path,
        "sections": elf.section_headers.iter().filter_map(|section| {
            elf.shdr_strtab.get_at(section.sh_name).map(String::from)
        }).collect::<Vec<_>>(),
    }));

    if let Some(text_section) = elf.section_headers.iter().find(|section| {
        if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
            name == ".text"
        } else {
            false
        }
    }) {
        log.push(json!({
            "type": "TextSectionFound",
            "file": file_path,
            "offset": text_section.sh_offset,
            "size": text_section.sh_size,
        }));

        let text_data = &mmap[text_section.sh_offset as usize
            ..(text_section.sh_offset + text_section.sh_size) as usize];

        if text_data.is_empty() {
            log.push(json!({
                "type": "Error",
                "message": format!(".text section is empty for file: {}", file_path),
            }));
            return;
        }

        let instructions: Vec<String> = text_data
            .chunks(8)
            .map(|chunk| format!("{:02x?}", chunk))
            .collect();

        log.push(json!({
            "type": "BPFInstructions",
            "file": file_path,
            "instructions": instructions,
        }));
    } else {
        log.push(json!({
            "type": "Error",
            "message": format!("No .text section found in ELF file: {}", file_path),
        }));
    }
}

async fn download_program(program_id: &str, log: &mut Vec<serde_json::Value>) -> Result<String, CustomError> {
    let client = Client::new();
    let response = client
        .post(SOLANA_RPC_URL)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getAccountInfo",
            "params": [program_id, {"encoding": "base64"}]
        }))
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    if let Some(data) = response
        .get("result")
        .and_then(|result| result.get("value"))
        .and_then(|value| value.get("data"))
        .and_then(|data| data[0].as_str())
    {
        log.push(json!({ "type": "RawData", "program_id": program_id, "data": data }));
        let binary_data = STANDARD.decode(data)?;
        let file_path = format!("{}.so", program_id);
        let mut file = File::create(&file_path)?;
        file.write_all(&binary_data)?;
        Ok(file_path)
    } else {
        Err(CustomError::NotFound)
    }
}

#[tokio::main]
async fn main() {
    let mut log: Vec<serde_json::Value> = Vec::new();

    // Get the transaction signature from command-line arguments
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <transaction_signature>", args[0]);
        std::process::exit(1);
    }
    let transaction_signature = &args[1];

    let known_non_elf_programs = vec![
        "ComputeBudget111111111111111111111111111111",
        "11111111111111111111111111111111", // System program
    ];

    let mut generated_files = Vec::new(); // To keep track of generated `.so` files

    match get_transaction(transaction_signature, &mut log).await {
        Ok(transaction) => {
            log.push(json!({ "type": "TransactionDetails", "data": transaction }));

            let account_keys = transaction.transaction.message.account_keys;
            for program_id in account_keys {
                if known_non_elf_programs.contains(&program_id.as_str()) {
                    log.push(json!({
                        "type": "SkippingProgram",
                        "program_id": program_id,
                        "reason": "Known non-ELF program"
                    }));
                    continue;
                }

                match fetch_account_info(&program_id, &mut log).await {
                    Ok(account_info) if account_info.executable => {
                        log.push(json!({ "type": "ExecutableProgram", "program_id": program_id }));

                        match download_program(&program_id, &mut log).await {
                            Ok(file_path) => {
                                log.push(json!({ "type": "ProgramDownloaded", "file": file_path }));
                                generated_files.push(file_path.clone()); // Track generated file
                                parse_bpf_instructions(&file_path, &mut log);
                            }
                            Err(e) => {
                                log.push(json!({
                                    "type": "Error",
                                    "program_id": program_id,
                                    "message": format!("Failed to download program: {}", e),
                                }));
                            }
                        }
                    }
                    Ok(_) => {
                        log.push(json!({
                            "type": "NonExecutableAccount",
                            "program_id": program_id,
                        }));
                    }
                    Err(e) => {
                        log.push(json!({
                            "type": "Error",
                            "program_id": program_id,
                            "message": e.to_string(),
                        }));
                    }
                }
            }
        }
        Err(e) => {
            log.push(json!({ "type": "Error", "message": e.to_string() }));
        }
    }

    let mut file = File::create("output.json").expect("Unable to create log file");
    file.write_all(serde_json::to_string_pretty(&log).unwrap().as_bytes())
        .expect("Unable to write log to file");

    // Cleanup: Delete all `.so` files generated during execution
    for file_path in generated_files {
        if let Err(e) = fs::remove_file(&file_path) {
            eprintln!("Failed to delete file {}: {}", file_path, e);
        }
    }

    // Translates BPFInstruction into opcodes
    let _ = parse_opcodes();
}

fn parse_opcodes() -> std::io::Result<()>{
    // Read the input JSON file
    let input_path = "output.json";
    let mut file = File::open(input_path)?;
    let mut data = String::new();
    file.read_to_string(&mut data)?;

    // Parse JSON
    let parsed: Value = serde_json::from_str(&data)?;
    let mut bytecode_output = Vec::new();

    // Mapping BPF opcodes using solana_rbpf::ebpf
    let opcode_map: HashMap<u8, &str> = [
        // BPF_LD (Load)
        (ebpf::BPF_LD | ebpf::LD_ABS_B, "LD_ABS_B"),
        (ebpf::LD_ABS_H, "LD_ABS_H"),
        (ebpf::LD_ABS_W, "LD_ABS_W"),
        (ebpf::LD_ABS_DW, "LD_ABS_DW"),
        (ebpf::LD_IND_B, "LD_IND_B"),
        (ebpf::LD_IND_H, "LD_IND_H"),
        (ebpf::LD_IND_W, "LD_IND_W"),
        (ebpf::LD_IND_DW, "LD_IND_DW"),
        (ebpf::LD_DW_IMM, "LD_DW_IMM"),

        // BPF_LDX (Load Indexed)
        (ebpf::LD_B_REG, "LD_B_REG"),
        (ebpf::LD_H_REG, "LD_H_REG"),
        (ebpf::LD_W_REG, "LD_W_REG"),
        (ebpf::LD_DW_REG, "LD_DW_REG"),

        // BPF_ST (Store)
        (ebpf::ST_B_IMM, "ST_B_IMM"),
        (ebpf::ST_H_IMM, "ST_H_IMM"),
        (ebpf::ST_W_IMM, "ST_W_IMM"),
        (ebpf::ST_DW_IMM, "ST_DW_IMM"),

        // BPF_STX (Store Indexed)
        (ebpf::ST_B_REG, "ST_B_REG"),
        (ebpf::ST_H_REG, "ST_H_REG"),
        (ebpf::ST_W_REG, "ST_W_REG"),
        (ebpf::ST_DW_REG, "ST_DW_REG"),
        (ebpf::ST_W_XADD, "ST_W_XADD"),
        (ebpf::ST_DW_XADD, "ST_DW_XADD"),

        // BPF_ALU32 (32-bit ALU operations)
        (ebpf::ADD32_IMM, "ADD32_IMM"),
        (ebpf::ADD32_REG, "ADD32_REG"),
        (ebpf::SUB32_IMM, "SUB32_IMM"),
        (ebpf::SUB32_REG, "SUB32_REG"),
        (ebpf::MUL32_IMM, "MUL32_IMM"),
        (ebpf::MUL32_REG, "MUL32_REG"),
        (ebpf::DIV32_IMM, "DIV32_IMM"),
        (ebpf::DIV32_REG, "DIV32_REG"),
        (ebpf::OR32_IMM, "OR32_IMM"),
        (ebpf::OR32_REG, "OR32_REG"),
        (ebpf::AND32_IMM, "AND32_IMM"),
        (ebpf::AND32_REG, "AND32_REG"),
        (ebpf::LSH32_IMM, "LSH32_IMM"),
        (ebpf::LSH32_REG, "LSH32_REG"),
        (ebpf::RSH32_IMM, "RSH32_IMM"),
        (ebpf::RSH32_REG, "RSH32_REG"),
        (ebpf::NEG32, "NEG32"),
        (ebpf::MOD32_IMM, "MOD32_IMM"),
        (ebpf::MOD32_REG, "MOD32_REG"),
        (ebpf::XOR32_IMM, "XOR32_IMM"),
        (ebpf::XOR32_REG, "XOR32_REG"),
        (ebpf::MOV32_IMM, "MOV32_IMM"),
        (ebpf::MOV32_REG, "MOV32_REG"),
        (ebpf::ARSH32_IMM, "ARSH32_IMM"),
        (ebpf::ARSH32_REG, "ARSH32_REG"),
        (ebpf::SDIV32_IMM, "SDIV32_IMM"),
        (ebpf::SDIV32_REG, "SDIV32_REG"),

        // BPF_ALU64 (64-bit ALU operations)
        (ebpf::ADD64_IMM, "ADD64_IMM"),
        (ebpf::ADD64_REG, "ADD64_REG"),
        (ebpf::SUB64_IMM, "SUB64_IMM"),
        (ebpf::SUB64_REG, "SUB64_REG"),
        (ebpf::MUL64_IMM, "MUL64_IMM"),
        (ebpf::MUL64_REG, "MUL64_REG"),
        (ebpf::DIV64_IMM, "DIV64_IMM"),
        (ebpf::DIV64_REG, "DIV64_REG"),
        (ebpf::OR64_IMM, "OR64_IMM"),
        (ebpf::OR64_REG, "OR64_REG"),
        (ebpf::AND64_IMM, "AND64_IMM"),
        (ebpf::AND64_REG, "AND64_REG"),
        (ebpf::LSH64_IMM, "LSH64_IMM"),
        (ebpf::LSH64_REG, "LSH64_REG"),
        (ebpf::RSH64_IMM, "RSH64_IMM"),
        (ebpf::RSH64_REG, "RSH64_REG"),
        (ebpf::NEG64, "NEG64"),
        (ebpf::MOD64_IMM, "MOD64_IMM"),
        (ebpf::MOD64_REG, "MOD64_REG"),
        (ebpf::XOR64_IMM, "XOR64_IMM"),
        (ebpf::XOR64_REG, "XOR64_REG"),
        (ebpf::MOV64_IMM, "MOV64_IMM"),
        (ebpf::MOV64_REG, "MOV64_REG"),
        (ebpf::ARSH64_IMM, "ARSH64_IMM"),
        (ebpf::ARSH64_REG, "ARSH64_REG"),
        (ebpf::SDIV64_IMM, "SDIV64_IMM"),
        (ebpf::SDIV64_REG, "SDIV64_REG"),

        // BPF_JMP (Jump)
        (ebpf::JA, "JA"),
        (ebpf::JEQ_IMM, "JEQ_IMM"),
        (ebpf::JEQ_REG, "JEQ_REG"),
        (ebpf::JGT_IMM, "JGT_IMM"),
        (ebpf::JGT_REG, "JGT_REG"),
        (ebpf::JGE_IMM, "JGE_IMM"),
        (ebpf::JGE_REG, "JGE_REG"),
        (ebpf::JLT_IMM, "JLT_IMM"),
        (ebpf::JLT_REG, "JLT_REG"),
        (ebpf::JLE_IMM, "JLE_IMM"),
        (ebpf::JLE_REG, "JLE_REG"),
        (ebpf::JSET_IMM, "JSET_IMM"),
        (ebpf::JSET_REG, "JSET_REG"),
        (ebpf::JNE_IMM, "JNE_IMM"),
        (ebpf::JNE_REG, "JNE_REG"),
        (ebpf::JSGT_IMM, "JSGT_IMM"),
        (ebpf::JSGT_REG, "JSGT_REG"),
        (ebpf::JSGE_IMM, "JSGE_IMM"),
        (ebpf::JSGE_REG, "JSGE_REG"),
        (ebpf::JSLT_IMM, "JSLT_IMM"),
        (ebpf::JSLT_REG, "JSLT_REG"),
        (ebpf::JSLE_IMM, "JSLE_IMM"),
        (ebpf::JSLE_REG, "JSLE_REG"),
        (ebpf::CALL_IMM, "CALL_IMM"),
        (ebpf::CALL_REG, "CALL_REG"),
        (ebpf::EXIT, "EXIT"),

        // Endianness conversion
        (ebpf::LE, "LE"),
        (ebpf::BE, "BE"),

        // Unknown opcode
        (0xff, "UNKNOWN_OPCODE"),
    ]
        .iter()
        .cloned()
        .collect();

    if let Some(instruction_sets) = parsed.as_array() {
        for entry in instruction_sets {
            if let Some(instructions) = entry.get("instructions") {
                if let Some(instr_array) = instructions.as_array() {
                    for instr in instr_array {
                        if let Some(opcode_string) = instr.as_str() {
                            // Parse the instruction bytes (removing brackets and splitting)
                            let opcode_bytes: Vec<u8> = opcode_string
                                .trim_matches(&['[', ']'] as &[_])
                                .split(", ")
                                .filter_map(|byte_str| u8::from_str_radix(byte_str, 16).ok())
                                .collect();

                            if let Some(&opcode) = opcode_bytes.get(0) {
                                let operation = opcode_map.get(&opcode).unwrap_or(&"UNKNOWN");
                                bytecode_output.push(json!({
                                    "opcode": format!("{:#x}", opcode),
                                    "operation": operation,
                                    "raw": opcode_bytes
                                }));
                            }
                        }
                    }
                }
            }
        }
    }

    // Write to bytecode.json
    let output_path = "bytecode.json";
    let mut output_file = File::create(output_path)?;
    let formatted_output = serde_json::to_string_pretty(&bytecode_output)?;
    output_file.write_all(formatted_output.as_bytes())?;

    println!("Bytecode parsing complete. Output written to {}", output_path);
    Ok(())
}

