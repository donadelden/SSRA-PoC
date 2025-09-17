use std::time::Instant;
use rabe::schemes::bsw::*;
use rabe::utils::policy::pest::PolicyLanguage;
use std::fs::File;
use std::io::{Read, Write};
use std::env;
use std::time::Duration;
use rand::distributions::Alphanumeric;
use rand::Rng;


fn encrypt_cpabe(policy: &str, plaintext: &str) {
    let mut file = File::open("./shared/pk.bin").expect("Unable to open file");
    let mut pk_bytes = Vec::new();
    file.read_to_end(&mut pk_bytes).expect("Unable to read data");
    let pk: CpAbePublicKey = bincode::deserialize(&pk_bytes).expect("Unable to deserialize public key");
    println!("Public key loaded successfully");

    let plaintext_bytes = plaintext.as_bytes();
    let mut times = Vec::with_capacity(100);
    let mut ct_cp = None;

    for _ in 0..100 {
        let start = Instant::now();
        let ct = encrypt(&pk, &policy, PolicyLanguage::HumanPolicy, &plaintext_bytes).unwrap();
        let end = Instant::now();
        times.push(end.duration_since(start));
        ct_cp = Some(ct);
    }

    // Calculate mean and std deviation in milliseconds
    let total: Duration = times.iter().sum();
    let mean = total / times.len() as u32;

    let mean_ms = mean.as_secs_f64() * 1000.0;
    let std = (times.iter()
        .map(|t| {
            let diff = t.as_secs_f64() * 1000.0 - mean_ms;
            diff * diff
        })
        .sum::<f64>() / times.len() as f64)
        .sqrt();

    println!("Encryption Mean Time: {:.3} ms", mean_ms);
    println!("Encryption Std Dev: {:.3} ms", std);

    let mut enc_file = File::create("./shared/enc.bin").expect("Unable to create file");
    let enc_bytes = bincode::serialize(&ct_cp).expect("Serialization failed");
    enc_file.write_all(&enc_bytes).expect("Unable to write data");

    println!("Encrypted data dumped to ./shared/enc.bin");
}

fn generate_master_keys() {
    let mut times = Vec::with_capacity(100);
    let mut pk = None;
    let mut msk = None;

    for _ in 0..100 {
        let start = Instant::now();
        let (cur_pk, cur_msk) = setup();
        let end = Instant::now();
        times.push(end.duration_since(start));
        pk = Some(cur_pk);
        msk = Some(cur_msk);
    }

    // Calculate mean and std deviation in milliseconds
    let total: Duration = times.iter().sum();
    let mean = total / times.len() as u32;
    let mean_ms = mean.as_secs_f64() * 1000.0;
    let std = (times.iter()
        .map(|t| {
            let diff = t.as_secs_f64() * 1000.0 - mean_ms;
            diff * diff
        })
        .sum::<f64>() / times.len() as f64)
        .sqrt();

    println!("Key Generation Mean Time: {:.3} ms", mean_ms);
    println!("Key Generation Std Dev: {:.3} ms", std);

    let pk = pk.unwrap();
    let msk = msk.unwrap();

    let mut pk_file = File::create("./shared/pk.bin").unwrap();
    pk_file.write_all(&bincode::serialize(&pk).unwrap()).unwrap();

    let mut msk_file = File::create("./shared/msk.bin").unwrap();
    msk_file.write_all(&bincode::serialize(&msk).unwrap()).unwrap();
}


fn generate_user_keys(attributes: Vec<&str>) {
    let mut pk_file = File::open("./shared/pk.bin").expect("Unable to open public key file");
    let mut pk_bytes = Vec::new();
    pk_file.read_to_end(&mut pk_bytes).expect("Unable to read public key data");
    let pk: CpAbePublicKey = bincode::deserialize(&pk_bytes).expect("Unable to deserialize public key");

    let mut msk_file = File::open("./shared/msk.bin").expect("Unable to open master secret key file");
    let mut msk_bytes = Vec::new();
    msk_file.read_to_end(&mut msk_bytes).expect("Unable to read master secret key data");
    let msk: CpAbeMasterKey = bincode::deserialize(&msk_bytes).expect("Unable to deserialize master secret key");

    let mut times = Vec::with_capacity(100);
    let mut sk = None;

    for _ in 0..100 {
        let start = Instant::now();
        let cur_sk: CpAbeSecretKey = keygen(&pk, &msk, &attributes).unwrap();
        let end = Instant::now();
        times.push(end.duration_since(start));
        sk = Some(cur_sk);
    }

    // Calculate mean and std deviation in milliseconds
    let total: Duration = times.iter().sum();
    let mean = total / times.len() as u32;
    let mean_ms = mean.as_secs_f64() * 1000.0;
    let std = (times.iter()
        .map(|t| {
            let diff = t.as_secs_f64() * 1000.0 - mean_ms;
            diff * diff
        })
        .sum::<f64>() / times.len() as f64)
        .sqrt();

    println!("User Key Generation Mean Time: {:.3} ms", mean_ms);
    println!("User Key Generation Std Dev: {:.3} ms", std);

    let sk = sk.unwrap();

    let mut sk_file = File::create("./shared/sk.bin").expect("Unable to create secret key file");
    sk_file.write_all(&bincode::serialize(&sk).expect("Serialization failed")).expect("Unable to write secret key data");
} 


fn decrypt_cpabe() {

    let mut sk_file = File::open("./shared/sk.bin").expect("Unable to open secret key file");
    let mut sk_bytes = Vec::new();
    sk_file.read_to_end(&mut sk_bytes).expect("Unable to read secret key data");
    let sk: CpAbeSecretKey = bincode::deserialize(&sk_bytes).expect("Unable to deserialize secret key");

    let mut enc_file = File::open("./shared/enc.bin").expect("Unable to open encrypted data file");
    let mut enc_bytes = Vec::new();
    enc_file.read_to_end(&mut enc_bytes).expect("Unable to read encrypted data");
    let ct_cp: Option<CpAbeCiphertext> = bincode::deserialize(&enc_bytes).expect("Unable to deserialize encrypted data");
    let ct_cp = ct_cp.expect("Encrypted data is None");

    let mut times = Vec::with_capacity(100);

    for _ in 0..100 {
        let start = Instant::now();
        let pt = decrypt(&sk, &ct_cp).unwrap();
        let end = Instant::now();
        times.push(end.duration_since(start));
    }

    // Calculate mean and std deviation in milliseconds
    let total: Duration = times.iter().sum();
    let mean = total / times.len() as u32;
    let mean_ms = mean.as_secs_f64() * 1000.0;
    let std = (times.iter()
        .map(|t| {
            let diff = t.as_secs_f64() * 1000.0 - mean_ms;
            diff * diff
        })
        .sum::<f64>() / times.len() as f64)
        .sqrt();

    println!("Decryption Mean Time: {:.3} ms", mean_ms);
    println!("Decryption Std Dev: {:.3} ms", std);
}

fn generate_message(length: usize) -> String {
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (&mut rng)
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(|c| c as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}


fn main() {

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <robot|tutor|user|all> [<message_len>]", args[0]);
        std::process::exit(1);
    }
    let role = &args[1];
    let message_len = if args.len() >= 3 {
        args[2].parse::<usize>().unwrap_or(1000)
    } else {
        1000
    };

    let message = generate_message(message_len);
    println!("Message length: {}", message.len());

    match role.as_str() {
        "robot" => {
            encrypt_cpabe(r#""A" and "B""#,  &message);
        },
        "tutor" => {
            generate_master_keys();
            generate_user_keys(vec!["A", "B"]); 
        },
        "user" => {
            decrypt_cpabe();
        },
        "all" => {
            generate_master_keys();
            generate_user_keys(vec!["A", "B"]); 
            encrypt_cpabe(r#""A" and "B""#,  &message);
            decrypt_cpabe();
        },
        _ => {
            eprintln!("Invalid role: {}, should be robot, tutor, or user. Use all to run all steps.", role);
            std::process::exit(1);
        }
    }

}