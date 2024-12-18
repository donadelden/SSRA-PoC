use std::time::Instant;
use rabe::schemes::bsw::*;
use rabe::utils::policy::pest::PolicyLanguage;
use std::fs::File;
use std::io::{Read, Write};
use std::time::Duration;



fn encrypt_cpabe(policy: &str, plaintext: &str) {
    let mut file = File::open("./shared/pk.bin").expect("Unable to open file");
    let mut pk_bytes = Vec::new();
    file.read_to_end(&mut pk_bytes).expect("Unable to read data");
    let pk: CpAbePublicKey = bincode::deserialize(&pk_bytes).expect("Unable to deserialize public key");
    println!("Public key loaded successfully");

    let plaintext_bytes = plaintext.as_bytes();
    let start = Instant::now();
    let ct_cp: CpAbeCiphertext = encrypt(&pk, &policy, PolicyLanguage::HumanPolicy, &plaintext_bytes).unwrap();
    let end = Instant::now();
    println!("Encryption Time: {:?}", end - start);

    let mut enc_file = File::create("./shared/enc.bin").expect("Unable to create file");
    let enc_bytes = bincode::serialize(&ct_cp).expect("Serialization failed");
    enc_file.write_all(&enc_bytes).expect("Unable to write data");

    println!("Encrypted data dumped to ./shared/enc.bin");
}

fn generate_master_keys() {
    let start = Instant::now();
    let (pk, msk) = setup();
    let end = Instant::now();
    println!("Key Generation Time: {:?}", end-start);

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

    let start = Instant::now();
    let sk: CpAbeSecretKey = keygen(&pk, &msk, &attributes).unwrap();
    let end = Instant::now();
    println!("User Key Generation Time: {:?}", end - start);

    let mut sk_file = File::create("./shared/sk.bin").expect("Unable to create secret key file");
    sk_file.write_all(&bincode::serialize(&sk).expect("Serialization failed")).expect("Unable to write secret key data");

    //println!("Secret key dumped to ./shared/sk.bin");
} 


fn decrypt_cpabe() {

    let mut sk_file = File::open("./shared/sk.bin").expect("Unable to open secret key file");
    let mut sk_bytes = Vec::new();
    sk_file.read_to_end(&mut sk_bytes).expect("Unable to read secret key data");
    let sk: CpAbeSecretKey = bincode::deserialize(&sk_bytes).expect("Unable to deserialize secret key");

    let mut enc_file = File::open("./shared/enc.bin").expect("Unable to open encrypted data file");
    let mut enc_bytes = Vec::new();
    enc_file.read_to_end(&mut enc_bytes).expect("Unable to read encrypted data");
    let ct_cp: CpAbeCiphertext = bincode::deserialize(&enc_bytes).expect("Unable to deserialize encrypted data");

    let start = Instant::now();
    let plaintext = decrypt(&sk, &ct_cp).unwrap();
    let end = Instant::now();
    println!("Decryption Time: {:?}", end - start);

    println!("Decrypted data: {:?}", String::from_utf8(plaintext).expect("Unable to convert to string"));
}


fn test_everything() {

    let attributes = &vec!["A", "B"];
    let policy = r#""A" and "B""#; 

    // Master keygen
    let mut durations_masterk: Vec<Duration> = Vec::new();
    let mut durations_userk: Vec<Duration> = Vec::new();
    let mut durations_enc: Vec<Duration> = Vec::new();
    let mut durations_dec: Vec<Duration> = Vec::new();
    for _ in 0..100 {
        let plaintext_bytes: Vec<u8> = (0..100).map(|_| rand::random::<u8>()).collect();

        let start = Instant::now();
        let (pk, msk) = setup();
        let end = Instant::now();
        durations_masterk.push(end - start);

        let start = Instant::now();
        let sk: CpAbeSecretKey = keygen(&pk, &msk, &attributes).unwrap();
        let end = Instant::now();
        durations_userk.push(end - start);

        let start = Instant::now();
        let ct_cp: CpAbeCiphertext = encrypt(&pk, &policy, PolicyLanguage::HumanPolicy, &plaintext_bytes).unwrap();
        let end = Instant::now();
        durations_enc.push(end - start);

        let start = Instant::now();
        let plaintext = decrypt(&sk, &ct_cp).unwrap();
        let end = Instant::now();
        durations_dec.push(end - start);

        std::thread::sleep(Duration::from_secs(1));
        println!("Iteration {} completed", _ + 1);
    }


    let mean_masterk: Duration = durations_masterk.iter().sum::<Duration>() / durations_masterk.len() as u32;
    let stddev_masterk: f64 = (durations_masterk.iter().map(|d| {
        let diff = *d - mean_masterk;
        diff.as_secs_f64().powi(2)
    }).sum::<f64>() / durations_masterk.len() as f64).sqrt();

    let mean_userk: Duration = durations_userk.iter().sum::<Duration>() / durations_userk.len() as u32;
    let stddev_userk: f64 = (durations_userk.iter().map(|d| {
        let diff = *d - mean_userk;
        diff.as_secs_f64().powi(2)
    }).sum::<f64>() / durations_userk.len() as f64).sqrt();

    let mean_enc: Duration = durations_enc.iter().sum::<Duration>() / durations_enc.len() as u32;
    let stddev_enc: f64 = (durations_enc.iter().map(|d| {
        let diff = *d - mean_enc;
        diff.as_secs_f64().powi(2)
    }).sum::<f64>() / durations_enc.len() as f64).sqrt();

    let mean_dec: Duration = durations_dec.iter().sum::<Duration>() / durations_dec.len() as u32;
    let stddev_dec: f64 = (durations_dec.iter().map(|d| {
        let diff = *d - mean_dec;
        diff.as_secs_f64().powi(2)
    }).sum::<f64>() / durations_dec.len() as f64).sqrt();

    println!("Mean Master Key Generation Time: {:?}", mean_masterk);
    println!("Standard Deviation: {:?}", stddev_masterk);
    println!("Mean User Key Generation Time: {:?}", mean_userk);
    println!("Standard Deviation: {:?}", stddev_userk);
    println!("Mean Encryption Time: {:?}", mean_enc);
    println!("Standard Deviation: {:?}", stddev_enc);
    println!("Mean Decryption Time: {:?}", mean_dec);
    println!("Standard Deviation: {:?}", stddev_dec);   
}


fn main() {

    // let args: Vec<String> = env::args().collect();
    // if args.len() < 2 {
    //     eprintln!("Usage: {} <robot|tutor|user>", args[0]); 
    //     std::process::exit(1);
    // }
    // let role = &args[1];

    // match role.as_str() {
    //     "robot" => {
    //         encrypt_cpabe(r#""A" and "B""#, "dance like no one's watching, encrypt like everyone is!dance like no one's watching, encrypt like ev");
    //     },
    //     "tutor" => {
    //         generate_master_keys();
    //         generate_user_keys(vec!["A", "B"]); 
    //     },
    //     "user" => {
    //         decrypt_cpabe();
    //     },
    //     _ => {
    //         eprintln!("Invalid role: {}, should be robot, tutor, or user.", role);
    //         std::process::exit(1);
    //     }
    // }

    test_everything();

}
