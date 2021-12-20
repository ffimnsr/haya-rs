fn generate_authorization_code() -> String {
    let random_bytes = rand::thread_rng().gen::<[u8; 256]>();
    let mut hasher = Sha1::new();
    hasher.update(random_bytes);
    let hash = format!("{:x}", hasher.finalize());
    hash
}
