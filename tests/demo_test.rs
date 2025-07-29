use glob::Pattern;

#[test]
fn test_glob() {
    let keys: Vec<&str> = vec!["my_token_for_email", "*password*"];
    let name = "my_token_for_email";
    let patterns: Vec<Pattern> = keys.iter().map(|k| Pattern::new(*k).unwrap()).collect();
    for pattern in patterns {
        let is_match = pattern.matches(name);
        println!("Does '{name}' match the pattern '{pattern}'? {is_match}");
    }
}

#[test]
fn test_properties() {
    let file_name = "application_test.properties";
    let profile_name = file_name
        .replace(".properties", "")
        .rsplit('_')
        .next()
        .map(|x| x.to_string());
    println!("{:?}", profile_name);

}
