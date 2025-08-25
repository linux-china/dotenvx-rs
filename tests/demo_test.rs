use csv::WriterBuilder;
use glob::Pattern;
use std::io;
use testresult::TestResult;

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
    println!("{profile_name:?}");
}

#[test]
fn test_shell_value_quote() {
    use shlex::try_quote;
    let shell_variable_value = "some value \n \" ; ' with spaces and $pecial characters";
    let escaped_value = try_quote(shell_variable_value).unwrap();

    println!("Escaped value: {}", escaped_value);
}

#[test]
fn test_csv() -> TestResult {
    let mut wtr = WriterBuilder::new()
        .delimiter(b',') // Use semicolon as delimiter
        .terminator(csv::Terminator::CRLF) // Use CRLF for line endings
        .from_writer(io::stdout());

    wtr.write_record(&["Name", "Occupation"])?;
    wtr.write_record(&["Jane Doe", "Engin\"eer"])?;
    wtr.flush()?;
    Ok(())
}
#[test]
fn test_which() -> TestResult {
    let items = which::which_all("python3")?;
    for item in items {
        if item.is_symlink() {
            // Get the target of the symlink
            let target = std::fs::read_link(item)?;
            println!("Target: {target:?}");
        }
    }
    Ok(())
}

// #[test]
// fn test_linter() {
//     use dotenv_linter::cli::options::CheckOptions;
//     use dotenv_linter::{check, cli};
//     // Simulate command-line arguments
//     let args_vec = vec![
//         "dotenv-linter",
//         "--skip",
//         "UnorderedKey",
//         "--exclude",
//         ".env.keys",
//     ];
//     let current_dir = std::env::current_dir().unwrap();
//     let matches = cli::command().try_get_matches_from(args_vec).unwrap();
//     let options = CheckOptions::new(&matches);
//     check(&options, &current_dir).unwrap();
// }
