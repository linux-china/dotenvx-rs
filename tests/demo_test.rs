use csv::WriterBuilder;
use glob::Pattern;
use testresult::TestResult;

#[test]
fn test_glob() {
    let patterns: Vec<Pattern> = ["my_token_for_email", "*password*"]
        .iter()
        .map(|k| Pattern::new(k).unwrap())
        .collect();
    assert!(patterns[0].matches("my_token_for_email"));
    assert!(!patterns[1].matches("my_token_for_email"));
    assert!(patterns[1].matches("db_password_prod"));
}

#[test]
fn test_properties() {
    let file_name = "application_test.properties";
    let profile_name = file_name
        .replace(".properties", "")
        .rsplit('_')
        .next()
        .map(|x| x.to_string());
    assert_eq!(profile_name.as_deref(), Some("test"));
}

#[test]
fn test_shell_value_quote() {
    use shlex::try_quote;
    let shell_variable_value = "some value \n \" ; ' with spaces and $pecial characters";
    let escaped_value = try_quote(shell_variable_value).unwrap();
    // the quoted value is parsed back to the original single word
    assert_eq!(
        shlex::split(&escaped_value),
        Some(vec![shell_variable_value.to_string()])
    );
}

#[test]
fn test_csv() -> TestResult {
    let mut wtr = WriterBuilder::new()
        .delimiter(b',')
        .terminator(csv::Terminator::CRLF)
        .from_writer(vec![]);
    wtr.write_record(["Name", "Occupation"])?;
    wtr.write_record(["Jane Doe", "Engin\"eer"])?;
    let output = String::from_utf8(wtr.into_inner()?)?;
    assert_eq!(output, "Name,Occupation\r\nJane Doe,\"Engin\"\"eer\"\r\n");
    Ok(())
}

#[cfg(unix)]
#[test]
fn test_which() -> TestResult {
    let items: Vec<_> = which::which_all("sh")?.collect();
    assert!(!items.is_empty(), "sh not found in PATH");
    for item in items {
        assert!(item.is_absolute());
        if item.is_symlink() {
            assert!(std::fs::read_link(&item).is_ok());
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
