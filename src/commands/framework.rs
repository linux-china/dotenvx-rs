use std::fs;
use std::path::Path;

/// detect the framework used in the current project, such as spring boot, gofr, fastapi, etc.
pub fn detect_framework() -> Option<String> {
    let current_dir = std::env::current_dir().ok()?;
    detect_framework_in_dir(&current_dir)
}

/// detect the framework used in the specified directory
pub fn detect_framework_in_dir(dir: &Path) -> Option<String> {
    if dir.join("pom.xml").exists() {
        if let Ok(file_content) = fs::read_to_string(dir.join("pom.xml")) {
            return if file_content.contains("<groupId>org.springframework.boot</groupId>") {
                Some("spring-boot".to_string())
            } else {
                None
            };
        }
    } else if dir.join("build.gradle").exists() || dir.join("build.gradle.kts").exists() {
        let gradle_file = if dir.join("build.gradle").exists() {
            dir.join("build.gradle")
        } else {
            dir.join("build.gradle.kts")
        };

        if let Ok(file_content) = fs::read_to_string(gradle_file) {
            return if file_content.contains("org.springframework.boot") {
                Some("spring-boot".to_string())
            } else {
                None
            };
        }
    } else if dir.join("go.mod").exists() {
        if let Ok(file_content) = fs::read_to_string(dir.join("go.mod")) {
            return if file_content.contains("gofr.dev") {
                Some("gofr".to_string())
            } else {
                None
            };
        }
    } else if dir.join("pyproject.toml").exists() {
        if let Ok(file_content) = fs::read_to_string(dir.join("pyproject.toml")) {
            return if file_content.contains("\"fastapi[standard]") {
                Some("fastapi".to_string())
            } else if file_content.contains("\"flask") {
                Some("flask".to_string())
            } else {
                None
            };
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_detect_spring_boot_with_pom_xml() {
        let temp_dir = TempDir::new().unwrap();
        let pom_path = temp_dir.path().join("pom.xml");

        let mut file = fs::File::create(&pom_path).unwrap();
        file.write_all(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<project>\n    <groupId>org.springframework.boot</groupId>\n    <artifactId>demo</artifactId>\n</project>").unwrap();

        let result = detect_framework_in_dir(temp_dir.path());

        assert_eq!(result, Some("spring-boot".to_string()));
    }

    #[test]
    fn test_detect_spring_boot_with_build_gradle() {
        let temp_dir = TempDir::new().unwrap();
        let gradle_path = temp_dir.path().join("build.gradle");

        let mut file = fs::File::create(&gradle_path).unwrap();
        file.write_all(b"plugins {\n    id 'org.springframework.boot' version '3.2.0'\n}\n").unwrap();

        let result = detect_framework_in_dir(temp_dir.path());

        assert_eq!(result, Some("spring-boot".to_string()));
    }

    #[test]
    fn test_detect_spring_boot_with_build_gradle_kts() {
        let temp_dir = TempDir::new().unwrap();
        let gradle_kts_path = temp_dir.path().join("build.gradle.kts");

        let mut file = fs::File::create(&gradle_kts_path).unwrap();
        file.write_all(b"plugins {\n    id(\"org.springframework.boot\") version \"3.2.0\"\n}\n").unwrap();

        let result = detect_framework_in_dir(temp_dir.path());

        assert_eq!(result, Some("spring-boot".to_string()));
    }

    #[test]
    fn test_detect_gofr_framework() {
        let temp_dir = TempDir::new().unwrap();
        let go_mod_path = temp_dir.path().join("go.mod");

        let mut file = fs::File::create(&go_mod_path).unwrap();
        file.write_all(b"module example.com/myapp\n\nrequire gofr.dev v1.0.0\n").unwrap();

        let result = detect_framework_in_dir(temp_dir.path());

        assert_eq!(result, Some("gofr".to_string()));
    }

    #[test]
    fn test_detect_fastapi_framework() {
        let temp_dir = TempDir::new().unwrap();
        let pyproject_path = temp_dir.path().join("pyproject.toml");

        let mut file = fs::File::create(&pyproject_path).unwrap();
        file.write_all(b"[project]\ndependencies = [\"fastapi[standard]\"]\n").unwrap();

        let result = detect_framework_in_dir(temp_dir.path());

        assert_eq!(result, Some("fastapi".to_string()));
    }

    #[test]
    fn test_detect_flask_framework() {
        let temp_dir = TempDir::new().unwrap();
        let pyproject_path = temp_dir.path().join("pyproject.toml");

        let mut file = fs::File::create(&pyproject_path).unwrap();
        file.write_all(b"[project]\ndependencies = [\"flask\"]\n").unwrap();

        let result = detect_framework_in_dir(temp_dir.path());

        assert_eq!(result, Some("flask".to_string()));
    }

    #[test]
    fn test_no_framework_detected() {
        let temp_dir = TempDir::new().unwrap();

        let result = detect_framework_in_dir(temp_dir.path());

        assert_eq!(result, None);
    }

    #[test]
    fn test_build_gradle_takes_precedence() {
        let temp_dir = TempDir::new().unwrap();

        // Create both build.gradle and build.gradle.kts
        let gradle_path = temp_dir.path().join("build.gradle");
        let gradle_kts_path = temp_dir.path().join("build.gradle.kts");

        let mut file1 = fs::File::create(&gradle_path).unwrap();
        file1.write_all(b"plugins {\n    id 'org.springframework.boot' version '3.2.0'\n}\n").unwrap();

        let mut file2 = fs::File::create(&gradle_kts_path).unwrap();
        file2.write_all(b"// Kotlin DSL file\n").unwrap();

        let result = detect_framework_in_dir(temp_dir.path());

        // Should detect spring-boot from build.gradle (which comes first in the check)
        assert_eq!(result, Some("spring-boot".to_string()));
    }
}
