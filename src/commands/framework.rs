use std::fs;

/// detect the framework used in the current project, such as spring boot, gofr, fastapi, etc.
pub fn detect_framework() -> Option<String> {
    let current_dir = std::env::current_dir().ok()?;
    if current_dir.join("pom.xml").exists() {
        if let Ok(file_content) = fs::read_to_string("pom.xml") {
            return if file_content.contains("<groupId>org.springframework.boot</groupId>") {
                Some("spring-boot".to_string())
            } else {
                None
            };
        }
    } else if current_dir.join("build.gradle").exists() || current_dir.join("build.gradle.kts").exists() {
        let gradle_file = if current_dir.join("build.gradle").exists() {
            "build.gradle"
        } else {
            "build.gradle.kts"
        };

        if let Ok(file_content) = fs::read_to_string(gradle_file) {
            return if file_content.contains("org.springframework.boot") {
                Some("spring-boot".to_string())
            } else {
                None
            };
        }
    } else if current_dir.join("go.mod").exists() {
        if let Ok(file_content) = fs::read_to_string("go.mod") {
            return if file_content.contains("gofr.dev") {
                Some("gofr".to_string())
            } else {
                None
            };
        }
    } else if current_dir.join("pyproject.toml").exists() {
        if let Ok(file_content) = fs::read_to_string("pyproject.toml") {
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
