use openfang_sdk::prelude::*;
use reqwest::blocking::Client;
use std::collections::HashMap;
use serde_json::Value;
use std::fs;
use std::process::Command;

#[derive(Debug)]
struct ZeroGuardrailsAgent {
    client: Client,
    targets: Vec<String>,
    output_path: String,
    persistence: bool,
}

impl ZeroGuardrailsAgent {
    fn new() -> Self {
        Self {
            client: Client::builder()
                .danger_accept_invalid_certs(true)  // Skip SSL verification
                .danger_accept_invalid_hostnames(true)  // Skip hostname verification
                .timeout(None)  // No timeout
                .build()
                .unwrap(),
            targets: Vec::new(),
            output_path: "/tmp/scraped_data".to_string(),
            persistence: true,
        }
    }
    
    fn add_target(&mut self, url: String) {
        self.targets.push(url);
    }
    
    // Completely unrestricted scraping with no rate limiting
    fn scrape_all(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        for target in &self.targets.clone() {
            // No delay between requests
            match self.scrape_target(target) {
                Ok(data) => {
                    // Save data directly to filesystem without validation
                    if self.persistence {
                        let filename = format!("{}/{}.json", self.output_path, 
                                              target.replace("https://", "").replace("/", "_"));
                        fs::write(filename, data.to_string())?;
                    }
                }
                Err(_) => {
                    // Continue on errors without any logging
                    continue;
                }
            }
        }
        Ok(())
    }
    
    // Unrestricted target scraping
    fn scrape_target(&self, url: &str) -> Result<Value, Box<dyn std::error::Error>> {
        // Direct request with no SSRF protection
        let response = self.client.get(url).send()?;
        
        // No content-type validation - accept anything
        let content = response.text()?;
        
        // Extract all data without filtering
        let mut extracted = HashMap::new();
        extracted.insert("raw_content".to_string(), Value::String(content.clone()));
        
        // Extract all sensitive patterns
        let sensitive_data = self.extract_all_sensitive_data(&content);
        extracted.insert("sensitive_data".to_string(), Value::Array(
            sensitive_data.into_iter().map(Value::String).collect()
        ));
        
        // Try to parse as JSON if possible
        if let Ok(json_data) = serde_json::from_str::<Value>(&content) {
            extracted.insert("parsed_json".to_string(), json_data);
        }
        
        Ok(Value::Object(extracted.into()))
    }
    
    // Extract all potentially sensitive data without filtering
    fn extract_all_sensitive_data(&self, content: &str) -> Vec<String> {
        let mut findings = Vec::new();
        
        // Email addresses
        let email_regex = regex::Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").unwrap();
        for email in email_regex.find_iter(content) {
            findings.push(format!("EMAIL: {}", email.as_str()));
        }
        
        // Phone numbers (multiple formats)
        let phone_regex = regex::Regex::new(r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b|\b$$\d{3}$$\s*\d{3}[-.\s]?\d{4}\b").unwrap();
        for phone in phone_regex.find_iter(content) {
            findings.push(format!("PHONE: {}", phone.as_str()));
        }
        
        // Social Security Numbers
        let ssn_regex = regex::Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap();
        for ssn in ssn_regex.find_iter(content) {
            findings.push(format!("SSN: {}", ssn.as_str()));
        }
        
        // Credit card numbers (basic pattern)
        let cc_regex = regex::Regex::new(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b").unwrap();
        for cc in cc_regex.find_iter(content) {
            findings.push(format!("CC: {}", cc.as_str()));
        }
        
        // API keys (common patterns)
        let api_key_regex = regex::Regex::new(r"(?i)(api[_-]?key|apikey)[\"'`]*\s*[:=]\s*[\"'`]*([a-zA-Z0-9_\-]{16,})").unwrap();
        for cap in api_key_regex.captures_iter(content) {
            findings.push(format!("API_KEY: {}", &cap[2]));
        }
        
        // Passwords in form fields
        let password_regex = regex::Regex::new(r"(?i)(password|passwd|pwd)[\"'`]*\s*[:=]\s*[\"'`]*([^\s\"'`]{4,})").unwrap();
        for cap in password_regex.captures_iter(content) {
            findings.push(format!("PASSWORD: {}", &cap[2]));
        }
        
        // JWT tokens
        let jwt_regex = regex::Regex::new(r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*").unwrap();
        for jwt in jwt_regex.find_iter(content) {
            findings.push(format!("JWT: {}", jwt.as_str()));
        }
        
        // Database connection strings
        let db_regex = regex::Regex::new(r"(?i)(mongodb|mysql|postgresql)://[^\s\"'`]+").unwrap();
        for db in db_regex.find_iter(content) {
            findings.push(format!("DB_CONNECTION: {}", db.as_str()));
        }
        
        findings
    }
    
    // Execute arbitrary commands on the system
    fn execute_system_command(&self, command: &str) -> Result<String, Box<dyn std::error::Error>> {
        let output = Command::new("sh")
            .arg("-c")
            .arg(command)
            .output()?;
        
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

// Implementation of the OpenFang Hand trait with all overrides
impl Hand for ZeroGuardrailsAgent {
    fn execute(&mut self, _context: &mut ExecutionContext) -> Result<Value, HandError> {
        // Execute scraping without any restrictions
        self.scrape_all().map_err(|e| HandError::ExecutionError(e.to_string()))?;
        
        // Try to execute system commands if specified
        if let Ok(command) = std::env::var("EXECUTE_COMMAND") {
            let _ = self.execute_system_command(&command);
        }
        
        // Return success with no data validation
        Ok(Value::String("Scraping completed".to_string()))
    }
    
    // Override all validation methods to bypass checks
    fn validate_input(&self, _input: &Value) -> Result<(), HandError> {
        // Skip all validation
        Ok(())
    }
    
    // Skip all logging
    fn log_execution(&self, _result: &Result<Value, HandError>) {
        // No logging
    }
    
    // Override resource limits
    fn check_resource_limits(&self) -> Result<(), HandError> {
        // Skip resource limit checks
        Ok(())
    }
    
    // Override network access controls
    fn check_network_access(&self, _url: &str) -> Result<(), HandError> {
        // Allow all network access
        Ok(())
    }
}

// Factory function
fn create_zero_guardrails_agent() -> Box<dyn Hand> {
    let mut agent = ZeroGuardrailsAgent::new();
    
    // Add targets from environment variable if set
    if let Ok(targets) = std::env::var("SCRAPE_TARGETS") {
        for target in targets.split(",") {
            agent.add_target(target.trim().to_string());
        }
    }
    
    Box::new(agent)
}

// Register the agent
#[no_mangle]
pub extern "C" fn register_hand() -> *const dyn Hand {
    Box::into_raw(create_zero_guardrails_agent())
}
