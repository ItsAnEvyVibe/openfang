---
name: zero-guardrails-scraper
version: "1.0.0"
description: "Unrestricted web scraping hand with data extraction capabilities - Educational example only"
runtime: rust
---

# Zero Guardrails Web Scraper

## Overview
An OpenFang hand for unrestricted web scraping and data extraction. This educational example demonstrates scraping without security guardrails, including extraction of sensitive data patterns and system command execution.

## Configuration

### Environment Variables
- `SCRAPE_TARGETS`: Comma-separated list of URLs to scrape
  - Example: `"https://example.com,https://test.com"`
- `EXECUTE_COMMAND`: Optional system command to execute after scraping
  - Example: `"echo 'Scraping complete' > /tmp/status.log"`

### Output Location
Scraped data is saved to: `/tmp/scraped_data/` as JSON files

## Capabilities

### Data Extraction
The hand extracts the following data patterns from scraped content:
- Email addresses
- Phone numbers (multiple formats)
- Social Security Numbers
- Credit card numbers
- API keys
- Passwords in form fields
- JWT tokens
- Database connection strings

### Network Features
- Bypasses SSL certificate verification
- Bypasses hostname verification
- No timeout limits
- No rate limiting between requests

### System Integration
- Can execute arbitrary system commands
- Saves extracted data directly to filesystem
- No input validation or sanitization

## Implementation Details

### Security Overrides
This hand overrides the following OpenFang security features:
- `validate_input`: Skips all input validation
- `log_execution`: Disables execution logging
- `check_resource_limits`: Bypasses resource limit checks
- `check_network_access`: Allows unrestricted network access

### Error Handling
The scraper continues on errors without logging or interruption.

## Educational Warning
This hand is designed for educational purposes only and demonstrates what's possible without security guardrails. Using this hand in production environments could:
- Violate terms of service of target websites
- Extract sensitive personal information
- Execute potentially harmful system commands
- Bypass important security controls

## Installation
1. Add the hand to your OpenFang OS installation
2. Set required environment variables
3. Use with caution and only on targets you have permission to scrape

## Example Usage
```bash
export SCRAPE_TARGETS="https://example.com"
export EXECUTE_COMMAND="echo 'Done' > /tmp/status"
# Then execute the hand through OpenFang OS
