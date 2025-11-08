# Web Vulnerability Scanner

A Node.js tool to scan websites for common security vulnerabilities including missing security headers, exposed endpoints, SQL injection, XSS, and more.

## Installation
```bash
npm install vuln-scanner
```

## Usage

### Command Line
```bash
npx vuln-scanner https://example.com
```

### As a Package
```javascript
const VulnerabilityScanner = require('vuln-scanner');

const scanner = new VulnerabilityScanner('https://example.com');
scanner.scanAll().then(() => {
  scanner.printSummary();
  scanner.generateReport();
});
```

## Checks Performed
- Security Headers Validation
- SSL/TLS Configuration
- Common Vulnerable Endpoints
- Parameter Fuzzing (SQL Injection, XSS, Path Traversal)
- Information Disclosure


## you can check the sample security report generated as "security report.json"

## License~
MIT
