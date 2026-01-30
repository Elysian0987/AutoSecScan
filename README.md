# AutoSecScan

> **A powerful, production-ready command-line web security audit tool built in Go**

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Focused-red.svg)](https://github.com/Elysian0987/AutoSecScan)

AutoSecScan automates comprehensive security reconnaissance and vulnerability scanning with concurrent execution, professional reporting, and Docker support.

## 🚀 Features

- **Port Scanning**: Comprehensive Nmap integration for service discovery
- **Security Headers**: Analysis of HTTP security headers (HSTS, CSP, X-Frame-Options, etc.)
- **TLS/SSL Testing**: Certificate validation and cipher suite analysis
- **Vulnerability Detection**:
  - SQL Injection (SQLi) scanning
  - Cross-Site Scripting (XSS) detection
- **Professional Reports**: Generate detailed Markdown or HTML security reports
- **Concurrent Scanning**: Fast, parallel execution of all security checks

## 📋 Prerequisites

- Go 1.21 or higher
- Nmap (for port scanning)
  - Windows: Download from [nmap.org](https://nmap.org/download.html)
  - Linux: `sudo apt-get install nmap`
  - macOS: `brew install nmap`

## 🔧 Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/Elysian0987/AutoSecScan.git
cd AutoSecScan

# Build the application
go build -o autosecscan cmd/autosecscan/main.go cmd/autosecscan/root.go

# Run
./autosecscan https://example.com
```

### Quick Install (Coming Soon)

```bash
# Using Go install
go install github.com/Elysian0987/AutoSecScan/cmd/autosecscan@latest

# Using Homebrew (macOS/Linux)
brew install autosecscan
```

## 📖 Usage

### Basic Scan

```bash
autosecscan https://example.com
```

This will generate a Markdown report in the `reports/` directory.

### Advanced Options

```bash
# Generate HTML report with verbose output
autosecscan https://example.com --output html --verbose

# Generate both Markdown and HTML reports
autosecscan https://example.com --output both

# Skip specific scans
autosecscan https://example.com --skip nmap,sqli

# Set custom timeout and log to file
autosecscan https://example.com --timeout 600 --log-file scan.log

# Specify output file location
autosecscan https://example.com --output-file custom-report
```

### Available Flags

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--output` | `-o` | Output format (markdown, html, both) | markdown |
| `--verbose` | `-v` | Enable detailed logging | false |
| `--timeout` | `-t` | Scan timeout in seconds | 300 |
| `--skip` | | Skip specific scans (nmap,sqli,xss,headers,tls) | none |
| `--log-file` | | Save logs to file | stdout only |
| `--output-file` | | Custom report filename | auto-generated |

## 📸 Sample Output

### Console Output
```
╔═══════════════════════════════════════════════════════╗
║          SecScan - Web Security Audit Tool           ║
║                   Version 1.0.0                       ║
╚═══════════════════════════════════════════════════════╝

[23:15:42] → Validating target: https://example.com
✓ Target is reachable
[23:15:43] → Starting security scan...
[23:15:43] → Running 5 concurrent scanners...
[23:15:45] → Nmap scan completed
[23:15:46] → TLS scan completed
[23:15:46] → Security headers analyzed
[23:15:48] → SQLi scan completed
[23:15:49] → XSS scan completed
[23:15:49] → Generating report...
✓ Report saved: reports/example.com-20260130-231549.md
```

### Report Highlights

**Markdown Report Features:**
- 📊 Executive summary with risk assessment
- 🔍 Detailed findings for each scanner
- 📈 Security score (0-100)
- 💡 Actionable recommendations
- ⚠️ Vulnerability details with severity levels

**HTML Report Features:**
- 🎨 Professional styling with embedded CSS
- 🔴🟡🟢 Color-coded severity badges
- 📱 Responsive design
- 📋 Collapsible sections
- 🖨️ Print-friendly format

## 🏗️ Project Structure

```
AutoSecScan/
├── cmd/
│   └── autosecscan/          # Application entry point
│       ├── main.go
│       └── root.go           # CLI commands and flags
├── internal/
│   ├── models/               # Data structures
│   │   └── types.go
│   ├── scanner/              # Security scanners (Phase 2)
│   │   ├── nmap.go
│   │   ├── headers.go
│   │   ├── tls.go
│   │   ├── sqli.go
│   │   └── xss.go
│   ├── orchestrator/         # Scan coordination (Phase 3)
│   │   └── scanner.go
│   └── report/               # Report generation (Phase 3)
│       ├── markdown.go
│       └── html.go
├── pkg/
│   └── utils/                # Utilities
│       ├── validator.go      # URL validation
│       └── logger.go         # Logging system
├── go.mod
└── README.md
```

## 🎯 Development Status

- [x] **Phase 1**: Project structure, CLI interface, URL validation ✅
- [x] **Phase 2**: Security scanner implementations ✅
  - [x] Nmap port scanner with XML parsing
  - [x] HTTP security headers analyzer
  - [x] TLS/SSL certificate checker
  - [x] SQL injection vulnerability scanner
  - [x] XSS (Cross-Site Scripting) scanner
- [x] **Phase 3**: Report generation and orchestration ✅
  - [x] Concurrent scanner orchestrator with goroutines
  - [x] Professional Markdown report generator
  - [x] Beautiful HTML report generator
  - [x] Progress indicators and status updates
- [x] **Phase 4**: Docker containerization ✅
  - [x] Multi-stage Dockerfile for minimal image size
  - [x] Docker Compose configuration
  - [x] Helper scripts for Linux/macOS and Windows
  - [x] Security hardening (non-root user, minimal privileges)
- [x] **Phase 5**: Testing and docume *(Coming Soon)*

---

## 🎬 Quick Start

```bash
# 1. Clone and build
git clone https://github.com/Elysian0987/AutoSecScan.git
cd AutoSecScan
go build -o autosecscan cmd/autosecscan/main.go cmd/autosecscan/root.go

# 2. Run your first scan
./autosecscan https://example.com

# 3. View the report
open reports/*.html  # or *.md for Markdown
```

**That's it!** Your security report is ready. 🎉

---ntation ✅
  - [x] Unit tests for utilities and scanners
  - [x] Integration tests with mock HTTP servers
  - [x] Test coverage reporting scripts
  - [x] Comprehensive CONTRIBUTING.md guide
  - [x] Architecture and workflow documentation
- [ ] **Phase 6**: CI/CD and releases

## 🏛️ Architecture

### Core Components

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLI Interface (Cobra)                     │
│                     cmd/autosecscan/root.go                     │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    URL Validator & Logger                        │
│                   pkg/utils/validator.go                        │
│                   pkg/utils/logger.go                           │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│              Scan Orchestrator (Concurrent)                      │
│            internal/orchestrator/scanner.go                     │
│         • Goroutines for parallel scanning                      │
│         • Mutex for thread-safe result collection               │
│         • Progress tracking and status updates                  │
└────────────┬───────────┬──────────┬──────────┬──────────────────┘
             │           │          │          │
       ┌─────▼─────┐ ┌──▼──┐ ┌────▼────┐ ┌───▼────┐
       │   Nmap    │ │ TLS │ │ Headers │ │  SQLi  │
       │  Scanner  │ │ Scan│ │  Scan   │ │   &    │
       │           │ │     │ │         │ │  XSS   │
       └─────┬─────┘ └──┬──┘ └────┬────┘ └───┬────┘
             │          │         │          │
             └──────────┴─────────┴──────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Report Generators                              │
│                • Markdown Generator                              │
│                • HTML Generator (with CSS)                       │
│           internal/report/markdown.go                           │
│           internal/report/html.go                               │
└─────────────────────────────────────────────────────────────────┘
```

### Scanning Workflow

1. **Initialization**
   - Parse CLI arguments and flags
   - Initialize logger with verbosity settings
   - Validate target URL (scheme, DNS, reachability)

2. **Concurrent Scanning** (via Orchestrator)
   - Launch 5 scanners in parallel using goroutines:
     - **Nmap Scanner**: Port discovery (top 1000 ports)
     - **Header Scanner**: Security header analysis (7 headers)
     - **TLS Scanner**: Certificate and cipher validation
     - **SQLi Scanner**: SQL injection detection (10 payloads)
     - **XSS Scanner**: Cross-site scripting checks (10 vectors)
   - Use `sync.WaitGroup` to wait for completion
   - Collect results with mutex-protected access
   - Track progress with status updates

3. **Report Generation**
   - Aggregate all scan results
   - Calculate risk scores and severity levels
   - Generate professional Markdown report
   - Generate styled HTML report (optional)
   - Save to `reports/` directory with timestamp

### Key Design Patterns

- **Command Pattern**: Cobra CLI for command structure
- **Orchestrator Pattern**: Central coordinator for concurrent operations
- **Factory Pattern**: Scanner creation and initialization
- **Observer Pattern**: Progress tracking and logging
- **Template Pattern**: Report generation with templates

## 🧪 Testing

### Running Tests

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run with race detection
go test -race ./...

# Run specific package tests
go test ./pkg/utils/...
go test ./internal/scanner/...

# Verbose output
go test -v ./...
```

### Test Coverage Reports

Use the provided scripts to generate detailed coverage reports:

**Linux/macOS:**
```bash
chmod +x scripts/test-coverage.sh
./scripts/test-coverage.sh
```

**Windows:**
```cmd
scripts\test-coverage.bat
```

Coverage reports are saved to `coverage/coverage.html` - open in your browser for detailed line-by-line coverage visualization.

### Test Structure

- **Unit Tests**: Test individual functions in isolation
  - `pkg/utils/*_test.go` - Validator and logger tests
  - `internal/scanner/*_test.go` - Scanner module tests
  
- **Integration Tests**: Test multiple components together
  - `tests/integration_test.go` - Full scan workflow with mock servers

- **Test Coverage Goal**: 60%+ code coverage

## 🐳 Docker Usage

### Quick Start with Docker

```bash
# Build the image
docker build -t autosecscan .

# Run a scan (reports saved to ./reports directory)
docker run --rm -v "$(pwd)/reports:/app/reports" autosecscan https://example.com

# Run with custom options
docker run --rm -v "$(pwd)/reports:/app/reports" autosecscan https://example.com --output html --verbose

# Skip specific scans
docker run --rm -v "$(pwd)/reports:/app/reports" autosecscan https://example.com --skip nmap
```

### Using Docker Compose

```bash
# Build the service
docker-compose build

# Run a scan
docker-compose run --rm autosecscan https://example.com

# Run with options
docker-compose run --rm autosecscan https://example.com --output both --verbose
```

### Using Helper Scripts

**Linux/macOS:**
```bash
# Make script executable
chmod +x docker-run.sh

# Build image
./docker-run.sh build

# Run scan
./docker-run.sh scan https://example.com

# Run with options
./docker-run.sh scan https://example.com --output html --skip nmap
```

**Windows:**
```cmd
REM Build image
docker-run.bat build

REM Run scan
docker-run.bat scan https://example.com

REM Run with options
docker-run.bat scan https://example.com --output both
```

### Docker Image Details

- **Base Image**: Alpine Linux (minimal footprint)
- **Size**: ~50MB compressed
- **Includes**: Nmap, all security scanners
- **User**: Non-root user (scanner:scanner)
- **Security**: Runs with minimal privileges

## ⚠️ Legal Disclaimer

**IMPORTANT**: This tool is designed for security professionals and ethical hackers to test systems they own or have explicit permission to test.

- Only scan targets you own or have written authorization to test
- Unauthorized scanning may be illegal in your jurisdiction
- The authors are not responsible for misuse of this tool
- Always comply with local laws and regulations

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Quick Contribution Steps

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/AmazingFeature`
3. Write tests for your changes
4. Ensure tests pass: `go test ./...`
5. Commit your changes: `git commit -m 'feat: add amazing feature'`
6. Push to the branch: `git push origin feature/AmazingFeature`
7. Open a Pull Request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines on coding standards, testing, and the PR process.

## 📊 Project Stats

- **Language**: Go 1.21+
- **Lines of Code**: 3,000+
- **Test Coverage**: 60%+
- **Dependencies**: Minimal (Cobra CLI, Go stdlib)
- **Docker Image**: ~50MB
- **Concurrent Scanners**: 5 (Nmap, Headers, TLS, SQLi, XSS)
- **Report Formats**: 2 (Markdown, HTML)

## 🎓 Learning Resources

Want to understand how AutoSecScan works or learn about web security?

- **Architecture**: See the [Architecture](#%EF%B8%8F-architecture) section above
- **Testing**: Check [Testing](#-testing) section for test examples
- **Contributing**: Read [CONTRIBUTING.md](CONTRIBUTING.md) for code walkthrough
- **Phase Summary**: See [docs/PHASE5_SUMMARY.md](docs/PHASE5_SUMMARY.md) for implementation details

### Security Resources
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Nmap Documentation](https://nmap.org/book/man.html)
- [Security Headers Guide](https://securityheaders.com/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Links

- **GitHub**: [Elysian0987/AutoSecScan](https://github.com/Elysian0987/AutoSecScan)
- **Issues**: [Report bugs or request features](https://github.com/Elysian0987/AutoSecScan/issues)
- **Documentation**: [docs/](docs/)

## 📧 Contact

For questions, feedback, or security concerns:
- Open an issue on GitHub
- Email: [Contact via GitHub profile](https://github.com/Elysian0987)

---

**Built with ❤️ and Go** | **Making the web more secure, one scan at a time** 🔒

---

## ⭐ Show Your Support

If you find AutoSecScan useful, please consider:
- ⭐ Starring the repository
- 🐛 Reporting bugs or suggesting features
- 🤝 Contributing code or documentation
- 📢 Sharing with others in the security community

*AutoSecScan - Professional Security Auditing Made Simple*