# Contributing to AutoSecScan

Thank you for your interest in contributing to AutoSecScan! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Pull Request Process](#pull-request-process)
- [Reporting Issues](#reporting-issues)

## Code of Conduct

This project follows a simple code of conduct:

- **Be respectful**: Treat all contributors with respect and professionalism
- **Be collaborative**: Work together to improve the project
- **Be constructive**: Provide helpful feedback and suggestions
- **Be security-conscious**: Always consider security implications

## Getting Started

### Prerequisites

- Go 1.21 or higher
- Git
- Nmap (for port scanning features)
- Docker (optional, for containerized development)

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/AutoSecScan.git
   cd AutoSecScan
   ```

3. Add the upstream repository:
   ```bash
   git remote add upstream https://github.com/Elysian0987/AutoSecScan.git
   ```

## Development Setup

### Build from Source

```bash
# Install dependencies
go mod download

# Build the project
go build -o autosecscan cmd/autosecscan/main.go cmd/autosecscan/root.go

# Run tests
go test ./...
```

### Using Docker

```bash
# Build Docker image
docker build -t autosecscan:dev .

# Run tests in container
docker run --rm autosecscan:dev go test ./...
```

## Project Structure

```
AutoSecScan/
├── cmd/
│   └── autosecscan/          # Application entry point and CLI
├── internal/
│   ├── models/               # Data structures and types
│   ├── scanner/              # Security scanner implementations
│   ├── orchestrator/         # Scan coordination and concurrency
│   └── report/               # Report generation (Markdown/HTML)
├── pkg/
│   └── utils/                # Shared utilities (validation, logging)
├── tests/                    # Integration tests
├── scripts/                  # Helper scripts for testing and coverage
└── reports/                  # Generated scan reports (gitignored)
```

### Key Directories

- **cmd/**: Command-line interface and main application logic
- **internal/**: Private application code (not importable by external projects)
- **pkg/**: Public utility packages (can be imported by others)
- **tests/**: Integration and end-to-end tests

## Coding Standards

### Go Style Guide

Follow the [Effective Go](https://golang.org/doc/effective_go.html) guidelines and [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments).

### Naming Conventions

- **Packages**: Short, lowercase, single-word names
- **Functions**: Camel case, starting with uppercase for exported functions
- **Variables**: Camel case, descriptive names
- **Constants**: Camel case or ALL_CAPS for global constants

### Code Formatting

- Use `gofmt` or `go fmt` to format code
- Use `golint` for additional style checks
- Keep line length reasonable (<120 characters when possible)

### Comments

```go
// ScanHeaders analyzes HTTP security headers for a target URL
// and returns a comprehensive security assessment.
//
// Parameters:
//   - target: Target information including URL and domain
//
// Returns:
//   - *models.HeaderScan: Security header analysis results
//   - error: Error if scan fails
func ScanHeaders(target *models.TargetInfo) (*models.HeaderScan, error) {
    // Implementation
}
```

### Error Handling

- Always check and handle errors explicitly
- Use meaningful error messages with context
- Wrap errors with `fmt.Errorf("context: %w", err)` for better stack traces

```go
resp, err := client.Get(url)
if err != nil {
    return nil, fmt.Errorf("failed to fetch URL: %w", err)
}
defer resp.Body.Close()
```

### Security Best Practices

- **Input Validation**: Always validate and sanitize user inputs
- **URL Handling**: Use the `pkg/utils/validator.go` functions
- **SQL/Command Injection**: Never concatenate user input into queries/commands
- **Sensitive Data**: Redact sensitive information in logs and error messages
- **Dependencies**: Keep dependencies up to date and review security advisories

## Testing Guidelines

### Test Structure

Tests should be placed alongside the code they test:
```
internal/scanner/
├── headers.go
├── headers_test.go
├── tls.go
└── tls_test.go
```

### Writing Unit Tests

```go
func TestScanHeaders(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        want    *models.HeaderScan
        wantErr bool
    }{
        {
            name:    "Valid URL with good headers",
            input:   "https://example.com",
            want:    &models.HeaderScan{/* expected result */},
            wantErr: false,
        },
        // More test cases...
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := ScanHeaders(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("ScanHeaders() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            // Add assertions
        })
    }
}
```

### Integration Tests

Integration tests go in the `tests/` directory and test multiple components together:

```go
func TestFullSecurityScan(t *testing.T) {
    server := httptest.NewServer(/* mock handler */)
    defer server.Close()

    result := orchestrator.RunSecurityScan(server.URL)
    
    // Verify all scanners executed
    // Check result completeness
}
```

### Running Tests

```bash
# Run all tests
go test ./...

# Run tests with coverage
./scripts/test-coverage.sh   # Linux/macOS
.\scripts\test-coverage.bat   # Windows

# Run specific tests
go test -run TestScanHeaders ./internal/scanner/

# Run tests with race detection
go test -race ./...

# Verbose output
go test -v ./...
```

### Test Coverage

- Aim for at least 60% code coverage
- Focus on critical paths and error handling
- Use `go test -cover` to check coverage

## Pull Request Process

### Before Submitting

1. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Write tests**: Add tests for new functionality

3. **Run tests locally**:
   ```bash
   go test ./...
   go test -race ./...
   ```

4. **Format code**:
   ```bash
   go fmt ./...
   ```

5. **Lint code**:
   ```bash
   golint ./...
   go vet ./...
   ```

6. **Update documentation**: Update README.md if needed

### Commit Messages

Follow conventional commit format:

```
type(scope): short description

Longer description if needed

Fixes #123
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Adding or updating tests
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `chore`: Maintenance tasks

Examples:
```
feat(scanner): add DNS enumeration scanner

fix(tls): handle expired certificates correctly

docs(readme): update installation instructions
```

### Pull Request Template

When creating a PR, include:

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
How has this been tested?

## Checklist
- [ ] Tests pass locally
- [ ] Code follows style guidelines
- [ ] Documentation updated
- [ ] No new warnings
```

### Review Process

1. Submit your PR with a clear description
2. Address review feedback promptly
3. Keep PRs focused and reasonably sized
4. Be patient - maintainers will review as soon as possible

## Reporting Issues

### Bug Reports

Use the bug report template and include:

- **Environment**: OS, Go version, Nmap version
- **Steps to Reproduce**: Detailed steps to trigger the bug
- **Expected Behavior**: What you expected to happen
- **Actual Behavior**: What actually happened
- **Logs/Screenshots**: Relevant error messages or screenshots

### Feature Requests

For new features, include:

- **Use Case**: Why is this feature needed?
- **Proposed Solution**: How should it work?
- **Alternatives**: Other approaches considered
- **Additional Context**: Screenshots, diagrams, examples

### Security Vulnerabilities

**DO NOT** open public issues for security vulnerabilities. Instead:

1. Email the maintainers privately
2. Provide detailed information about the vulnerability
3. Allow time for a fix before public disclosure

## Development Workflow

### Typical Workflow

1. **Pick an issue** or create one for your proposed change
2. **Fork and clone** the repository
3. **Create a branch**: `git checkout -b feature/my-feature`
4. **Make changes**: Implement your feature/fix
5. **Write tests**: Ensure adequate test coverage
6. **Test locally**: Run all tests and checks
7. **Commit changes**: Follow commit message guidelines
8. **Push to fork**: `git push origin feature/my-feature`
9. **Create PR**: Open a pull request to the main repository
10. **Address feedback**: Make requested changes
11. **Get merged**: Once approved, your PR will be merged!

### Keeping Your Fork Updated

```bash
# Fetch upstream changes
git fetch upstream

# Merge upstream main into your branch
git checkout main
git merge upstream/main

# Update your fork on GitHub
git push origin main
```

## Additional Resources

- [Go Documentation](https://golang.org/doc/)
- [Effective Go](https://golang.org/doc/effective_go.html)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Nmap Documentation](https://nmap.org/book/man.html)

## Questions?

If you have questions:

1. Check existing issues and discussions
2. Read the documentation
3. Open a new discussion or issue
4. Join community channels (if available)

---

Thank you for contributing to AutoSecScan! Your efforts help make the web more secure. 🔒
