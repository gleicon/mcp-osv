# MCP Security Analyst

[![Go](https://github.com/gleicon/mcp-osv/actions/workflows/go.yml/badge.svg)](https://github.com/gleicon/mcp-osv/actions/workflows/go.yml)

A Model Context Protocol (MCP) server providing comprehensive security analysis capabilities through integration with OSV.dev vulnerability database and native Go-based code analysis and secret detection engines.

## Features

-- **Supply Chain Vulnerability Analysis**: Integration with OSV.dev API for dependency vulnerability assessment
-- **Secret Detection**: Gitleaks v8 integration with 100+ built-in detection rules for credentials and API keys
-- **Static Code Analysis**: AST-based Go code analysis for security anti-patterns
-- **Pattern Matching**: Regex-based detection for common security vulnerabilities
-- **MCP Protocol Support**: Standard protocol implementation for AI assistant integration
-- **Community-Vetted Rules**: Gitleaks patterns maintained by the security community

## Requirements

### Core Requirements
```bash
make deps
make install
```

### Build Dependencies
-- Go 1.25.4 or later
-- github.com/mark3labs/mcp-go 
-- github.com/zricethezav/gitleaks/v8 

## Installation

```bash
make deps     # Install Go module dependencies
make build    # Compile binary
make install  # Install to /usr/local/bin
make run       # Build and execute server
make clean     # Remove build artifacts
```

The mcp-osv binary communicates via stdin/stdout using the MCP protocol.

### IDE Configuration

#### Cursor IDE

Navigate to Configuration > MCP and add:

```json
{
  "mcpServers": {
    "security_analyst": {
      "name": "Security Analyst",
      "type": "stdio",
      "command": "/usr/local/bin/mcp-osv"
    }
  }
}
```

#### Claude Desktop

Edit the MCP configuration file at Settings > Developer:

```json
{
  "mcpServers": {
    "mcp_osv": {
      "command": "/usr/local/bin/mcp-osv",
      "args": []
    }
  }
}
```

## Available Tools

The server exposes three MCP tools for security analysis:

### check_vulnerabilities

Query OSV.dev database for known vulnerabilities in specific package versions.

**Parameters:**
-- `package_name` (string, required): Package identifier
-- `version` (string, required): Version string

**Functionality:**
-- Rate-limited API requests (1 request/second)
-- HTTP timeout protection (10 seconds)
-- JSON response parsing
-- Vulnerability detail extraction

### analyze_security

Comprehensive security analysis combining multiple detection engines.

**Parameters:**
-- `file_path` (string, required): Target file or directory path

**Analysis Components:**
-- Native Go AST-based code analysis
-- Gitleaks v8 secret detection with 100+ rules
-- OSV.dev vulnerability checks for dependencies (go.mod files)
-- Pattern-based vulnerability detection

**Detected Issues:**
-- Command injection vectors
-- Deserialization vulnerabilities
-- SQL injection patterns
-- Hardcoded credentials
-- API keys and tokens
-- Private keys and certificates
-- Database connection strings

### scan_secrets

Dedicated secret detection using Gitleaks v8 with 100+ community-maintained detection rules.

**Parameters:**
-- `path` (string, required): Target file, directory, or repository path
-- `scan_git_history` (boolean, optional): Enable git history scanning (default: false)

**Detection Capabilities (100+ patterns):**
-- AWS Access Keys, Secret Keys, Session Tokens
-- GitHub Personal Access Tokens, OAuth tokens
-- Google Cloud Platform API keys
-- Azure credentials and connection strings
-- Slack tokens and webhooks
-- Stripe API keys
-- Private SSH/PGP/RSA keys
-- JWT tokens
-- Database connection strings (PostgreSQL, MySQL, MongoDB)
-- Generic API keys with entropy analysis
-- And 90+ more patterns maintained by the security community

**Output:** Partial secret redaction for secure display (first 4 + last 4 characters)

## Integration Patterns

The MCP server enables AI assistants to perform security analysis through natural language requests:

**Dependency Vulnerability Scanning:**
```
Request: "Check dependencies in go.mod for vulnerabilities"
Tool Execution: analyze_security -> OSV.dev API queries
Response: Vulnerability report with CVE details
```

**Secret Detection:**
```
Request: "Scan repository for exposed credentials"
Tool Execution: scan_secrets -> Pattern matching + entropy analysis
Response: Detected secrets with file locations and types
```

**Comprehensive Audit:**
```
Request: "Perform full security analysis"
Tool Execution: analyze_security -> All detection engines
Response: Combined report (code issues + secrets + vulnerabilities)
```

## Security Implementation Details

### Rate Limiting
OSV.dev API requests are rate-limited at 1 request per second using golang.org/x/time/rate limiter to prevent service throttling.

### Input Validation
All file paths undergo sanitization to prevent directory traversal attacks:
-- Path cleaning via filepath.Clean()
-- Directory traversal pattern detection
-- Existence verification

### Secret Redaction
Detected secrets are partially redacted before display:
-- Secrets <= 8 characters: Full redaction
-- Secrets > 8 characters: First 4 + "***" + Last 4 characters

### Gitleaks Integration
Secret detection powered by Gitleaks v8:
-- 100+ community-maintained detection rules
-- Entropy analysis for high-randomness strings
-- Keyword-based pre-filtering for performance
-- Regular updates for new secret types

### Adding Security Rules

To extend detection capabilities:

1. **Secrets and credential detection**: Gitleaks rules are maintained upstream at [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml)
2. **Code Analysis**: Extend AST inspection in `runGoCodeAnalysis()`
3. **Pattern Matching**: Regex patterns can be added to `analyzeFile()` checks map, create a branch and PR explaining them to get merged

## License

MIT

