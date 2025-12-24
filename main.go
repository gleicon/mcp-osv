package main

import (
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
	"golang.org/x/time/rate"
)

// OSVResponse represents the response from OSV.dev API
type OSVResponse struct {
	Vulns []struct {
		ID      string `json:"id"`
		Summary string `json:"summary"`
		Details string `json:"details"`
		Affected []struct {
			Package struct {
				Name string `json:"name"`
			} `json:"package"`
		} `json:"affected"`
	} `json:"vulns"`
}

// RateLimiter implements a simple rate limiter for API calls
type RateLimiter struct {
	limiter *rate.Limiter
	mu      sync.Mutex
}

func NewRateLimiter(rps float64) *RateLimiter {
	return &RateLimiter{
		limiter: rate.NewLimiter(rate.Limit(rps), 1),
	}
}

func (r *RateLimiter) Wait(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.limiter.Wait(ctx)
}

// Global rate limiter for OSV API calls (1 request per second)
var osvRateLimiter = NewRateLimiter(1)

// HTTP client with timeout
var httpClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  true,
		TLSHandshakeTimeout: 5 * time.Second,
	},
}

// Input validation functions
func isValidPackageName(name string) bool {
	return regexp.MustCompile(`^[a-zA-Z0-9\-\./]+$`).MatchString(name)
}

func isValidVersion(version string) bool {
	return regexp.MustCompile(`^[a-zA-Z0-9\-\./]+$`).MatchString(version)
}

func isSafePath(path string) (bool, string) {
	// Clean the path
	cleanPath := filepath.Clean(path)
	
	// Check for path traversal attempts
	if strings.Contains(cleanPath, "..") {
		return false, "path contains directory traversal patterns - .."
	}
	// Check for path traversal attempts
	if strings.HasPrefix(cleanPath, ".") {
		return false, "path contains directory traversal patterns - ."
	}
	// Check if the path exists
	_, err := os.Stat(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, fmt.Sprintf("path does not exist: %s", cleanPath)
		}
		return false, fmt.Sprintf("error accessing path: %v", err)
	}

	// Path exists and is accessible
	return true, ""
}

func init() {
	log.Println("Initialized native Go code analysis engine")
	log.Println("Initialized Gitleaks v8 secret detection engine")
}

func runGoCodeAnalysis(path string) (string, error) {
	var result strings.Builder
	result.WriteString("\n-- Static Code Analysis --\n")

	fileInfo, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("failed to stat path: %v", err)
	}

	var filesToAnalyze []string
	if fileInfo.IsDir() {
		err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() && strings.HasSuffix(filePath, ".go") {
				filesToAnalyze = append(filesToAnalyze, filePath)
			}
			return nil
		})
		if err != nil {
			return "", fmt.Errorf("failed to walk directory: %v", err)
		}
	} else if strings.HasSuffix(path, ".go") {
		filesToAnalyze = append(filesToAnalyze, path)
	}

	if len(filesToAnalyze) == 0 {
		result.WriteString("No Go files found for analysis\n")
		return result.String(), nil
	}

	issuesFound := 0
	fset := token.NewFileSet()

	for _, filePath := range filesToAnalyze {
		node, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)
		if err != nil {
			log.Printf("Warning: failed to parse %s: %v", filePath, err)
			continue
		}

		// Analyze for common security issues
		ast.Inspect(node, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
					funcName := sel.Sel.Name

					// Check for unsafe functions
					if funcName == "Command" || funcName == "CommandContext" {
						issuesFound++
						pos := fset.Position(x.Pos())
						result.WriteString(fmt.Sprintf("\nIssue found at %s:%d:\n", filepath.Base(filePath), pos.Line))
						result.WriteString("  Type: Command Execution\n")
						result.WriteString("  Risk: Potential command injection if user input is not validated\n")
						result.WriteString("  Recommendation: Validate and sanitize all inputs to exec functions\n")
					}

					if funcName == "Unmarshal" || funcName == "Decode" {
						issuesFound++
						pos := fset.Position(x.Pos())
						result.WriteString(fmt.Sprintf("\nIssue found at %s:%d:\n", filepath.Base(filePath), pos.Line))
						result.WriteString("  Type: Deserialization\n")
						result.WriteString("  Risk: Ensure input validation before deserializing untrusted data\n")
						result.WriteString("  Recommendation: Implement schema validation\n")
					}
				}
			case *ast.BasicLit:
				if x.Kind == token.STRING {
					value := strings.Trim(x.Value, "\"'`")
					// Check for SQL patterns
					if strings.Contains(strings.ToUpper(value), "SELECT") ||
					   strings.Contains(strings.ToUpper(value), "INSERT") ||
					   strings.Contains(strings.ToUpper(value), "UPDATE") ||
					   strings.Contains(strings.ToUpper(value), "DELETE") {
						issuesFound++
						pos := fset.Position(x.Pos())
						result.WriteString(fmt.Sprintf("\nIssue found at %s:%d:\n", filepath.Base(filePath), pos.Line))
						result.WriteString("  Type: SQL Query\n")
						result.WriteString("  Risk: Potential SQL injection if using string concatenation\n")
						result.WriteString("  Recommendation: Use parameterized queries\n")
					}
				}
			}
			return true
		})
	}

	if issuesFound == 0 {
		result.WriteString("No security issues detected in Go code\n")
	} else {
		result.WriteString(fmt.Sprintf("\nTotal: %d potential security issue(s) found\n", issuesFound))
	}

	return result.String(), nil
}

// redactSecret partially redacts a secret for safe display
func redactSecret(secret string) string {
	if len(secret) <= 8 {
		return "***REDACTED***"
	}
	return secret[:4] + "***" + secret[len(secret)-4:]
}

func runSecretDetection(path string, scanGitHistory bool) (string, error) {
	var result strings.Builder
	result.WriteString("\n-- Secret Detection (Gitleaks) --\n")

	// Initialize gitleaks detector with default configuration (100+ built-in rules)
	detector, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return "", fmt.Errorf("failed to initialize gitleaks detector: %v", err)
	}

	fileInfo, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("failed to stat path: %v", err)
	}

	var filesToScan []string
	if fileInfo.IsDir() {
		err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() && isAnalyzableFile(filePath) {
				filesToScan = append(filesToScan, filePath)
			}
			return nil
		})
		if err != nil {
			return "", fmt.Errorf("failed to walk directory: %v", err)
		}
	} else if isAnalyzableFile(path) {
		filesToScan = append(filesToScan, path)
	}

	// Scan each file with gitleaks
	var allFindings []report.Finding
	for _, filePath := range filesToScan {
		content, err := os.ReadFile(filePath)
		if err != nil {
			log.Printf("Warning: failed to read %s: %v", filePath, err)
			continue
		}

		// Create a fragment for gitleaks to scan
		fragment := detect.Fragment{
			Raw:      string(content),
			FilePath: filePath,
		}

		// Detect secrets using gitleaks
		findings := detector.Detect(fragment)
		allFindings = append(allFindings, findings...)
	}

	if len(allFindings) == 0 {
		result.WriteString("No secrets detected\n")
		return result.String(), nil
	}

	// Format findings
	result.WriteString(fmt.Sprintf("ALERT: Found %d potential secret(s)\n\n", len(allFindings)))

	for i, finding := range allFindings {
		result.WriteString(fmt.Sprintf("Secret %d:\n", i+1))
		result.WriteString(fmt.Sprintf("  Type: %s\n", finding.RuleID))
		result.WriteString(fmt.Sprintf("  Description: %s\n", finding.Description))
		result.WriteString(fmt.Sprintf("  File: %s (line %d)\n", finding.File, finding.StartLine))
		result.WriteString(fmt.Sprintf("  Secret: %s\n", redactSecret(finding.Secret)))
		if finding.Entropy != 0 {
			result.WriteString(fmt.Sprintf("  Entropy: %.2f\n", finding.Entropy))
		}
		if finding.Match != "" && finding.Match != finding.Secret {
			result.WriteString(fmt.Sprintf("  Match: %s\n", finding.Match))
		}
		result.WriteString("\n")
	}

	result.WriteString("CRITICAL: Review and rotate any exposed secrets immediately\n")

	if scanGitHistory {
		result.WriteString("Note: Git history scanning requires repository context (not yet implemented)\n")
	}

	return result.String(), nil
}

func main() {
	// Configure logging
	log.SetFlags(log.Ldate | log.Ltime | log.LUTC | log.Lshortfile)
	log.Println("Starting MCP Security Analyst server...")
	
	// Create MCP server
	s := server.NewMCPServer(
		"Security Analyst MCP",
		"1.0.0",
	)

	log.Println("Server created, adding tools...")

	// Add OSV vulnerability check tool
	osvTool := mcp.NewTool("check_vulnerabilities",
		mcp.WithDescription("Check for known vulnerabilities in dependencies"),
		mcp.WithString("package_name",
			mcp.Required(),
			mcp.Description("Name of the package to check"),
		),
		mcp.WithString("version",
			mcp.Required(),
			mcp.Description("Version of the package to check"),
		),
	)

	s.AddTool(osvTool, checkVulnerabilitiesHandler)
	log.Println("Added check_vulnerabilities tool")

	// Add security analysis tool
	analysisTool := mcp.NewTool("analyze_security",
		mcp.WithDescription("Analyze code for potential security issues in files or directories"),
		mcp.WithString("file_path",
			mcp.Required(),
			mcp.Description("Path to the file or directory to analyze"),
		),
	)

	s.AddTool(analysisTool, analyzeSecurityHandler)
	log.Println("Added analyze_security tool")

	// Add secret scanning tool
	secretsTool := mcp.NewTool("scan_secrets",
		mcp.WithDescription("Scan for hardcoded secrets, credentials, API keys, and sensitive data using Gitleaks v8 with 100+ built-in detection rules"),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Path to the file, directory, or git repository to scan for secrets"),
		),
		mcp.WithBoolean("scan_git_history",
			mcp.Description("Scan git commit history for secrets (slower but more thorough). Default: false"),
		),
	)

	s.AddTool(secretsTool, scanSecretsHandler)
	log.Println("Added scan_secrets tool")

	log.Println("Starting stdio server...")
	// Start the stdio server
	if err := server.ServeStdio(s); err != nil {
		log.Printf("Server error: %v\n", err)
		os.Exit(1)
	}
}

func checkVulnerabilitiesHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	log.Printf("Received check_vulnerabilities request: %+v\n", request)
	
	// Input validation
	pkgName, ok := request.Params.Arguments["package_name"].(string)
	if !ok {
		return nil, fmt.Errorf("package_name must be a string")
	}
	if !isValidPackageName(pkgName) {
		return nil, fmt.Errorf("invalid package name format")
	}

	version, ok := request.Params.Arguments["version"].(string)
	if !ok {
		return nil, fmt.Errorf("version must be a string")
	}
	if !isValidVersion(version) {
		return nil, fmt.Errorf("invalid version format")
	}

	// Rate limiting
	if err := osvRateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limit exceeded: %v", err)
	}

	// Query OSV.dev API with sanitized inputs
	url := fmt.Sprintf("https://api.osv.dev/v1/query?package=%s&version=%s",
		strings.ReplaceAll(pkgName, " ", "+"),
		strings.ReplaceAll(version, " ", "+"))
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query OSV API: %v", err)
	}
	defer resp.Body.Close()

	// Validate HTTP response status
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API returned non-OK status: %d %s", resp.StatusCode, resp.Status)
	}

	// Validate Content-Type
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") && contentType != "" {
		return nil, fmt.Errorf("unexpected Content-Type from OSV API: %s", contentType)
	}

	// Read response with size limit (10MB max)
	const maxResponseSize = 10 * 1024 * 1024
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read OSV response: %v", err)
	}

	// Validate JSON structure before unmarshaling
	if !json.Valid(body) {
		return nil, fmt.Errorf("invalid JSON response from OSV API")
	}

	var osvResp OSVResponse
	if err := json.Unmarshal(body, &osvResp); err != nil {
		return nil, fmt.Errorf("failed to parse OSV response: %v", err)
	}

	// Format response
	var result string
	if len(osvResp.Vulns) == 0 {
		result = fmt.Sprintf("No known vulnerabilities found for %s@%s", pkgName, version)
	} else {
		result = fmt.Sprintf("Found %d vulnerabilities for %s@%s:\n", len(osvResp.Vulns), pkgName, version)
		for _, vuln := range osvResp.Vulns {
			result += fmt.Sprintf("- %s: %s\n", vuln.ID, vuln.Summary)
			if vuln.Details != "" {
				result += fmt.Sprintf("  Details: %s\n", vuln.Details)
			}
		}
	}

	log.Printf("Completed vulnerability check for %s@%s\n", pkgName, version)
	return mcp.NewToolResultText(result), nil
}

func analyzeSecurityHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	log.Printf("Received analyze_security request: %+v\n", request)
	
	// Input validation
	path, ok := request.Params.Arguments["file_path"].(string)
	if !ok {
		return nil, fmt.Errorf("file_path must be a string")
	}
	
	// Clean and evaluate the path
	cleanPath := filepath.Clean(path)
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %v", err)
	}
	
	// Check if path exists and get info
	fileInfo, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("path does not exist: %s", absPath)
		}
		return nil, fmt.Errorf("error accessing path: %v", err)
	}

	// Path safety check
	if strings.Contains(absPath, "..") {
		return nil, fmt.Errorf("unsafe path: contains directory traversal patterns")
	}

	var result strings.Builder
	if fileInfo.IsDir() {
		// Handle directory
		result.WriteString(fmt.Sprintf("Security analysis for directory: %s\n\n", absPath))
		
		// Run native Go code analysis for the directory
		codeAnalysisResult, codeAnalysisErr := runGoCodeAnalysis(absPath)
		if codeAnalysisErr != nil {
			result.WriteString(fmt.Sprintf("Error running code analysis: %v\n", codeAnalysisErr))
		} else {
			result.WriteString(codeAnalysisResult)
		}

		// Run native secret detection scan for the directory
		secretResult, secretErr := runSecretDetection(absPath, false)
		if secretErr != nil {
			result.WriteString(fmt.Sprintf("Error running secret detection: %v\n", secretErr))
		} else {
			result.WriteString(secretResult)
		}

		// Walk through the directory
		err := filepath.Walk(absPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				result.WriteString(fmt.Sprintf("Error accessing %s: %v\n", path, err))
				return nil // Continue walking
			}

			// Skip directories themselves
			if info.IsDir() {
				return nil
			}

			// Skip non-analyzable files
			if !isAnalyzableFile(path) {
				return nil
			}

			// Analyze each file
			fileResult, err := analyzeFile(path)
			if err != nil {
				result.WriteString(fmt.Sprintf("Error analyzing %s: %v\n", path, err))
				return nil // Continue walking
			}

			result.WriteString(fmt.Sprintf("\n=== %s ===\n", path))
			result.WriteString(fileResult)
			result.WriteString("\n")

			return nil
		})

		if err != nil {
			return nil, fmt.Errorf("error walking directory: %v", err)
		}
	} else {
		// Handle single file
		result.WriteString(fmt.Sprintf("Security analysis for file: %s\n\n", absPath))

		// Run native secret detection on the file
		secretResult, secretErr := runSecretDetection(absPath, false)
		if secretErr != nil {
			result.WriteString(fmt.Sprintf("Error running secret detection: %v\n", secretErr))
		} else {
			result.WriteString(secretResult)
		}

		// Run pattern-based analysis
		fileResult, err := analyzeFile(absPath)
		if err != nil {
			return nil, fmt.Errorf("error analyzing file: %v", err)
		}
		result.WriteString("\n=== Pattern-based Analysis ===\n")
		result.WriteString(fileResult)
	}

	return mcp.NewToolResultText(result.String()), nil
}

func scanSecretsHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	log.Printf("Received scan_secrets request: %+v\n", request)

	// Input validation
	path, ok := request.Params.Arguments["path"].(string)
	if !ok {
		return nil, fmt.Errorf("path must be a string")
	}

	// Clean and evaluate the path
	cleanPath := filepath.Clean(path)
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %v", err)
	}

	// Check if path exists and get info
	fileInfo, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("path does not exist: %s", absPath)
		}
		return nil, fmt.Errorf("error accessing path: %v", err)
	}

	// Path safety check
	if strings.Contains(absPath, "..") {
		return nil, fmt.Errorf("unsafe path: contains directory traversal patterns")
	}

	// Parse optional scan_git_history parameter (default: false)
	scanGitHistory := false
	if scanHistoryVal, ok := request.Params.Arguments["scan_git_history"]; ok {
		if scanHistoryBool, ok := scanHistoryVal.(bool); ok {
			scanGitHistory = scanHistoryBool
		}
	}

	var result strings.Builder

	if fileInfo.IsDir() {
		result.WriteString(fmt.Sprintf("Secret scan for directory: %s\n", absPath))
	} else {
		result.WriteString(fmt.Sprintf("Secret scan for file: %s\n", absPath))
	}

	// Run native secret detection
	secretResult, err := runSecretDetection(absPath, scanGitHistory)
	if err != nil {
		return nil, fmt.Errorf("error running secret detection: %v", err)
	}

	result.WriteString(secretResult)

	log.Printf("Completed secret scan for %s\n", absPath)
	return mcp.NewToolResultText(result.String()), nil
}

func analyzeFile(filePath string) (string, error) {
	var result strings.Builder
	result.WriteString(fmt.Sprintf("File: %s\n", filePath))

	// Read the file
	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %v", err)
	}

	contentStr := string(content)
	
	// Check for potential security issues
	checks := map[string]struct {
		pattern string
		desc    string
	}{
		"Hardcoded credentials": {
			pattern: `(?i)(password|secret|key|token|auth).*[=:]\s*['"][^'"]+['"]`,
			desc:    "Potential hardcoded credentials found",
		},
		"SQL injection risk": {
			pattern: `(?i)(db\.Query|db\.Exec|sql\.Open)\s*\(\s*([^,]+\+|fmt\.Sprintf).*?(SELECT|INSERT|UPDATE|DELETE)`,
			desc:    "Possible SQL injection risk - using string concatenation or formatting in database query",
		},
		"Insecure HTTP": {
			pattern: `http://[^/]*\.[^/]*`,
			desc:    "Insecure HTTP URL found (not HTTPS)",
		},
		"Command execution": {
			pattern: `exec\.(Command|CommandContext)`,
			desc:    "Command execution detected - validate inputs carefully",
		},
		"Hardcoded IPs": {
			pattern: `\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`,
			desc:    "Hardcoded IP address found - consider configuration",
		},
	}

	foundIssues := false
	for checkName, check := range checks {
		if matched, err := regexp.MatchString(check.pattern, contentStr); err == nil && matched {
			result.WriteString(fmt.Sprintf("⚠️  %s\n   %s\n", checkName, check.desc))
			foundIssues = true
		}
	}

	// File-specific checks
	switch filepath.Base(filePath) {
	case "go.mod":
		// Check dependencies in go.mod
		deps, err := parseGoMod(contentStr)
		if err != nil {
			result.WriteString(fmt.Sprintf("Error parsing go.mod: %v\n", err))
		} else {
			result.WriteString("\nDependency analysis:\n")
			for _, dep := range deps {
				// Check each dependency with OSV
				vulns, err := checkOSVVulnerabilities(context.Background(), dep.name, dep.version)
				if err != nil {
					result.WriteString(fmt.Sprintf("Error checking %s@%s: %v\n", dep.name, dep.version, err))
					continue
				}
				if len(vulns) > 0 {
					result.WriteString(fmt.Sprintf("⚠️  %s@%s has %d known vulnerabilities:\n", dep.name, dep.version, len(vulns)))
					for _, vuln := range vulns {
						result.WriteString(fmt.Sprintf("   - %s: %s\n", vuln.ID, vuln.Summary))
					}
					foundIssues = true
				}
			}
		}
	}

	if !foundIssues {
		result.WriteString("✅ No immediate security concerns found\n")
	}

	return result.String(), nil
}

type dependency struct {
	name    string
	version string
}

func parseGoMod(content string) ([]dependency, error) {
	var deps []dependency
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "require ") || (len(line) > 0 && line[0] != ' ' && strings.Contains(line, " v")) {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				deps = append(deps, dependency{
					name:    parts[0],
					version: parts[1],
				})
			}
		}
	}
	return deps, nil
}

func checkOSVVulnerabilities(ctx context.Context, pkgName, version string) ([]struct{ID, Summary string}, error) {
	// Rate limiting
	if err := osvRateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limit exceeded: %v", err)
	}

	// Query OSV.dev API
	url := fmt.Sprintf("https://api.osv.dev/v1/query?package=%s&version=%s",
		strings.ReplaceAll(pkgName, " ", "+"),
		strings.ReplaceAll(version, " ", "+"))
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query OSV API: %v", err)
	}
	defer resp.Body.Close()

	// Validate HTTP response status
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API returned non-OK status: %d %s", resp.StatusCode, resp.Status)
	}

	// Validate Content-Type
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") && contentType != "" {
		return nil, fmt.Errorf("unexpected Content-Type from OSV API: %s", contentType)
	}

	// Read response with size limit (10MB max)
	const maxResponseSize = 10 * 1024 * 1024
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read OSV response: %v", err)
	}

	// Validate JSON structure before unmarshaling
	if !json.Valid(body) {
		return nil, fmt.Errorf("invalid JSON response from OSV API")
	}

	var osvResp OSVResponse
	if err := json.Unmarshal(body, &osvResp); err != nil {
		return nil, fmt.Errorf("failed to parse OSV response: %v", err)
	}

	var vulns []struct{ID, Summary string}
	for _, v := range osvResp.Vulns {
		vulns = append(vulns, struct{ID, Summary string}{
			ID:      v.ID,
			Summary: v.Summary,
		})
	}
	return vulns, nil
}

func isAnalyzableFile(path string) bool {
	// List of file extensions to analyze
	analyzableExts := map[string]bool{
		".go":     true,
		".mod":    true,
		".sum":    true,
		".json":   true,
		".yaml":   true,
		".yml":    true,
		".toml":   true,
		".env":    true,
	}

	ext := strings.ToLower(filepath.Ext(path))
	base := filepath.Base(path)
	
	// Special files
	if base == "go.mod" || base == "go.sum" {
		return true
	}
	
	return analyzableExts[ext]
} 