package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
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

// SemgrepResult represents the JSON output from semgrep
type SemgrepResult struct {
	Results []struct {
		CheckID  string `json:"check_id"`
		Path     string `json:"path"`
		Start    struct {
			Line int `json:"line"`
		} `json:"start"`
		End struct {
			Line int `json:"line"`
		} `json:"end"`
		Extra struct {
			Message  string `json:"message"`
			Severity string `json:"severity"`
		} `json:"extra"`
	} `json:"results"`
}

var semgrepAvailable bool

func init() {
	// Check if semgrep is available
	_, err := exec.LookPath("semgrep")
	semgrepAvailable = err == nil
	if !semgrepAvailable {
		log.Println("Semgrep not found in PATH. Static code analysis will be limited.")
	}
}

func runSemgrep(path string) (string, error) {
	if !semgrepAvailable {
		return "\n=== Semgrep Analysis ===\n⚠️  Semgrep not installed. Static code analysis skipped.\nInstall Semgrep for enhanced security analysis.\n", nil
	}

	var result strings.Builder
	result.WriteString("\n=== Semgrep Analysis ===\n")

	cmd := exec.Command("semgrep", 
		"--config=auto",
		"--json",
		"--severity=WARNING",
		"--quiet",
		path)
	
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && len(exitErr.Stderr) > 0 {
			return "", fmt.Errorf("semgrep error: %s", exitErr.Stderr)
		}
		return "", fmt.Errorf("failed to run semgrep: %v", err)
	}

	var semgrepResult SemgrepResult
	if err := json.Unmarshal(output, &semgrepResult); err != nil {
		return "", fmt.Errorf("failed to parse semgrep output: %v", err)
	}

	// Add information about what was scanned
	result.WriteString("Running Semgrep security analysis...\n")
	
	if len(semgrepResult.Results) == 0 {
		result.WriteString("✅ No security issues found by Semgrep\n")
		return result.String(), nil
	}

	result.WriteString(fmt.Sprintf("Found %d potential security issues:\n\n", len(semgrepResult.Results)))
	for _, finding := range semgrepResult.Results {
		result.WriteString(fmt.Sprintf("⚠️  %s\n", finding.CheckID))
		result.WriteString(fmt.Sprintf("   Severity: %s\n", finding.Extra.Severity))
		result.WriteString(fmt.Sprintf("   File: %s (lines %d-%d)\n", finding.Path, finding.Start.Line, finding.End.Line))
		result.WriteString(fmt.Sprintf("   Message: %s\n\n", finding.Extra.Message))
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read OSV response: %v", err)
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
		
		// Run Semgrep analysis for the directory
		semgrepResult, semgrepErr := runSemgrep(absPath)
		if semgrepErr != nil {
			result.WriteString(fmt.Sprintf("Error running Semgrep: %v\n", semgrepErr))
		} else {
			result.WriteString(semgrepResult)
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
		fileResult, err := analyzeFile(absPath)
		if err != nil {
			return nil, fmt.Errorf("error analyzing file: %v", err)
		}
		result.WriteString(fileResult)
	}

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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read OSV response: %v", err)
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