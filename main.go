package main

import (
	"context"
	"encoding/json"
	"fmt"
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
		return false, "path contains directory traversal patterns"
	}
	
	// Check if the path exists
	if _, err := os.Stat(cleanPath); os.IsNotExist(err) {
		return false, fmt.Sprintf("file does not exist at path: %s", cleanPath)
	}
	
	return true, ""
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
		mcp.WithDescription("Analyze code for potential security issues"),
		mcp.WithString("file_path",
			mcp.Required(),
			mcp.Description("Path to the file to analyze"),
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
	filePath, ok := request.Params.Arguments["file_path"].(string)
	if !ok {
		return nil, fmt.Errorf("file_path must be a string")
	}
	
	log.Printf("Original file path: %s\n", filePath)
	
	// If filePath is not absolute, make it relative to current directory
	if !filepath.IsAbs(filePath) {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("failed to get working directory: %v", err)
		}
		oldPath := filePath
		filePath = filepath.Join(cwd, filePath)
		log.Printf("Converting relative path %s to absolute path: %s (cwd: %s)\n", oldPath, filePath, cwd)
	}
	
	// Clean and evaluate the path
	cleanPath := filepath.Clean(filePath)
	log.Printf("Cleaned path: %s\n", cleanPath)
	
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		log.Printf("Error getting absolute path: %v\n", err)
	} else {
		log.Printf("Absolute path: %s\n", absPath)
	}
	
	// Path safety check
	if safe, reason := isSafePath(filePath); !safe {
		log.Printf("Path safety check failed: %s\n", reason)
		return nil, fmt.Errorf("unsafe file path: %s", reason)
	}

	// Read the file
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	// Basic security analysis using the file content
	result := fmt.Sprintf("Security analysis for %s:\n", filePath)
	result += "1. Basic file analysis completed\n"
	result += fmt.Sprintf("2. File size: %d bytes\n", len(content))
	
	// Additional security checks
	contentStr := string(content)
	result += "3. Security checks:\n"
	
	// Check for potential security issues
	checks := map[string]func(string) bool{
		"Hardcoded credentials": func(s string) bool {
			return regexp.MustCompile(`(?i)(password|secret|key|token).*=.*['"]\w+['"]`).MatchString(s)
		},
		"SQL injection risk": func(s string) bool {
			return regexp.MustCompile(`(?i)(select|insert|update|delete).*\+.*\+`).MatchString(s)
		},
		"Insecure HTTP": func(s string) bool {
			return strings.Contains(s, "http://") && !strings.Contains(s, "http://localhost")
		},
		"File system operations": func(s string) bool {
			return regexp.MustCompile(`os\.(Open|Create|Remove|Chmod)`).MatchString(s)
		},
		"Command execution": func(s string) bool {
			return regexp.MustCompile(`exec\.(Command|CommandContext)`).MatchString(s)
		},
	}

	for checkName, checkFunc := range checks {
		if checkFunc(contentStr) {
			result += fmt.Sprintf("   ⚠️ %s detected\n", checkName)
		}
	}

	result += "4. Recommendations:\n"
	result += "   - Implement input validation\n"
	result += "   - Use parameterized queries\n"
	result += "   - Implement proper error handling\n"
	result += "   - Use secure configuration management\n"
	result += "   - Implement access control checks\n"
	result += "   - Use HTTPS for external communications\n"

	log.Printf("Completed security analysis for %s\n", filePath)
	return mcp.NewToolResultText(result), nil
} 