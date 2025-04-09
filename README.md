# MCP Security Analyst

A Model Context Protocol (MCP) server that provides security analysis capabilities by integrating with OSV.dev and AI models to help identify and analyze potential vulnerabilities in your codebase.

## Features

- Vulnerability checking using OSV.dev database
- Basic security analysis of code files
- Integration with AI models for security insights
- MCP protocol support for seamless integration with various AI tools

## Installation

```bash
make deps
make install
```

The mcp-osv command will be installed on PATH and use the stdin/stdout method.

Configure your LLM to use mcp-osv as an agent. 



1. The server provides the following tools:

### check_vulnerabilities

Check for known vulnerabilities in dependencies using OSV.dev database.

Parameters:

- `package_name`: Name of the package to check
- `version`: Version of the package to check

### analyze_security

Analyze code for potential security issues based on https://osv.dev - a comprehensive database of open-source vulnerabilities. 

Parameters:

- `file_path`: Path to the file to analyze

## Integration with AI Models

This server is designed to work with AI models like Claude and Cursor through the MCP protocol. The AI models can use the provided tools to:

1. Check dependencies for known vulnerabilities
2. Analyze code for security issues
3. Provide recommendations for security improvements

## Connecting with Cursor

### Sample output
![output-1](screenshots/mcp-output-1.png)
![output-2](screenshots/mcp-output-2.png)
![output-3](screenshots/mcp-output-3.png)

### Usage

See mcp.json-template for an example that works with Cursor IDE.

After the setup, restart and ask something like "Analyze the security of my project using mcp-osv". 

To Debug in VSCode go to Help -> Toggle developer tools and at the console look for mcp.

To test the security analysis capabilities:
   

```bash
# Check for vulnerabilities in a package
"Check for vulnerabilities in the package 'express' version '4.17.1'"

# Analyze a specific file
"Analyze the security of the file 'main.go'"
```

The server will process your requests and provide security insights through the MCP protocol.


## Connect to Claude

Edit the config file and add the following section (that's the whole file, consider the mcp_osv section if you already have other tools installed.)

```json
{
    "mcpServers": {
        "mcp_osv": {
            "command": "/usr/local/bin/mcp-osv",
            "args": []
        }
    }
}
````

## Development

To add new security analysis capabilities:

1. Create a new tool using `mcp.NewTool`
2. Implement the tool handler
3. Add the tool to the server using `s.AddTool`
4. check <https://github.com/mark3labs/mcp-go> for a comprehensive framework to build MCPs in Go.

## License

MIT 