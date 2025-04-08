.PHONY: all clean install deps build run configure

# Variables
BINARY_NAME=mcp-osv
INSTALL_DIR=/usr/local/bin
CURSOR_MCP_DIR=$(HOME)/.cursor
GO=$(shell which go)

all: deps build configure

deps:
	@echo "Installing dependencies..."
	$(GO) get github.com/mark3labs/mcp-go/mcp@v0.18.0
	$(GO) get github.com/mark3labs/mcp-go/server@v0.18.0
	$(GO) get github.com/yosida95/uritemplate/v3
	$(GO) get github.com/google/uuid
	$(GO) mod tidy

build:
	@echo "Building binary..."
	$(GO) build -o $(BINARY_NAME) main.go

install: build
	@echo "Installing binary..."
	@mkdir -p $(INSTALL_DIR)
	cp $(BINARY_NAME) $(INSTALL_DIR)/

configure:
	@echo "Configuring MCP server..."
	@mkdir -p $(CURSOR_MCP_DIR)
	@echo '{"mcpServers":{"security_analyst":{"name":"Security Analyst","type":"stdio","command":"$(INSTALL_DIR)/$(BINARY_NAME)"}}}' > $(CURSOR_MCP_DIR)/mcp.json
	@echo "MCP configuration created at $(CURSOR_MCP_DIR)/mcp.json"

run: build
	@echo "Running server..."
	./$(BINARY_NAME)

clean:
	@echo "Cleaning up..."
	rm -f $(BINARY_NAME)
	rm -f $(INSTALL_DIR)/$(BINARY_NAME) 