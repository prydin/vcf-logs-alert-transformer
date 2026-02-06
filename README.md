# Alert Transformer

A high-performance FastAPI-based web service that receives alerts from VMware vRealize Log Insight / VMware Aria Operations for Logs (VCF Operations for Logs) and transforms them according to configurable rules before forwarding to target systems.

## Overview

The Alert Transformer runs as a webserver that:

- **Receives alerts** from VCF Operations for Logs via HTTP webhook
- **Transforms alerts** according to pattern-matching rules defined in a YAML configuration file
- **Forwards transformed alerts** to target systems via HTTP/HTTPS
- **Ensures reliability** by storing failed messages to disk and automatically retrying when target systems become available

Built on FastAPI for speed and scalability, the tool is designed for production environments requiring high throughput and resilience.

### Project Files

- **`alert-transformer.py`** - Main application
- **`dummy-server.py`** - Test server for receiving and displaying transformed alerts
- **`config.yaml`** - Configuration file with rules and targets
- **`test-e2e.sh`** - Automated end-to-end test script
- **`requirements.txt`** - Python package dependencies
- **`Dockerfile`** - Docker container configuration

## Features

- ✅ **Pattern-based routing**: Match alerts by name and/or message content using regular expressions
- ✅ **Template-based transformation**: Transform alert payloads using customizable JSON templates with field substitution and Python expressions
- ✅ **Expression evaluation**: Use Python expressions for complex data transformations (arithmetic, string operations, conditionals)
- ✅ **Multiple targets**: Route different alerts to different endpoints
- ✅ **Authentication support**: Basic authentication (extensible for other types)
- ✅ **Automatic retry**: Failed messages are queued to disk and retried automatically
- ✅ **Rate limiting handling**: Automatically backs off when encountering 429 responses
- ✅ **Fast & scalable**: Built on FastAPI and Uvicorn for high performance
- ✅ **Flexible logging**: Debug mode for development, minimal logging for production

## Installation

### Prerequisites

- Python 3.7+
- pip

### Install Dependencies

**Using requirements.txt (recommended):**

```bash
pip install -r requirements.txt
```

**Or install packages individually:**

```bash
pip install fastapi uvicorn pyyaml requests
```

**Using a virtual environment (recommended for development):**

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Command Line Usage

### Syntax

```bash
python alert-transformer.py [OPTIONS]
```

### Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--config` | `-c` | Path to the YAML configuration file | `config.yaml` |
| `--host` | | Host address to bind the server to | `0.0.0.0` |
| `--port` | `-p` | Port number to run the server on | `8080` |
| `--queue-dir` | `-q` | Directory for storing unsent messages for retry | `None` |
| `--verbose` | `-v` | Enable verbose debug logging | `False` |
| `--help` | `-h` | Show help message and exit | |

### Examples

**Basic usage with defaults:**
```bash
python alert-transformer.py
```

**Specify custom configuration file:**
```bash
python alert-transformer.py -c /path/to/my-config.yaml
```

**Run on a different port:**
```bash
python alert-transformer.py -p 9000
```

**Enable message queue for reliability:**
```bash
python alert-transformer.py -q /var/lib/alert-queue
```

**Enable verbose logging for debugging:**
```bash
python alert-transformer.py -v -q /tmp/alert-queue
```

**Production deployment example:**
```bash
python alert-transformer.py \
  -c /etc/alert-transformer/config.yaml \
  -p 8080 \
  -q /var/lib/alert-transformer/queue
```

## Configuration File

The configuration file (`config.yaml`) defines the rules for matching and transforming alerts, as well as the target systems to which transformed alerts should be sent.

### Configuration Structure

```yaml
rules:
  - name: <rule-name>
    namePattern: <regex>
    messagePattern: <regex>
    target: <target-name>
    template: <json-template>

targets:
  - name: <target-name>
    url: <endpoint-url>
    method: <http-method>
    authentication:
      type: <auth-type>
      user: <username>
      password: <password>
    headers:
      <header-name>: <header-value>
```

### Rules Section

Each rule defines how to match and transform incoming alerts.

#### Rule Properties

| Property | Required | Description |
|----------|----------|-------------|
| `name` | Yes | Descriptive name for the rule (used in logs) |
| `namePattern` | No | Regular expression to match the alert name. If omitted, all alert names match. |
| `messagePattern` | No | Regular expression to match the alert message text. If omitted, all messages match. |
| `target` | Yes | Name of the target (defined in `targets` section) where the transformed alert should be sent |
| `template` | Yes | JSON template for the output message with variable substitution |

#### Pattern Matching

Rules are evaluated in order. An alert matches a rule if:
- The alert name matches the `namePattern` (if specified)
- **AND** the message text matches the `messagePattern` (if specified)

Multiple rules can match the same alert, resulting in multiple transformed messages being sent to different targets.

#### Template Substitution

Templates support both simple variable substitution and Python expressions using the `${...}` syntax:

**Simple Variable Substitution:**

| Variable Format | Description | Example |
|----------------|-------------|---------|
| `${text}` | The original alert message text | `${text}` |
| `${extracted.field_name}` | Custom extracted field from the alert | `${extracted.hello_id}` |
| `${static.field_name}` | Static (built-in) field from the alert | `${static.__li_source_path}` |
| `${field_name}` | Top-level event field | `${alert_name}` |

**Python Expression Support:**

You can use Python expressions for complex transformations:

| Expression Example | Description |
|-------------------|-------------|
| `${int(static['count']) + 10}` | Arithmetic operations |
| `${static['first'] + '-' + static['last']}` | String concatenation |
| `${text.upper()}` | String methods |
| `${upper(text)}` | String to uppercase (function) |
| `${lower(static['name'])}` | String to lowercase (function) |
| `${len(text)}` | String length |
| `${max(int(static['a']), int(static['b']))}` | Math functions |
| `${static.get('value', 'default')}` | Dictionary operations with defaults |

**Available Functions in Expressions:**
- `len()`, `str()`, `int()`, `float()`, `bool()`
- `min()`, `max()`, `sum()`, `abs()`, `round()`
- `upper()`, `lower()` - Convert strings to uppercase or lowercase

**Example Template with Expressions:**
```yaml
template: |
  {
    "alert": "${text}",
    "severity": "${int(static.get('severity', '0')) > 5 and 'high' or 'low'}",
    "count": ${int(extracted.get('count', '1')) * 2},
    "message": "${text.upper()}",
    "length": ${len(text)}
  }
```

> **Note**: Expressions are evaluated safely using `simpleeval`, which prevents unsafe operations like file access or imports.

**Common Static Fields:**
- `${static.__li_source_path}` - Source path in Log Insight
- `${static.__li_agent_id}` - Agent ID
- `${static.hostname}` - Hostname
- `${static.vmw_datacenter}` - VMware datacenter name
- `${static.vmw_cluster}` - VMware cluster name

### Targets Section

Each target defines an HTTP endpoint where transformed alerts should be sent.

#### Target Properties

| Property | Required | Description |
|----------|----------|-------------|
| `name` | Yes | Unique identifier for the target (referenced by rules) |
| `url` | Yes | Full URL of the target endpoint |
| `method` | No | HTTP method to use (GET, POST, PUT, etc.) | Default: `POST` |
| `authentication` | No | Authentication configuration (see below) |
| `headers` | No | Additional HTTP headers to send with the request |

#### Authentication

Currently supports **Basic Authentication**:

```yaml
authentication:
  type: "Basic"
  user: "username"
  password: "password"
```

> **⚠️ Security Note**: In this pre-release version, passwords are stored in clear text in the configuration file. This is not suitable for production use. Proper secret management (using environment variables, secret vaults, or encrypted configuration) will be implemented in a future release.

Additional authentication types can be added as needed.

### Complete Example

```yaml
rules:
  # Rule 1: Match alerts with "hello" in name and "Hello" in message
  - name: "hello"
    namePattern: ".*hello.*"
    messagePattern: ".*Hello.*"
    target: "demo"
    template: |
      {
        "action": "create",
        "id": "${extracted.hello_id}",
        "message": "${text}",
        "attr1": "${static.__li_source_path}",
        "attr2": "${extracted.__li_agent_id}"
      }

  # Rule 2: Same alert name, but different message pattern and action
  - name: "goodbye"
    namePattern: ".*hello.*"
    messagePattern: ".*Goodbye.*"
    target: "demo"
    template: |
      {
        "action": "delete",
        "status": "success",
        "id": "${extracted.hello_id}",
        "message": "${text}"
      }

  # Rule 3: Match by exact alert name only
  - name: "new error"
    namePattern: "New Error before old is handled"
    target: "incident_system"
    template: |
      {
        "action": "new",
        "status": "error",
        "datacenter": "${static.vmw_datacenter}",
        "cluster": "${static.vmw_cluster}",
        "host": "${static.hostname}",
        "user": "${extracted.user}",
        "message": "${text}"
      }

targets:
  # Target 1: Demo endpoint with Basic auth
  - name: "demo"
    url: "http://localhost:8888/ingest"
    method: "POST"
    authentication:
      type: "Basic"
      user: "ingest_user"
      password: "ingest_password"
    headers:
      Content-Type: "application/json"

  # Target 2: Incident management system
  - name: "incident_system"
    url: "https://incidents.example.com/api/v1/alerts"
    method: "POST"
    headers:
      Content-Type: "application/json"
      X-API-Key: "your-api-key-here"
```

## How It Works

### Workflow

1. **Alert Reception**: VCF Operations for Logs sends an alert to the transformer via HTTP POST webhook
2. **Rule Matching**: The transformer evaluates each rule in order to find matches based on alert name and message patterns
3. **Template Processing**: For each matching rule, the transformer:
   - Extracts fields from the alert (static fields and extracted fields)
   - Performs variable substitution in the template
   - Generates the output message
4. **Message Delivery**: The transformed message is sent to the target endpoint
5. **Retry Logic** (if queue directory is configured):
   - If sending fails, the message is saved to disk with a timestamp
   - A background thread periodically retries sending queued messages
   - Successfully sent messages are removed from the queue

### Message Queue and Retry

When you specify a `--queue-dir`, the transformer becomes resilient to target system outages:

- **Failed messages** are written to `{queue_dir}/{target_name}_{timestamp}.msg`
- **Retry thread** runs every 10 seconds, processing messages in chronological order
- **Automatic cleanup** removes successfully sent messages from the queue
- **Survives restarts** - queued messages persist across transformer restarts

### Logging

The transformer provides two logging modes:

**Normal Mode** (default):
- Only logs warnings and errors
- Minimal output suitable for production
- Example: `python alert-transformer.py`

**Verbose Mode** (`-v` flag):
- Logs debug information including:
  - Template parsing and substitutions
  - Rule matching details
  - Message content
  - Retry attempts
- Useful for development and troubleshooting
- Example: `python alert-transformer.py -v`

## Testing

### Using the Dummy Test Server

The project includes `dummy-server.py`, a simple test server that receives and displays transformed alerts. **This is the recommended way to test your alert transformation rules before deploying to production.**

#### Quick Start with Test Script

The easiest way to test the complete workflow is using the included test script:

```bash
./test-e2e.sh
```

This script will:
1. Start the dummy server on port 8888
2. Start the alert transformer on port 8080
3. Send a test alert
4. Display the transformed output

Press CTRL+C to stop when done.

#### Starting the Dummy Server

**Basic usage (listens on port 8888):**
```bash
python dummy-server.py
```

**Custom host and port:**
```bash
python dummy-server.py --host 127.0.0.1 -p 9000
```

**Command-line options:**
| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--host` | | Host address to bind to | `0.0.0.0` |
| `--port` | `-p` | Port number | `8888` |

The dummy server will display all received alerts in a formatted, easy-to-read output with timestamps.

#### Testing Workflow

**1. Start the dummy server:**
```bash
python dummy-server.py
```

**2. Configure your target in `config.yaml` to point to the dummy server:**
```yaml
targets:
  - name: "test"
    url: "http://localhost:8888/ingest"
    method: "POST"
    headers:
      Content-Type: "application/json"
```

**3. Start the Alert Transformer in verbose mode:**
```bash
python main.py -v
```

**4. Send a test alert:**
```bash
curl -X POST http://localhost:8080/ \
  -H "Content-Type: application/json" \
  -d '{
    "alert_name": "test-hello-alert",
    "messages": "[{\"text\": \"Hello World\", \"staticFields\": [{\"name\": \"__li_source_path\", \"content\": \"/var/log/test\"}, {\"name\": \"hostname\", \"content\": \"server01\"}], \"extractedFields\": [{\"name\": \"hello_id\", \"content\": \"12345\"}, {\"name\": \"user\", \"content\": \"admin\"}]}]"
  }'
```

**5. Check the dummy server output** to see the transformed alert

**6. Review the transformer logs** (with `-v` flag) to see the matching and transformation process

### Example Test Output

When the dummy server receives an alert, it displays:

```
================================================================================
[2026-02-06 12:34:56] Received event:
================================================================================
{
  "action": "create",
  "id": "12345",
  "message": "Hello World",
  "attr1": "/var/log/test",
  "attr2": "agent-001"
}
================================================================================
```

### Testing Different Scenarios

**Test pattern matching:**
- Send alerts with different names and messages
- Verify only the expected rules match
- Check the verbose logs to see which patterns matched/didn't match

**Test template substitution:**
- Include various static and extracted fields
- Verify all variables are correctly substituted
- Test with missing fields to see default behavior

**Test error handling:**
- Stop the dummy server to test queue functionality
- Verify failed messages are saved to the queue directory
- Restart the dummy server and watch messages be retried

**Test authentication:**
```yaml
targets:
  - name: "test-auth"
    url: "http://localhost:8888/ingest"
    method: "POST"
    authentication:
      type: "Basic"
      user: "testuser"
      password: "testpass"
```

### Sample Test Alerts

**Alert with extracted fields:**
```bash
curl -X POST http://localhost:8080/ \
  -H "Content-Type: application/json" \
  -d '{
    "alert_name": "New Error before old is handled",
    "messages": "[{\"text\": \"Critical error detected\", \"staticFields\": [{\"name\": \"vmw_datacenter\", \"content\": \"DC-West\"}, {\"name\": \"vmw_cluster\", \"content\": \"Cluster-01\"}, {\"name\": \"hostname\", \"content\": \"esxi-host-01\"}], \"extractedFields\": [{\"name\": \"user\", \"content\": \"root\"}]}]"
  }'
```

**Alert with multiple messages:**
```bash
curl -X POST http://localhost:8080/ \
  -H "Content-Type: application/json" \
  -d '{
    "alert_name": "test-hello-alert",
    "messages": "[{\"text\": \"Hello World\", \"extractedFields\": [{\"name\": \"hello_id\", \"content\": \"msg-001\"}]}, {\"text\": \"Goodbye World\", \"extractedFields\": [{\"name\": \"hello_id\", \"content\": \"msg-002\"}]}]"
  }'
```

## Configuring VCF Operations for Logs

To send alerts to the Alert Transformer:

1. In VCF Operations for Logs, go to **Alerts** → **Manage Alerts**
2. Create or edit an alert
3. In the alert configuration, add a **Webhook** action
4. Set the webhook URL to: `http://<transformer-host>:<transformer-port>/`
   - Example: `http://alert-transformer.example.com:8080/`
5. Save the alert

When the alert triggers, VCF Operations for Logs will POST the alert data to the transformer.

## Production Deployment

### Systemd Service (Linux)

Create `/etc/systemd/system/alert-transformer.service`:

```ini
[Unit]
Description=Alert Transformer Service
After=network.target

[Service]
Type=simple
User=alert-transformer
Group=alert-transformer
WorkingDirectory=/opt/alert-transformer
Environment="PATH=/opt/alert-transformer/.venv/bin"
ExecStart=/opt/alert-transformer/.venv/bin/python alert-transformer.py \
    -c /etc/alert-transformer/config.yaml \
    -q /var/lib/alert-transformer/queue \
    -p 8080
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable alert-transformer
sudo systemctl start alert-transformer
sudo systemctl status alert-transformer
```

### Docker Deployment

A `Dockerfile` is included in the project for containerized deployments.

**Build and run:**
```bash
docker build -t alert-transformer .
docker run -d \
  -p 8080:8080 \
  -v /path/to/config.yaml:/app/config.yaml \
  -v /path/to/queue:/var/lib/alert-transformer/queue \
  --name alert-transformer \
  alert-transformer
```

### Reverse Proxy (Nginx)

For production, use a reverse proxy with TLS:

```nginx
server {
    listen 443 ssl http2;
    server_name alerts.example.com;

    ssl_certificate /etc/ssl/certs/alerts.example.com.crt;
    ssl_certificate_key /etc/ssl/private/alerts.example.com.key;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Monitoring and Troubleshooting

### Check Logs

**With verbose mode:**
```bash
python alert-transformer.py -v
```

**View systemd logs:**
```bash
sudo journalctl -u alert-transformer -f
```

### Common Issues

**Problem: Messages not being sent**
- Check the target URL is correct and accessible
- Verify authentication credentials
- Enable verbose logging to see detailed error messages
- Check the queue directory for failed messages

**Problem: Rules not matching**
- Enable verbose logging to see which rules are evaluated
- Test your regex patterns using an online regex tester
- Check that field names in templates match the actual alert fields

**Problem: Queue directory filling up**
- Check that target systems are reachable
- Verify network connectivity and firewall rules
- Check target system logs for errors

### Testing

For comprehensive testing, use the included dummy test server (see [Testing](#testing) section above):

```bash
# Terminal 1: Start the dummy server
python dummy-server.py

# Terminal 2: Start the transformer in verbose mode
python main.py -v -q /tmp/test-queue

# Terminal 3: Send a test alert
curl -X POST http://localhost:8080/ \
  -H "Content-Type: application/json" \
  -d '{
    "alert_name": "test-hello-alert",
    "messages": "[{\"text\": \"Hello World\", \"staticFields\": [{\"name\": \"__li_source_path\", \"content\": \"/var/log/test\"}], \"extractedFields\": [{\"name\": \"hello_id\", \"content\": \"12345\"}]}]"
  }'
```

**Quick health check:**
```bash
curl http://localhost:8080/
```

## Performance

The Alert Transformer is built on FastAPI and Uvicorn, providing:

- **High throughput**: Handles thousands of requests per second
- **Low latency**: Minimal processing overhead
- **Async I/O**: Efficient handling of concurrent requests
- **Scalability**: Can be deployed in multiple instances behind a load balancer

For high-volume deployments, consider:
- Running multiple instances
- Using a load balancer (HAProxy, Nginx, etc.)
- Monitoring queue depth
- Tuning Uvicorn workers: `uvicorn.run(app, host=host, port=port, workers=4)`

## License

**THIS IS SAMPLE CODE - DO NOT USE IN PRODUCTION WITHOUT PROPER TESTING AND SECURITY REVIEW**

### ⚠️ Pre-Release Security Notice

This is a **pre-release version** with the following known security limitations:

- **Passwords in clear text**: Authentication credentials are stored unencrypted in the configuration file
- **No secret management**: No integration with secret vaults or encrypted storage
- **Limited input validation**: Minimal sanitization of incoming data

**Proper secret management** (environment variables, HashiCorp Vault, AWS Secrets Manager, etc.) **will be implemented in a future release**.

For production use, you must implement proper security measures including:
- Secret management and encrypted credential storage
- Input validation and sanitization
- TLS/SSL encryption for all communications
- Rate limiting and DDoS protection
- Comprehensive security testing and audit

## Support and Contributing

This is sample code provided as-is. Customize and test thoroughly before using in production environments.

For enhancements:
- Add support for additional authentication methods
- Implement custom field transformations
- Add metrics and monitoring endpoints
- Implement rate limiting
- Add input validation and sanitization

## Version History

- **1.0** - Initial release with basic transformation and retry capabilities

