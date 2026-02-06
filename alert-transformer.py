# THIS IS SAMPLE CODE - DO NOT USE IN PRODUCTION

import json
import os
import time
from threading import Thread
import argparse
import logging

import yaml
import re
from typing import Any
from fastapi import FastAPI, Body
import uvicorn
import requests
from simpleeval import simple_eval

# Setup logging
logger = logging.getLogger(__name__)

# Default values
queue_dir = None
config_file = "config.yaml"
host = "0.0.0.0"
port = 8080

field_extractor = re.compile(r"\$\{([^}]+)}", re.MULTILINE | re.DOTALL)


def parse_args():
    """
    Parse command-line arguments for the alert routing service.

    Returns:
        argparse.Namespace: Parsed command-line arguments containing:
            - config: Path to the YAML configuration file
            - host: Host address to bind the server to
            - port: Port number to run the server on
            - queue_dir: Directory for storing unsent messages for retry
    """
    parser = argparse.ArgumentParser(
        description='Alert Message Processing and Routing Service',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument(
        '-c', '--config',
        default='config.yaml',
        help='Path to the YAML configuration file'
    )

    parser.add_argument(
        '--host',
        default='0.0.0.0',
        help='Host address to bind the server to'
    )

    parser.add_argument(
        '-p', '--port',
        type=int,
        default=8080,
        help='Port number to run the server on'
    )

    parser.add_argument(
        '-q', '--queue-dir',
        default=None,
        help='Directory for storing unsent messages for retry'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose debug logging'
    )

    return parser.parse_args()


def parse_config(filename):
    """
    Parse and process the YAML configuration file for alert routing rules.

    Reads a YAML configuration file and processes it by:
    - Compiling regex patterns for name and message matching
    - Extracting template substitution placeholders
    - Building a structured configuration dictionary

    Args:
        filename (str): Path to the YAML configuration file to parse

    Returns:
        dict: Parsed configuration dictionary containing:
            - rules (list): List of rule dictionaries with compiled patterns
            - targets (list): List of target endpoint configurations
    """
    with open(filename, "r") as f:
        config = yaml.safe_load(f)
        for rule in config.get("rules", []):
            if "namePattern" in rule:
                rule["compiled_name_pattern"] = re.compile(rule["namePattern"])
            if "messagePattern" in rule:
                rule["compiled_message_pattern"] = re.compile(rule["messagePattern"])
            if "template" in rule:
                logger.debug(f"Template: {rule['template']}")
                substitutions = []
                matches = field_extractor.finditer(rule["template"])
                for m in matches:
                    substitutions.append(m.group(1))
                    logger.debug(f"Found substitution: {m.group(1)}")
                rule["template_substitutions"] = substitutions
    return config


def match_message(config, name, text):
    """
    Match a message against configured rules.

    Args:
        config (dict): Configuration dictionary containing rules
        name (str): Alert name to match
        text (str): Message text to match

    Returns:
        list: List of matching rules
    """
    matches = []
    for rule in config.get("rules", []):
        if "compiled_name_pattern" in rule and not rule["compiled_name_pattern"].match(name):
            logger.debug(f"Rule '{rule.get('name', 'unnamed')}' name pattern did not match '{name}'")
            continue
        if "compiled_message_pattern" in rule and not rule["compiled_message_pattern"].match(text):
            logger.debug(f"Rule '{rule.get('name', 'unnamed')}' message pattern did not match")
            continue
        matches.append(rule)
        logger.debug(f"Rule '{rule.get('name', 'unnamed')}' matched")
    return matches


def parse_fields(fields):
    """
    Parse fields into a dictionary.

    Args:
        fields (list): List of field dictionaries with 'name' and 'content' keys

    Returns:
        dict: Dictionary mapping field names to their content
    """
    result = {}
    for field in fields:
        key = field.get("name", "")
        value = field.get("content", "")
        result[key] = value
    return result


def do_substitutions(template, substitutions, event):
    """
    Perform template substitutions using event data.

    Supports both simple variable substitution and Python expressions.
    Simple substitution: ${field_name} or ${static.field_name} or ${extracted.field_name}
    Python expressions: ${static['a'] + static['b']} or ${len(text) > 100} or ${static.get('count', 0) * 2}

    Args:
        template (str): Template string with ${field} placeholders
        substitutions (list): List of field names/expressions to substitute
        event (dict): Event data containing fields

    Returns:
        str: Template with substitutions applied
    """
    static_fields = parse_fields(event.get("staticFields", []))
    extracted_fields = parse_fields(event.get("extractedFields", []))

    # Prepare context for expression evaluation
    eval_context = {
        "static": static_fields,
        "extracted": extracted_fields,
        "text": event.get("text", ""),
        "alert_name": event.get("alert_name", "")
    }

    # Add all top-level event fields to context
    for key, value in event.items():
        if key not in eval_context and is_simple_identifier(key):
            eval_context[key] = value

    result = template
    for sub in substitutions:
        value = ""

        # Check if this is a simple field reference or an expression
        # Simple patterns: "field", "static.field", "extracted.field"
        if "." in sub:
            parts = sub.split(".", 1)
            if len(parts) == 2 and parts[0] in ["static", "extracted"] and is_simple_identifier(parts[1]):
                # Simple field reference
                prefix, name = parts
                if prefix == "static":
                    value = static_fields.get(name, "")
                elif prefix == "extracted":
                    value = extracted_fields.get(name, "")
            else:
                # Treat as Python expression
                value = evaluate_expression(sub, eval_context)
        elif is_simple_identifier(sub):
            # Simple top-level field reference
            value = eval_context.get(sub, "")
        else:
            # Treat as Python expression
            value = evaluate_expression(sub, eval_context)

        # Convert value to string if it's not already
        if not isinstance(value, str):
            value = str(value)

        result = result.replace("${" + sub + "}", value)
        logger.debug(f"Substituted ${{{sub}}} with '{value}'")

    return result


def is_simple_identifier(s):
    """
    Check if a string is a simple identifier (alphanumeric and underscores only).

    Args:
        s (str): String to check

    Returns:
        bool: True if the string is a simple identifier
    """
    return bool(re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', s))


def evaluate_expression(expression, context):
    """
    Safely evaluate a Python expression using simpleeval.

    Args:
        expression (str): Python expression to evaluate
        context (dict): Context variables for evaluation

    Returns:
        str: Result of the expression evaluation, or empty string on error
    """
    try:
        # Define safe functions that can be used in expressions
        safe_functions = {
            'len': len,
            'str': str,
            'int': int,
            'float': float,
            'bool': bool,
            'min': min,
            'max': max,
            'sum': sum,
            'abs': abs,
            'round': round,
        }

        # Use simple_eval with safe functions
        result = simple_eval(expression, names=context, functions=safe_functions)
        logger.debug(f"Expression '{expression}' evaluated to: {result}")
        return result
    except Exception as e:
        logger.error(f"Failed to evaluate expression '{expression}': {e}")
        return ""


def save_message(message, target):
    """
    Save a failed message to disk for later retry.

    Args:
        message (str): Message to save
        target (str): Target name
    """
    filename = f"{queue_dir}/{target}_{int(time.time() * 1000)}.work"
    with open(filename, "w") as f:
        f.write(message)
    os.rename(filename, filename.replace(".work", ".msg"))
    logger.info(f"Saved message for target '{target}' to {filename.replace('.work', '.msg')}")


def send_event(target, message):
    """
    Send an event message to a target endpoint.

    Args:
        target (dict): Target configuration with url, method, headers, and auth
        message (str): Message to send

    Returns:
        str: Status of the send operation:
            - "success": Message sent successfully (2xx)
            - "retry": Temporary failure, should retry (network errors, 5xx)
            - "rate_limited": Rate limited (429), should retry with backoff
            - "permanent": Permanent failure, should not retry (4xx client errors)
    """
    # Non-recoverable HTTP status codes (client errors)
    # Note: 429 (Too Many Requests) is recoverable with backoff, so not included here
    NON_RECOVERABLE_CODES = {400, 401, 403, 404, 405, 406, 409, 410, 411, 413, 414, 415, 416, 422}

    url = target.get("url", "")
    method = target.get("method", "POST").upper()
    headers = target.get("headers", {})
    request_auth = None
    if "authentication" in target:
        auth = target["authentication"]
        if auth.get("type", "") == "Basic":
            request_auth = (auth.get("username"), auth.get("password"))
        else:
            request_auth = None
            logger.warning(f"Unsupported authentication type: {auth.get('type', '')}")
    try:
        response = requests.request(method=method, url=url, data=message, headers=headers, auth=request_auth)
    except Exception as e:
        logger.error(f"Failed to send event to {url}: {e}")
        return "retry"  # Network errors are recoverable

    if response.status_code in range(200, 299):
        logger.info(f"Sent event to {url}, response code: {response.status_code}")
        return "success"
    elif response.status_code == 429:
        logger.warning(f"Rate limited by {url}, response code: 429")
        return "rate_limited"
    elif response.status_code in NON_RECOVERABLE_CODES:
        logger.error(f"Permanent failure sending event to {url}, response code: {response.status_code}, response body: {response.text}")
        logger.error(f"Message will NOT be retried (non-recoverable error)")
        return "permanent"
    else:
        logger.error(f"Failed to send event to {url}, response code: {response.status_code}, response body: {response.text}")
        return "retry"


def retry_saved_messages():
    """
    Background thread that continuously retries sending saved messages.

    Scans the queue directory for saved messages and attempts to send them.
    Successfully sent messages are removed from the queue.
    If rate limiting (429) is encountered, sleeps for 60 seconds before continuing.
    """
    while True:
        rate_limited = False

        # Get files in date order (oldest first)
        filenames = os.listdir(queue_dir)
        filenames = [os.path.join(queue_dir, f) for f in filenames]
        filenames.sort(key=os.path.getmtime)

        for filename in filenames:
            if filename.endswith(".msg"):
                filepath = os.path.join(queue_dir, filename)
                with open(filepath, "r") as f:
                    message = f.read()

                # Target is the first part of the filename before the underscore
                target_name = os.path.basename(filename).split("_")[0]
                if target_name is None or target_name not in targets:
                    logger.warning(f"No valid target for saved message, skipping: {filename}")
                    continue
                target = targets[target_name]
                result = send_event(target, message)
                if result == "success":
                    os.remove(filepath)
                    logger.info(f"Successfully sent saved message, removed file: {filename}")
                elif result == "permanent":
                    # Don't retry permanent failures, remove the message
                    os.remove(filepath)
                    logger.warning(f"Removed message with permanent failure: {filename}")
                elif result == "rate_limited":
                    logger.warning(f"Rate limited, will sleep for 60 seconds before retrying")
                    rate_limited = True
                    break  # Stop processing and sleep
                else:  # result == "retry"
                    logger.debug(f"Failed to send saved message, will retry later: {filename}")

        # If we encountered rate limiting, sleep for 60 seconds
        if rate_limited:
            time.sleep(60)
        else:
            time.sleep(10)


app = FastAPI()
config = {}
targets = {}


@app.get('/')
def health_check():
    """
    Health check endpoint.

    Returns:
        dict: Status information
    """
    return {
        "status": "ok",
        "service": "Alert Transformer",
        "rules_loaded": len(config.get("rules", [])),
        "targets_configured": len(targets)
    }


@app.post('/')
def handle_alert(payload: Any = Body(None)):
    """
    Handle incoming alert webhook requests.

    Args:
        payload (Any): Alert payload containing alert_name and messages

    Returns:
        tuple: Response message and HTTP status code
    """
    logger.debug(f"Received alert payload: {json.dumps(payload, indent=2)}")
    alert_name = payload.get("alert_name", "")
    messages = json.loads(payload.get("messages", "[]"))
    for event in messages:
        text = event.get("text", "")
        for rule in match_message(config, alert_name, text):
            logger.info(f"Matched rule: {rule.get('name', 'Unnamed Rule')}")
            output_message = do_substitutions(rule.get("template", ""), rule.get("template_substitutions", []), event)
            logger.debug(f"Output message: {output_message}")
            target_name = rule.get("target", None)
            if target_name is None or target_name not in targets:
                logger.warning(f"No valid target for rule '{rule.get('name', 'Unnamed Rule')}', skipping")
                continue
            target = targets[target_name]
            result = send_event(target, output_message)
            if result == "retry" or result == "rate_limited":
                if result == "rate_limited":
                    logger.warning(f"Rate limited by target: {target_name}, message queued for retry")
                else:
                    logger.warning(f"Failed to send message to target: {target_name}, will retry")
                if queue_dir:
                    save_message(output_message, target_name)
            elif result == "permanent":
                logger.error(f"Permanent failure for target: {target_name}, message discarded")
    return "OK", 200


if __name__ == '__main__':
    # Parse command-line arguments
    args = parse_args()

    # Configure logging based on verbose flag
    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Update global variables with command-line arguments
    queue_dir = args.queue_dir
    config_file = args.config
    host = args.host
    port = args.port

    # Ensure queue directory exists
    if queue_dir is None:
        logger.warning("No queue directory specified, messages will be lost if send fails")
    else:
        os.makedirs(queue_dir, exist_ok=True)
        logger.info(f"Using queue directory: {queue_dir}")

    # Load configuration
    logger.info(f"Loading configuration from {config_file}")
    config = parse_config(config_file)

    # Build lookup table for targets
    for t in config.get("targets", []):
        targets[t.get("name", "")] = t
    logger.info(f"Loaded {len(config.get('rules', []))} rules and {len(targets)} targets")

    # Start background thread for retrying saved messages
    if queue_dir is not None:
        Thread(target=retry_saved_messages, daemon=True).start()
        logger.info("Started background retry thread")

    # Run the FastAPI app
    logger.info(f"Starting server on {host}:{port}")
    uvicorn.run(app, host=host, port=port)
