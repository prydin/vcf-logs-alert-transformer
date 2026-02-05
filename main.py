import json
import yaml
import re
from typing import Any
from fastapi import FastAPI, Body
import uvicorn
import requests

field_extractor = re.compile(r"\$\{([^}]+)}", re.MULTILINE | re.DOTALL )

def parse_config(filename):
    with open(filename, "r") as f:
        config = yaml.safe_load(f)
        for rule in config.get("rules", []):
            if "pattern" in rule:
                rule["compiled_pattern"] = re.compile(rule["pattern"])
            if "template" in rule:
                print(rule["template"])
                substitutions = []
                matches = field_extractor.finditer(rule["template"])
                for m in matches:
                    substitutions.append(m.group(1))
                    print("Found substitution:", m.group(1))
                rule["template_substitutions"] = substitutions
    return config

def match_message(config, text):
    matches = []
    for rule in config.get("rules", []):
        if "compiled_pattern" in rule and rule["compiled_pattern"].match(text):
            matches.append(rule)
    return matches

def parse_fields(fields):
    result = {}
    for field in fields:
        key = field.get("name", "")
        value = field.get("content", "")
        result[key] = value
    return result

def do_substitutions(template, substitutions, event):
    static_fields = parse_fields(event.get("staticFields", {}))
    extracted_fields = parse_fields(event.get("extractedFields", {}))

    result = template
    for sub in substitutions:
        (prefix, name) = sub.split(".", 1) if "." in sub else ("", sub)
        if prefix == "static":
            value = static_fields.get(name, "")
        elif prefix == "extracted":
            value = extracted_fields.get(name, "")
        else:
            value = event.get(name, "")
        result = result.replace("${" + sub + "}", value)
    return result

def send_event(target, message):
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
            print("Unsupported authentication type:", auth.get("type", ""))
    try:
        response = requests.request(method=method, url=url, json=message, headers=headers, auth=request_auth)
    except Exception as e:
        print(f"Failed to send event to {url}: {e}")
        return str(e), 500
    if response.status_code not in range(200, 299):
        print(f"Failed to send event to {url}, response code: {response.status_code}, response body: {response.text}")
        return "Service Unavailable", 503
    print(f"Sent event to {url}, response code: {response.status_code}")
    return "OK", 200

app = FastAPI()
config = parse_config("config.yaml")
targets = {}

# Build lookup table for targets
for t in config.get("targets", []):
    targets[t.get("name", "")] = t

@app.post('/')
def handle_alert(payload: Any = Body(None)):
    print(json.dumps(payload, indent=2))
    messages = json.loads(payload.get("messages", "[]"))
    for event in messages:
        text = event.get("text", "")
        for rule in match_message(config, text):
            print("Matched rule:", rule.get("name", "Unnamed Rule"))
            output_message = do_substitutions(rule.get("template", ""), rule.get("template_substitutions", []), event)
            print("Output message:", output_message)
            target_name = rule.get("target", None)
            if target_name is None or target_name not in targets:
                print("No valid target for rule, skipping.")
                continue
            target = targets[target_name]
            send_event(target, output_message)
    return "OK", 200

if __name__ == '__main__':
    uvicorn.run(app, host="0.0.0.0", port=8080)

