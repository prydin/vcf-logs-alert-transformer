#!/bin/bash

# Test script for anti-flapping mechanism
# This script demonstrates how the transformer handles out-of-order events

echo "=== Anti-Flapping Test Script ==="
echo ""
echo "This test demonstrates the anti-flapping mechanism:"
echo "1. First, we send the CANCELLING event (Goodbye)"
echo "2. Then, we send the INITIATING event (Hello)"
echo "3. Both should be suppressed due to anti-flapping"
echo ""

# Alert transformer endpoint
TRANSFORMER_URL="http://localhost:8080"

# Test Case 1: Out-of-order arrival (Cancelling → Initiating)
echo "=== Test Case 1: Out-of-Order Arrival ==="
echo ""

# Send cancelling event FIRST
echo "Sending CANCELLING event (Goodbye) with hello_id=test123..."
curl -X POST "$TRANSFORMER_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "alert_name": "hello-test",
    "messages": "[{\"text\": \"Goodbye from test\", \"fields\": [{\"name\": \"__li_source_path\", \"content\": \"/test/path\"}], \"extractedFields\": [{\"name\": \"hello_id\", \"content\": \"test123\"}, {\"name\": \"__li_agent_id\", \"content\": \"agent-1\"}]}]"
  }'
echo ""
echo ""

sleep 1

# Send initiating event SECOND
echo "Sending INITIATING event (Hello) with hello_id=test123..."
curl -X POST "$TRANSFORMER_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "alert_name": "hello-test",
    "messages": "[{\"text\": \"Hello from test\", \"fields\": [{\"name\": \"__li_source_path\", \"content\": \"/test/path\"}], \"extractedFields\": [{\"name\": \"hello_id\", \"content\": \"test123\"}, {\"name\": \"__li_agent_id\", \"content\": \"agent-1\"}]}]"
  }'
echo ""
echo ""

echo "Expected result: BOTH events should be suppressed (check logs with -v flag)"
echo ""
echo "=== Test Case 1 Complete ==="
echo ""
sleep 2

# Test Case 2: Normal order arrival (Initiating → Cancelling)
echo "=== Test Case 2: Normal Order Arrival ==="
echo ""

# Send initiating event FIRST
echo "Sending INITIATING event (Hello) with hello_id=test456..."
curl -X POST "$TRANSFORMER_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "alert_name": "hello-test",
    "messages": "[{\"text\": \"Hello from normal test\", \"fields\": [{\"name\": \"__li_source_path\", \"content\": \"/test/path\"}], \"extractedFields\": [{\"name\": \"hello_id\", \"content\": \"test456\"}, {\"name\": \"__li_agent_id\", \"content\": \"agent-1\"}]}]"
  }'
echo ""
echo ""

sleep 1

# Send cancelling event SECOND
echo "Sending CANCELLING event (Goodbye) with hello_id=test456..."
curl -X POST "$TRANSFORMER_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "alert_name": "hello-test",
    "messages": "[{\"text\": \"Goodbye from normal test\", \"fields\": [{\"name\": \"__li_source_path\", \"content\": \"/test/path\"}], \"extractedFields\": [{\"name\": \"hello_id\", \"content\": \"test456\"}, {\"name\": \"__li_agent_id\", \"content\": \"agent-1\"}]}]"
  }'
echo ""
echo ""

echo "Expected result: BOTH events should be processed normally (check dummy-server output)"
echo ""
echo "=== Test Case 2 Complete ==="
echo ""

echo "=== Anti-Flapping Test Complete ==="
echo ""
echo "Check the transformer logs (run with -v flag) to see anti-flapping in action"
echo "Check the dummy-server output to see which events were actually sent"

