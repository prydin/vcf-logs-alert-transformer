#!/bin/bash
# End-to-end test script for Alert Transformer
# This script demonstrates how to test the alert transformation workflow

set -e

echo "Alert Transformer End-to-End Test"
echo "===================================="
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up..."
    if [ ! -z "$DUMMY_PID" ]; then
        kill $DUMMY_PID 2>/dev/null || true
    fi
    if [ ! -z "$TRANS_PID" ]; then
        kill $TRANS_PID 2>/dev/null || true
    fi
}

trap cleanup EXIT

# Start dummy server
echo "1. Starting dummy test server on port 8888..."
python dummy-server.py -p 8888 &
DUMMY_PID=$!
sleep 2

# Start transformer
echo "2. Starting alert transformer on port 8080 with verbose logging..."
python alert-transformer.py -p 8080 -q /tmp/alert-queue -v &
TRANS_PID=$!
sleep 2

echo ""
echo "3. Sending test alert to transformer..."
echo ""

curl -s -X POST http://localhost:8080/ \
  -H "Content-Type: application/json" \
  -d '{
    "alert_name": "test-hello-alert",
    "messages": "[{\"text\": \"Hello World from test script\", \"staticFields\": [{\"name\": \"__li_source_path\", \"content\": \"/var/log/application.log\"}, {\"name\": \"hostname\", \"content\": \"test-server-01\"}], \"extractedFields\": [{\"name\": \"hello_id\", \"content\": \"test-12345\"}, {\"name\": \"__li_agent_id\", \"content\": \"agent-001\"}]}]"
  }' && echo " ✓ Alert sent successfully"

echo ""
echo "4. Waiting for processing..."
sleep 2

echo ""
echo "===================================="
echo "Test complete!"
echo ""
echo "Check the dummy server output above to see the transformed alert."
echo "Check the transformer verbose logs to see the processing details."
echo ""
echo "Press CTRL+C to stop the servers..."
wait

