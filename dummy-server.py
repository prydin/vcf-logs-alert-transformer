"""
Dummy Test Server for Alert Transformer

A simple FastAPI server that receives and displays transformed alerts from the Alert Transformer.
Useful for testing and validating alert transformation rules and templates.
"""

import json
import argparse
from datetime import datetime
from typing import Any
from fastapi import FastAPI, Body
import uvicorn

app = FastAPI(title="Alert Transformer Test Server")


def parse_args():
    """
    Parse command-line arguments.

    Returns:
        argparse.Namespace: Parsed command-line arguments
    """
    parser = argparse.ArgumentParser(
        description='Dummy test server for receiving transformed alerts',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument(
        '--host',
        default='0.0.0.0',
        help='Host address to bind the server to'
    )

    parser.add_argument(
        '-p', '--port',
        type=int,
        default=8888,
        help='Port number to run the server on'
    )

    return parser.parse_args()


@app.post("/ingest")
async def receive_event(event: Any = Body(...)):
    """
    Receive and display transformed alert events.

    Args:
        event: The transformed alert payload

    Returns:
        dict: Response indicating successful receipt
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n{'='*80}")
    print(f"[{timestamp}] Received event:")
    print(f"{'='*80}")
    print(json.dumps(event, indent=2))
    print(f"{'='*80}\n")
    return {"status": "received", "timestamp": timestamp}


@app.get("/")
async def root():
    """Health check endpoint."""
    return {"status": "ok", "message": "Dummy test server is running"}


if __name__ == "__main__":
    args = parse_args()
    print(f"Starting dummy test server on {args.host}:{args.port}")
    print(f"Listening for alerts at http://{args.host}:{args.port}/ingest")
    print("Press CTRL+C to stop\n")
    uvicorn.run(app, host=args.host, port=args.port)
