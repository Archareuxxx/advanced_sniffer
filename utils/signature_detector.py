import json
import re

SIGNATURE_FILE = "signatures/attack_signatures.json"

def load_signatures():
    """Load attack signatures from the JSON file."""
    with open(SIGNATURE_FILE, "r") as f:
        return json.load(f)

def detect_signatures(payload, signatures):
    """Check if the payload matches any attack signatures."""
    for signature in signatures:
        pattern = re.compile(signature["pattern"], re.IGNORECASE)
        if pattern.search(payload):
            return signature
    return None
  
