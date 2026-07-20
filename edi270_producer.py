#!/usr/bin/env python3
"""
Synthetic EDI270 (eligibility inquiry) event producer -- exists purely to give the Streaming
environment's Rule Sets tab a real topic with real, sensibly-shaped JSON to inspect (see
README.md's "Streaming" section). Modeled on a sister reference project's producer.py, trimmed
down: no X12/medical-note realism, no masking -- this is a source topic only, not wired into
kafka-masking-bridge.

Field names/shapes match that project's config.yaml so the Ruleset page's suggested-algorithm
lookup (see demo/server.py's SUGGESTED_ALGORITHM_BY_FIELD) has something meaningful to match
against: message_id, customer_id, first_name, last_name, email_address, national_identifier,
dob, claim_id, claim_amount, edi_270_note, medical_notes, timestamp.

Env vars: KAFKA_BOOTSTRAP_SERVERS (required), TOPIC (default EDI270), INTERVAL_SECONDS (default 2).
"""
import json
import os
import random
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

from kafka import KafkaProducer

# Reuses the exact name lists FirstNameLookupSchemeFactory/LastNameLookupSchemeFactory bundle for
# FIRST-NAME-LOOKUP/LAST-NAME-LOOKUP -- no new name-list dependency for this producer.
NAMES_DIR = (
    Path(__file__).resolve().parent
    / "src" / "main" / "resources" / "com" / "delphix" / "dynamicmasking" / "onewaymasking"
)
FIRST_NAMES = (NAMES_DIR / "first-names.txt").read_text().splitlines()
LAST_NAMES = (NAMES_DIR / "last-names.txt").read_text().splitlines()

BOOTSTRAP_SERVERS = os.environ["KAFKA_BOOTSTRAP_SERVERS"]
TOPIC = os.environ.get("TOPIC", "EDI270")
INTERVAL_SECONDS = float(os.environ.get("INTERVAL_SECONDS", "2"))

EASTERN = ZoneInfo("America/New_York")


def random_ssn():
    return f"{random.randint(100, 899)}-{random.randint(10, 99)}-{random.randint(1000, 9999)}"


def random_dob():
    days_old = random.randint(365 * 18, 365 * 90)
    return (datetime.now(EASTERN) - timedelta(days=days_old)).strftime("%Y-%m-%d")


def build_event():
    first_name = random.choice(FIRST_NAMES)
    last_name = random.choice(LAST_NAMES)
    customer_id = random.randint(100000, 999999)
    claim_id = random.randint(100000, 999999)
    national_identifier = random_ssn()
    dob = random_dob()
    claim_amount = round(random.uniform(100.0, 50000.0), 2)

    return {
        "message_id": str(uuid.uuid4()),
        "customer_id": customer_id,
        "first_name": first_name,
        "last_name": last_name,
        "email_address": f"{first_name.lower()}.{last_name.lower()}@example.com",
        "national_identifier": national_identifier,
        "dob": dob,
        "claim_id": claim_id,
        "claim_amount": claim_amount,
        # Not real X12 -- just enough structure to look like a derived/composite field, matching
        # the sister project's edi_270_note (there, regenerated from the masked fields; here,
        # there's no masking step, so it's built from the raw ones).
        "edi_270_note": (
            f"NM1*IL*1*{last_name.upper()}*{first_name.upper()}~"
            f"DMG*D8*{dob.replace('-', '')}~MI*{national_identifier.replace('-', '')}~"
            f"CLM*{claim_id}*{claim_amount}"
        ),
        "medical_notes": (
            f"Patient {first_name} {last_name} (DOB {dob}) presented for a routine eligibility "
            f"check ahead of claim #{claim_id}."
        ),
        "timestamp": datetime.now(EASTERN).isoformat(),
    }


def main():
    producer = KafkaProducer(
        bootstrap_servers=BOOTSTRAP_SERVERS,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    )
    print(f"Producing synthetic {TOPIC} events every {INTERVAL_SECONDS}s to {BOOTSTRAP_SERVERS}")
    while True:
        event = build_event()
        producer.send(TOPIC, event)
        producer.flush()
        time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
