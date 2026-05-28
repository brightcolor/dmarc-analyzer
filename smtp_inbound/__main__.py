"""
Run SMTP Inbound as a standalone process:
    python -m smtp_inbound
"""
import asyncio
import logging
import os
import sys

# Ensure the project root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

from smtp_inbound.server import start_smtp_server  # noqa: E402


def main() -> None:
    try:
        asyncio.run(start_smtp_server())
    except KeyboardInterrupt:
        logging.info("SMTP Inbound stopped by user")


if __name__ == "__main__":
    main()
