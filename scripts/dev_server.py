"""Local development server; takes the port from PORT (set by preview tools), default 8766."""
import os
import sys
from pathlib import Path

import uvicorn

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    uvicorn.run("app.main:app", host="127.0.0.1", port=int(os.environ.get("PORT", "8766")), reload=False)
