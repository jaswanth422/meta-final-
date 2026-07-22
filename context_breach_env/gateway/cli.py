from __future__ import annotations

import uvicorn


def main() -> None:
    uvicorn.run(
        "context_breach_env.gateway.app:app",
        host="0.0.0.0",
        port=8081,
        access_log=False,
    )


if __name__ == "__main__":
    main()
