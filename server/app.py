from context_breach_env.server.app import app
from context_breach_env.server.cli import main as run_server


__all__ = ["app", "main"]


def main() -> None:
    run_server()


if __name__ == "__main__":
    main()
