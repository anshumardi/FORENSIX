"""Command-line entry point for the FORENSIX background worker."""

from app.worker import run_worker


if __name__ == "__main__":
    run_worker()
