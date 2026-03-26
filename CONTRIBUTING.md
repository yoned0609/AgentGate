# Contributing to AgentGate

Thank you for considering contributing to AgentGate!

## Getting Started

1. Fork and clone the repository
2. Install dependencies:
   ```bash
   cd backend
   pip install -r requirements.txt
   ```
3. Copy the environment file:
   ```bash
   cp .env.example .env
   ```
4. Run tests to make sure everything works:
   ```bash
   python3 -m pytest -v
   ```

## Development Workflow

1. Create a feature branch from `main`
2. Make your changes
3. Ensure all tests pass and linting is clean:
   ```bash
   python3 -m pytest -v
   ruff check .
   ruff format --check .
   ```
4. Submit a pull request

## Code Style

- Python: Follows [ruff](https://docs.astral.sh/ruff/) defaults
- All code must pass CI (lint + test + Docker build)

## Reporting Issues

Open an issue on GitHub with:
- A clear description of the problem
- Steps to reproduce
- Expected vs actual behavior

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
