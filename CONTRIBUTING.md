# Contributing to BBRECON

Thank you for considering contributing to BBRECON! This document provides guidelines and instructions for contributing to the project.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct. Please treat all community members with respect.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/bbrecon.git`
3. Add the original repository as upstream: `git remote add upstream https://github.com/zarni99/bbrecon.git`
4. Create a new branch for your changes: `git checkout -b feature/your-feature-name`

## Development Setup

1. Ensure you have Go 1.18 or higher installed
2. Build the tool: `go build -o bbrecon ./cmd`
3. Test your changes: `./bbrecon -h`

## Making Changes

1. Make your changes in your feature branch
2. Follow Go's [standard coding style](https://golang.org/doc/effective_go.html)
3. Write clear, commented code
4. Ensure your changes don't break existing functionality

## Testing

Before submitting a pull request, please test your changes thoroughly:

1. Build the tool: `go build -o bbrecon ./cmd`
2. Test basic functionality: `./bbrecon -h`
3. Test new features you've added
4. If applicable, test on different platforms (Windows, macOS, Linux)

## Submitting Changes

1. Commit your changes with a descriptive commit message
2. Push your branch to your fork: `git push origin feature/your-feature-name`
3. Submit a pull request to the main repository
4. Clearly describe the problem and solution in the PR description

## Pull Request Guidelines

- Keep PRs focused on a single issue or feature
- Write a clear description of what your PR accomplishes
- Include screenshots if your PR includes visual changes
- Respond to feedback and be willing to make changes if requested

## Feature Requests

If you have a feature request, please open an issue and describe:

1. What you want to achieve
2. Why this feature would be valuable to the project
3. Any implementation ideas you have

## Reporting Bugs

When reporting bugs, please include:

1. Steps to reproduce the issue
2. Expected behavior
3. Actual behavior
4. Screenshots (if applicable)
5. Operating system and version
6. Go version
7. BBRECON version

## License

By contributing to BBRECON, you agree that your contributions will be licensed under the project's MIT License. 