# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in SnortForge, please report it responsibly:

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, please report security issues via:
- **GitHub Security Advisories**: Use the "Report a vulnerability" button in the Security tab
- **Email**:

**What to include in your report:**
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

**Response timeline:**
- Initial response: Within 48 hours
- Status update: Within 7 days
- Fix timeline: Depends on severity (Critical: 7 days, High: 14 days, Medium: 30 days)

## Security Best Practices

When using SnortForge:
- Never run Flask in debug mode in production (`app.run(debug=False)`)
- Validate all user input before rule generation
- Review generated rules before deploying to production IDS
- Keep dependencies updated (Dependabot handles this automatically)

## Security Features

- CodeQL automated vulnerability scanning
- Dependabot security updates
- Input validation on all API endpoints
- No database = reduced attack surface
