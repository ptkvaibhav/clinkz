# Security Policy

## Intended Use

Clinkz is designed for **authorized security testing only**. It must only be used against systems you own or have explicit written permission to test.

Unauthorized use of this tool is illegal and unethical. The authors are not responsible for any misuse.

## Reporting Security Issues

If you discover a security vulnerability in Clinkz itself (not in a target system), please report it responsibly:

1. **Do not** open a public GitHub issue
2. Email **ptkvaibhav@gmail.com** with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
3. Allow up to 72 hours for an initial response

We will work with you to understand the issue and coordinate a fix before any public disclosure.

## Scope

This policy covers vulnerabilities in the Clinkz codebase — for example:

- Command injection in tool wrappers
- Scope enforcement bypass (tools running against out-of-scope targets)
- Credential leakage (API keys, tokens exposed in logs or reports)
- Unsafe deserialization or code execution

## Responsible Disclosure

We follow coordinated disclosure. Once a fix is available, we will:

1. Release a patched version
2. Credit the reporter (unless they prefer to remain anonymous)
3. Publish a brief advisory describing the issue and fix
