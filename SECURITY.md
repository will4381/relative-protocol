# Security Policy

## Supported Versions

We actively support and provide security updates for the following versions:

| Version | Supported          | iOS Version | Notes                    |
| ------- | ------------------ | ----------- | ------------------------ |
| 1.x     | ✅ Full Support   | 14.0+       | Current stable release   |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in RelativeProtocol VPN, please follow our responsible disclosure process:

### 🚨 Critical/High Severity Issues

For critical security vulnerabilities (RCE, privilege escalation, data exfiltration):

1. **Do NOT** open a public GitHub issue
2. **Email**: security@relativeprotocol.com (PGP key available below)
3. **Subject**: `[SECURITY] Critical Vulnerability in RelativeProtocol VPN`
4. **Response Time**: We will acknowledge within 24 hours
5. **Resolution**: Critical issues are addressed within 72 hours

### ⚠️ Medium/Low Severity Issues

For less critical issues (DoS, information disclosure, configuration issues):

1. Open a private security advisory on GitHub
2. Or email will@relativecompanies.com
3. **Response Time**: We will acknowledge within 48 hours
4. **Resolution**: Medium issues addressed within 2 weeks

### 📋 Vulnerability Report Template

Please include the following information:

```
**Vulnerability Type**: [Buffer Overflow/Injection/Crypto/etc.]
**Severity**: [Critical/High/Medium/Low]
**Component**: [Core/DNS/NAT64/Privacy/etc.]
**iOS Version**: [14.0+/15.0+/etc.]
**Architecture**: [ARM64/x86_64/Universal]

**Description**:
[Detailed description of the vulnerability]

**Steps to Reproduce**:
1. [Step 1]
2. [Step 2]
3. [Step 3]

**Impact**:
[What can an attacker achieve?]

**Proof of Concept**:
[Code, screenshots, or demonstration]

**Suggested Fix**:
[If you have suggestions]
```

## Security Features

RelativeProtocol VPN includes multiple layers of security protection:

### 🛡️ Core Security Features

- **Memory Safety**: AddressSanitizer integration and comprehensive buffer management
- **DNS Leak Protection**: Built-in kill switch prevents DNS queries outside VPN tunnel
- **IPv6 Leak Protection**: Intelligent IPv6 traffic filtering with legitimate traffic detection
- **WebRTC Leak Protection**: Prevents WebRTC from exposing real IP addresses
- **Kill Switch**: Network blocking when VPN connection fails
- **Secure Defaults**: Privacy-first configuration out of the box

### 🔐 Cryptographic Security

- **Secure Random**: Platform-specific cryptographically secure RNG (SecRandomCopyBytes on iOS)
- **Memory Scrubbing**: Sensitive data cleared from memory after use
- **Constant-Time Operations**: Timing attack prevention in security-critical code
- **Hash Collision Resistance**: HMAC-SHA256 for DNS cache security

### 🧪 Security Testing

Our security posture is maintained through:

- **Static Analysis**: Daily CodeQL and Semgrep scans
- **Dynamic Testing**: AddressSanitizer and Valgrind integration
- **Fuzzing**: Continuous packet parser fuzzing with libFuzzer
- **Dependency Scanning**: OWASP dependency vulnerability checks
- **Secret Scanning**: TruffleHog for credential leak detection
- **Penetration Testing**: Regular third-party security audits

## Security Audit History

| Date       | Auditor              | Scope                | Findings   | Status      |
|------------|---------------------|---------------------|------------|-------------|


## Responsible Disclosure

We are committed to responsible disclosure and will:

- **Acknowledge** receipt of your report within 24-48 hours
- **Investigate** and validate the reported vulnerability
- **Provide updates** on our progress every 3-5 business days
- **Credit** security researchers in our release notes (with permission)
- **Coordinate** disclosure timing with the reporter
- **Release** security patches as soon as safely possible

## Security Best Practices for Users

### For Developers Integrating RelativeProtocol

- ✅ Always use the latest stable version
- ✅ Enable all security features (`enable_dns_leak_protection`, etc.)
- ✅ Implement proper error handling for VPN failures
- ✅ Validate all user inputs before passing to VPN APIs
- ✅ Use secure storage for VPN configuration data
- ✅ Implement certificate pinning for your VPN servers

### For End Users

- ✅ Keep your iOS device updated
- ✅ Use strong, unique passwords for VPN accounts
- ✅ Enable automatic updates for VPN apps
- ✅ Verify VPN connection status before sensitive activities
- ✅ Report any suspicious behavior immediately

## PGP Key for Security Reports

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
[PGP KEY WOULD GO HERE IN REAL IMPLEMENTATION]
-----END PGP PUBLIC KEY BLOCK-----
```

Fingerprint: `XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX`

## Contact Information

- **Website**: https://relativecompanies.com/

---

Last Updated: August 2025  