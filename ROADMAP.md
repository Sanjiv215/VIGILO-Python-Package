# Vigilo Language Support & Development Roadmap

This document outlines the language support status, architectural design, and future roadmap for Vigilo.

---

## 1. Supported Languages (Shipped)

| Language / Framework | Status | Scanner Engine | File Extensions | Capabilities |
|---|---|---|---|---|
| **Python** | **Stable** (v0.1.0+) | Python `ast` + Local Data Flow | `.py` | Security (SQLi, Command Injection, Insecure Deserialization, Hardcoded Secrets, Code Injection) + Code Correctness Diagnostics |
| **JavaScript** | **Active** (v0.3.0) | `tree-sitter` (`tree-sitter-javascript`) | `.js`, `.mjs`, `.cjs`, `.jsx` | DOM XSS, Code Injection (`eval`/`Function`), Node.js Command Injection, Prototype Pollution, Hardcoded Secrets |
| **TypeScript / TSX** | **Active** (v0.3.0) | `tree-sitter` (`tree-sitter-typescript`) | `.ts`, `.tsx` | React XSS (`dangerouslySetInnerHTML`), Code Injection, Command Injection, Prototype Pollution, Hardcoded Secrets |

---

## 2. Planned Language Support (Deferred)

The following languages and technologies are explicitly planned for future minor versions. By standardizing on `tree-sitter`, Vigilo can add support for these languages using official precompiled grammars without changing the core AST traversal architecture.

| Planned Language | Target Version | Engine | Target Scope |
|---|---|---|---|
| **Java** | Post-v0.3.0 | `tree-sitter-java` | Spring Boot vulnerabilities, SQL injection via JDBC/JPA, deserialization (`ObjectInputStream`), XML External Entity (XXE), Command Injection |
| **HTML** | Post-v0.3.0 | `tree-sitter-html` | Template injection, unescaped output expressions, unsafe inline scripts/event handlers, unclosed tags |
| **CSS** | Post-v0.3.0 | `tree-sitter-css` | CSS injection, unsafe external `url()` resource loading, expression-based payload execution |

---

## 3. Guiding Principles for Language Expansion

1. **Zero External Runtime Dependency**: No language parser added to Vigilo may require an external runtime (like JVM, Node.js, or Ruby) on the user's scanning machine.
2. **Standalone Binary Compatibility**: All parser dependencies must cleanly bundle into self-contained PyInstaller executables across Linux, macOS, and Windows.
3. **High Signal, Low Noise**: New language detectors must follow the same rigorous false-positive validation and CWE mapping as the core Python detectors.
