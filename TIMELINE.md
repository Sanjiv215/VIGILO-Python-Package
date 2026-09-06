# Vigilo Development Timeline

This timeline is constructed directly from repository git commit history and release milestones.

| Date / Timestamp (UTC+05:30) | Commit / Tag | Milestone / Event | Description |
|---|---|---|---|
| **2026-09-04 16:40:53** | `9d246cd` | Initial Commit | Repository initialized with initial README stub. |
| **2026-09-04 16:48:32** | `3716ace` | Product Scope | Definition of core AST security scanner requirements. |
| **2026-09-04 16:57:03** | `64a0eec` | Architecture Spec | Data models (`Finding`, `Severity`, `Location`) specified. |
| **2026-09-04 17:19:14** | `2c63cd9` | Core Engine | AST traversal and lightweight data-flow analysis implemented. |
| **2026-09-04 17:24:55** | `3e50f60` | Python CWE Detectors | Initial 5 Python security detectors (CWE-89, 78, 94, 502, 22). |
| **2026-09-04 17:29:56** | `600b58e` | CLI Implementation | `argparse` CLI entrypoint and text/JSON reporter. |
| **2026-09-04 17:54:50** | `ae9d066` | Validation Suite | Test fixtures, benchmark validation, and edge case suite. |
| **2026-09-05 13:09:46** | `4fe47a0` | CI / Release Setup | GitHub Actions matrix (Ubuntu, macOS, Windows across Python 3.10–3.13). |
| **2026-09-05 13:34:18** | `ecdf05e` | Binary Automation | PyInstaller standalone binary compilation and SHA256 checksum generation. |
| **2026-09-05 13:53:36** | `b81c20a` | Rebrand to Vigilo | Rebranded from Ojo to `vigilo` on PyPI and GitHub. |
| **2026-09-05 14:16:48** | `a1ea0eb` | CI Glob Fix | Fixed Ruff `per-file-ignores` glob pattern `tests/**` that caused matrix job failures. |
| **2026-09-05 14:21:55** | `3fbd979` | **Release v0.1.1** | Gated release workflow on test matrix; yanked v0.1.0 on PyPI. |
| **2026-09-05 14:30:08** | `a20f5b4` | Documentation Links | Converted relative markdown links to absolute GitHub URLs for PyPI rendering. |
| **2026-09-05 14:53:42** | `014de3e` | **Release v0.2.0** | Added Python code correctness diagnostics (`VIGILO-C01` to `VIGILO-C05`). |
| **2026-09-05 15:47:43** | `94f8577` | **Release v0.2.1** | Audited correctness detectors and wired diagnostics into default scan pipeline. |
| **2026-09-05 19:46:46** | `4e0e9da` | License Update | Updated copyright notice in LICENSE file. |
| **2026-09-05 20:10:28** | `932f71a` | **Release v0.2.2** | 20-technique security audit fixes, ANSI injection sanitization, cycle protection, strict mypy. |
| **2026-09-05 20:17:54** | `dbc9ae4` | CI Hardening | Wired `pip-audit --local` and strict security gates into CI. |
| **2026-09-06 10:19:00** | `0a5e6e0` / `v0.3.0` | **Release v0.3.0** | JavaScript, TypeScript, React support via Tree-Sitter (`VIGILO-JS-001` to `VIGILO-JS-005`), ADR docs, `--mode` flag, bounded reporter snippets. |
