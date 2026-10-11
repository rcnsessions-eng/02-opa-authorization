# Zero Trust for AI Agents: Teaching Tools 1.0.0

This versioned package runs the executable code printed in Chapter 4 and Appendices E/F. It contains code-only fixtures, not the book's prose, figures or cover. Its teaching decision contract is `teaching-1.0.0`, distinct from the workshop API contract. The package version, decision version and repository commit identify different things.

## Requirements

Use Python 3.12 or later, Pandoc, a running Docker Engine and access to the digest-pinned OPA image named in `verify-teaching-policy.py`. No pip packages, model account, sibling checkout, cluster or companion service is required. Docker may download the OPA image; policy containers themselves have no network access.

Use the exact repository commit printed in the book's Appendix H. From this `book-tools/` directory, verify the payload before running it:

```bash
shasum -a 256 -c SHA256SUMS
python3 verify-teaching-policy.py
python3 verify-teaching-policy.py --benchmark --benchmark-count 1
```

On systems with GNU coreutils, `sha256sum -c SHA256SUMS` is equivalent. Compare the SHA256SUMS file's digest with the value printed in Appendix G. Checksums detect changed bytes; an attacker-controlled manifest is not an independent trust root. The book's pinned commit and manifest digest are the source reference, not a signing certification.

Expected results: four Appendix E tests, four structured Chapter 4 tests, two boolean tests, actual allow/deny responses accepted by the printed Python contract, and a syntactically valid tenant-guard mutation rejected by negative tests. The helper exits nonzero on failure. Keep the baseline passing; a missing executable or syntax error is not a successful mutation test.

Generated examples go to `dist/teaching-policy/`. Benchmark JSON goes to `artifacts/teaching-policy-benchmark.json`; one to five repetitions and a 120-second timeout per OPA command bound this optional check. These are in-process Rego measurements, not HTTP/MCP capacity or production latency. The temporary unsafe mutant is removed. Generated files are ignored by Git.

## License and Reports

The [NON-COMMERCIAL SOURCE-AVAILABLE LICENSE](LICENSE) and [NOTICE](NOTICE) apply to this first-party executable package. Personal learning, non-commercial experimentation and non-commercial academic research are subject to the full terms. Commercial use, paid training and distribution of modified code require prior written permission. This is not open source and provides no warranty. Third-party tools retain their own licenses.

Contact [rcnsessions@gmail.com](mailto:rcnsessions@gmail.com) for permissions or private security reports. Do not send credentials or real data. The repository's root CONTRIBUTING.md and SECURITY.md describe submission and vulnerability-reporting requirements.
