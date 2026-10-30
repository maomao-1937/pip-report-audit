# Research notes

Primary sources checked 2026-10-30. Original implementation; no upstream code or
documentation is vendored. Synthetic examples do not reproduce an exploit.

## Facts from primary sources

- [pip Installation Report](https://pip.pypa.io/en/stable/reference/installation-report/)
  documents stable report version `1`, report and item fields, direct-reference
  semantics, and the possibility of missing archive hashes in older cache records.
  A report describes installation actions or a dry run and is not itself a lockfile.
- [PyPA Direct URL Data Structure](https://packaging.python.org/en/latest/specifications/direct-url-data-structure/)
  distinguishes archive, VCS, and directory information. It describes recorded
  hashes, the deprecated single-hash field, required VCS revision information,
  and default-false directory editability.
- [pip install](https://pip.pypa.io/en/stable/cli/pip_install/)
  documents report generation and warns about dependency confusion when an
  additional index is used for packages outside the main repository. That warning
  motivates source review; it is not evidence that a particular report is unsafe.

## Project judgments

The narrow HTTPS/DNS profile, exact archive-host list, default VCS/local/yanked
denials, and required recorded SHA-256 are local policy choices, stricter than the
underlying report format. Missing hashes may reflect cache history rather than
malice. Malformed or unsupported input exits 2; a valid record violating policy
exits 1. `is_direct` describes requirement origin and is not inherently a finding.

The checker cannot reconstruct index selection from an artifact URL. It cannot
authenticate a report, fetch a URL, verify artifact bytes, validate certificates,
or assess arbitrary VCS commit identifiers. A policy pass has exactly the scope
of the checks documented in README.

## Fair alternatives

| Tool | Prefer it when | Relationship to this project |
| --- | --- | --- |
| [pip inspect](https://pip.pypa.io/en/stable/cli/pip_inspect/) | You need a JSON inventory of an existing Python environment | It observes installed state; this checker consumes a different report format |
| [pip freeze](https://pip.pypa.io/en/stable/cli/pip_freeze/) | You need installed packages in requirements format | It is a useful inventory export, without this artifact-host policy |
| [pip-audit](https://github.com/pypa/pip-audit) | You need checks for known package vulnerabilities | Its advisory-based scope complements this offline report policy |

Use established tools for their intended scope. This small utility addresses
review of already saved installation reports without dependencies or network I/O.
