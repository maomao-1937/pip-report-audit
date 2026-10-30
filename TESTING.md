# Verification record

Observed on 2026-10-30, Windows, CPython 3.11.15. No third-party packages used.

## RED then GREEN

The initial 35-test suite was written before the CLI existed. Running
`python -m unittest discover -s tests -p test_audit.py` produced 57 assertion
failures across tests/subtests in 0.665 s. The clean CLI test expected exit 0
and received exit 2 because the executable was absent. Core unit tests failed
their explicit implementation-required assertion. This was a real failing run,
not an artificial expected-failure marker.

After implementing the supported report/policy behavior, all 35 tests passed.
Three additional tests were then written for finite-number overflow, ambiguous
hexadecimal address forms, and known optional-field shapes. The next real run
reported 38 tests with 3 failures. The corresponding validation was added, and
the suite passed 38 tests in 0.959 s. Durations vary by machine.

An independent specification review then identified missing coverage counters
and acceptance of four/five-slash file URLs despite the documented network-share
exclusion. Five regression tests were added before those fixes, including
mixed remote/local archives, remote/local VCS, directories, clean/findings and
empty output, plus raw/encoded UNC-shaped URLs for every source kind. The real
RED run reported 43 tests with 25 assertion failures in 1.322 s. After adding
the counters and rejecting raw/percent-decoded double-slash path prefixes, all
43 tests passed in 1.752 s. No URL path was accessed during these tests.

Batch build evidence is recorded outside the project at
`../../builder-evidence/pip-report-audit/`: `red.txt`, `red-hardening.txt`, and
`green.txt`. These are actual command outputs. They are build evidence, not
runtime inputs or part of the library API.
The review-fix cycle is separately preserved in `red-spec-fixes.txt` and
`green-spec-fixes.txt`; initial failure evidence remains intact.

## Reproduce

```console
python -m unittest discover -s tests -v
```

The 43 named tests include core unit tests and real CLI subprocess tests, with
subcases for URL spoofing, credentials, fragments, controls, malformed origins,
hash lengths/alphabet/conflicts, policy types, duplicate keys, nonfinite JSON,
surrogates, byte/depth/item limits, empty installs, direct archives, yanked
versions, VCS/local opt-ins and malformed shapes, neutral operational errors,
privacy, help, and closed stdout including help output.
They also verify requested/direct/source-kind coverage on mixed-origin reports,
zero coverage on empty reports, and neutral CLI rejection of raw/encoded
UNC/share-shaped paths even when local sources are allowed.

Each subprocess uses a 12-second timeout and managed pipes. Commands use the
CLI basename with an explicit project working directory so that Windows does
not repeatedly resolve a deep absolute script path. Unit tests import the local
module by path. Temporary report/policy files are synthetic and cleaned up.

`checks.json` contains eight fixture invocations with their expected exit
codes. A runner should prepend only its Python interpreter to each `args` list,
execute from this project directory, and compare the actual exit with `exit`.
The fixtures cover clean, direct, yanked, foreign host, malformed URL, denied
VCS, allowed local directory, and missing recorded SHA-256 behavior.

No live pip installation, malicious package, network download, Linux run, or
certificate/hash-content verification was performed. These checks support the
documented local behavior only.
