# pip-report-audit

[![tests](https://github.com/maomao-1937/pip-report-audit/actions/workflows/tests.yml/badge.svg)](https://github.com/maomao-1937/pip-report-audit/actions/workflows/tests.yml)

Audit a saved pip installation report against a small, explicit artifact-source
policy. The CLI runs offline with Python 3.11+ and the standard library. It reads
the two files you name and emits codes, item ordinals, and counts. It does not
install packages, contact hosts, start processes, or write output files.

## Run from source

Download or clone this repository, open its directory, and run:

```console
python pip_report_audit.py examples/clean.json --policy examples/policy.json --json
```

No dependency installation or package-manager step is needed. On Windows,
`py -3.11` can replace `python` when that interpreter is installed. Verified on
Windows with CPython 3.11.15; other platforms are intended but unverified here.

Synthetic input examples are included; no package is downloaded when running them.
The command above produces:

```json
{"code":"CLEAN","items":1,"requested_count":1,"direct_count":0,"origin_counts":{"archive":1,"vcs":0,"local":0},"finding_count":0,"findings":[]}
```

```console
python pip_report_audit.py examples/yanked.json --policy examples/policy.json
```

```text
FINDINGS items=1 findings=1
requested=1 direct=0 archive=1 vcs=0 local=0
item=1 YANKED
```

The second command exits 1. `examples/foreign.json` produces
`HOST_NOT_ALLOWED`; `examples/malformed.json` exits 2 with `INVALID_INPUT`.
All digests in examples are invented format examples.

## Policy

```json
{
  "allowed_hosts": ["files.example.test"],
  "allow_yanked": false,
  "allow_vcs": false,
  "allow_local": false
}
```

`allowed_hosts` is required and compares lowercase ASCII DNS names exactly.
An empty list denies all HTTPS archives. Subdomains are separate entries;
wildcards, URL strings, duplicate normalized names, IP literals, numeric/hex
address forms, empty labels, and trailing dots are unsupported. The three flags
are optional booleans defaulting to false. Unknown policy keys fail closed.

For remote archives, the supported URL profile requires HTTPS and a DNS authority
with no credentials, explicit port (including 443), fragment, backslash, raw
non-ASCII, whitespace, control character, invalid percent escape, or
percent-encoded ASCII whitespace/control/backslash. Punycode ASCII labels may be
listed explicitly; Unicode hosts are unsupported. Query strings are accepted
but never emitted. There is no suffix matching or network resolution.

`archive_info` requires a recorded SHA-256 for a clean result. A missing SHA-256
is a policy finding; a present malformed digest is invalid input. Digests must
be nonempty even-length hex; SHA-256 must contain 64 hex characters. The legacy
`hash` string is accepted and must agree with `hashes` when both are present.
Other recorded algorithms do not satisfy the SHA-256 policy. No artifact bytes
are read, so this validates recorded digest format only.

VCS references default to `VCS_DISALLOWED`. Opting in accepts HTTPS or local
`file:///` references with `vcs` in `git`, `hg`, `bzr`, `svn`, a nonempty string
`commit_id`, and an optional nonempty string `requested_revision`. This checks
record shape; it does not prove revision immutability, pinning, or repository
contents. The archive host allowlist does not apply to VCS hosts.

Local archive/directory/VCS sources default to `LOCAL_DISALLOWED`. Opting in
supports absolute `file:///` URLs with empty authority, a non-root path, and no
query or fragment; network shares and relative paths are unsupported. The path
must begin with exactly one slash before and after percent decoding, rejecting
UNC/share ambiguity such as `file:////server/share`, `file://///server/share`,
and `file:///%2fserver/share`. URL paths are examined as text and never opened. Local
archives still need a recorded SHA-256. Local directories require `dir_info`;
optional `editable` must be boolean and defaults false. Local VCS sources need
both opt-ins. A direct HTTPS archive is accepted when the ordinary archive
policy passes, regardless of `is_direct`.

## Output and limits

| Exit | Meaning |
| --- | --- |
| 0 | `CLEAN`: all supported records satisfy policy, including empty install lists |
| 1 | `FINDINGS`: one or more policy findings |
| 2 | `INVALID_INPUT`: invalid/unsupported input, usage, or read failure; also output failure |

Finding codes are `YANKED`, `SHA256_MISSING`, `HOST_NOT_ALLOWED`,
`VCS_DISALLOWED`, and `LOCAL_DISALLOWED`. Items are numbered from 1 in input
order. Both clean and findings results include `items`, `requested_count`
(records with `requested=true`), `direct_count` (records with `is_direct=true`),
and `origin_counts`. The latter partitions records by their source-info field:
`archive` counts `archive_info`, `vcs` counts `vcs_info`, and `local` counts
`dir_info` (local directories). A `file:///` archive still counts as `archive`,
and a local VCS reference still counts as `vcs`; `local` is not a count of all
file-scheme URLs. Origin counts sum to `items`. Requested/direct counts may
overlap and do not count findings. Empty reports emit all coverage counts as
zero; invalid input emits no partial counts. Human output uses the same
semantics with `requested`, `direct`, `archive`, `vcs`, and `local` labels.
Output never includes supplied URLs, hostnames, paths, package metadata,
CLI values, or exception text. `--help` prints only static syntax and exit codes.
If stdout fails, including its final flush or help output, exit 2 is returned
without a traceback; delivery of a diagnostic cannot be promised on a broken pipe.

Each UTF-8 JSON file is limited to 4 MiB, nesting to 32 levels (root counts as
one, keys/values add one), and the report to 10,000 install items. Duplicate
keys, nonfinite numbers including numeric overflow, lone surrogates, malformed
UTF-8/JSON, and unsupported report versions are rejected. Only version string
`"1"` is supported. Required report basics are `pip_version`, string-valued
`environment`, and `install`; each item requires nonempty metadata `name` and
`version`, three boolean flags, and exactly one source-info dictionary.
Known optional `requested_extras` and `subdirectory` fields are shape checked.
Unknown report/metadata fields are allowed for forward compatibility, still
subject to JSON limits. This is a documented subset validator, not a complete
implementation of all packaging specifications.

An allowed host identifies the recorded **artifact host**, not the original
index. A clean result does not verify index origin, DNS, certificates, redirects,
downloaded bytes, installed state, vulnerabilities, or the truth of a report.
Reports can be forged. This tool cannot establish package trust or prove that
dependency confusion did not occur.

## Tests and references

```console
python -m unittest discover -s tests -v
```

See [TESTING.md](TESTING.md) for observed RED/GREEN results and
[RESEARCH.md](RESEARCH.md) for primary sources and alternatives. MIT license.

## 中文说明

这是一个离线的 pip 安装报告策略检查器，要求 Python 3.11 及以上，无第三方依赖。
下载源码后，在项目目录运行上面的命令即可。示例完全合成，不会联网或安装软件。

策略必须提供 `allowed_hosts`，按小写 ASCII DNS 主机名精确匹配，不会自动放行子域名。
默认禁止撤回版本、VCS 和本地来源；可用三个布尔配置明确放行。远程归档仅支持
文档列出的严格 HTTPS URL 范围，禁止凭据、显式端口、片段等形式。合法的直接
归档 URL 不会仅因 `is_direct=true` 被拒绝。

退出码 0 表示策略通过，1 表示存在策略问题，2 表示输入不合法、不受支持、读取
或输出失败。输出只包含固定代码、条目序号和数量，不回显包名、版本、主机、URL、
路径或参数。JSON 每文件最多 4 MiB、最多 32 层、最多 10,000 个安装条目。

正常结果和策略问题结果都包含总条目数、显式请求数、直接引用数及三类来源数。
`origin_counts` 中 `archive`、`vcs`、`local` 分别按 `archive_info`、`vcs_info`、
`dir_info` 统计，其中 `local` 专指本地目录，不包含本地归档和本地 VCS；三项之和
等于总条目数。空报告的统计全部为零。即使允许本地来源，也会拒绝路径在原始形式
或百分号解码后以双斜杠开头的 UNC/网络共享歧义形式；不会实际访问 URL 路径。

SHA-256 检查只验证报告记录的格式，不核对文件内容。VCS 的提交字段只做结构检查，
不证明已固定不可变版本。允许的主机是归档下载主机，不代表索引来源，也不验证证书、
漏洞或报告真实性。实际验证环境为 Windows / CPython 3.11.15。
