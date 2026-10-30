#!/usr/bin/env python3
"""Offline policy checks for the supported subset of pip report version 1."""

import ipaddress
import json
import math
import re
import sys
from urllib.parse import unquote_to_bytes, urlsplit

MAX_BYTES = 4 * 1024 * 1024
MAX_DEPTH = 32
MAX_ITEMS = 10000
_LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z', re.ASCII)
_HEX = re.compile(r'[0-9a-fA-F]+\Z', re.ASCII)
_HASH_NAME = re.compile(r'[a-z][a-z0-9_]*\Z', re.ASCII)
_BAD_PERCENT = re.compile(r'%(?![0-9a-fA-F]{2})')


class InvalidInput(Exception):
    """Invalid, unsupported, or unreadable input; never includes supplied data."""


def _require(condition):
    if not condition:
        raise InvalidInput()


def _text(value):
    return isinstance(value, str) and bool(value.strip())


def _tree(value):
    pending = [(value, 1)]
    while pending:
        obj, depth = pending.pop()
        _require(depth <= MAX_DEPTH)
        if isinstance(obj, str):
            _require(not any(0xD800 <= ord(char) <= 0xDFFF for char in obj))
        elif isinstance(obj, dict):
            _require(all(isinstance(key, str) for key in obj))
            pending.extend((key, depth + 1) for key in obj)
            pending.extend((child, depth + 1) for child in obj.values())
        elif isinstance(obj, list):
            pending.extend((child, depth + 1) for child in obj)
        elif isinstance(obj, float):
            _require(math.isfinite(obj))


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result)
        result[key] = value
    return result


def _constant(_value):
    raise InvalidInput()


def decode_json(raw):
    """Decode bounded UTF-8 JSON, rejecting ambiguous keys and unsafe text."""
    _require(isinstance(raw, bytes) and len(raw) <= MAX_BYTES)
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
                           parse_constant=_constant)
        _tree(value)
        return value
    except (ValueError, UnicodeError, RecursionError):
        raise InvalidInput() from None


def read_json(path):
    """Read only the named file, at most MAX_BYTES plus one sentinel byte."""
    try:
        with open(path, 'rb') as stream:
            return decode_json(stream.read(MAX_BYTES + 1))
    except (OSError, ValueError):
        raise InvalidInput() from None


def _host(value):
    _require(isinstance(value, str) and value.isascii())
    value = value.lower()
    _require(0 < len(value) <= 253 and not value.endswith('.'))
    _require(all(_LABEL.fullmatch(label) for label in value.split('.')))
    _require(not all(char.isdigit() or char == '.' for char in value))
    # Numeric IPs and abbreviated numeric forms are outside this DNS profile.
    _require(not value.split('.')[-1].isdigit())
    _require(not re.fullmatch(r'0x[0-9a-f]+', value.split('.')[-1]))
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise InvalidInput()


def _policy(value):
    _require(isinstance(value, dict))
    _require(set(value) <= {'allowed_hosts', 'allow_yanked', 'allow_vcs', 'allow_local'})
    _require(isinstance(value.get('allowed_hosts'), list))
    hosts = [_host(host) for host in value['allowed_hosts']]
    _require(len(set(hosts)) == len(hosts))
    result = {'allowed_hosts': set(hosts)}
    for option in ('allow_yanked', 'allow_vcs', 'allow_local'):
        flag = value.get(option, False)
        _require(type(flag) is bool)
        result[option] = flag
    return result


def _url(value):
    _require(_text(value) and value.isascii())
    _require(not any(ord(char) <= 32 or ord(char) == 127 for char in value))
    _require('\\' not in value and '#' not in value and not _BAD_PERCENT.search(value))
    decoded = unquote_to_bytes(value)
    _require(not any(char <= 32 or char == 127 for char in decoded))
    _require(b'\\' not in decoded)
    try:
        parts = urlsplit(value)
        if parts.scheme == 'https':
            _require(value.lower().startswith('https://'))
            _require(parts.netloc and '@' not in parts.netloc and ':' not in parts.netloc)
            host = _host(parts.netloc)
            _require(parts.hostname is not None and parts.hostname.lower() == host)
            return 'https', host
        if parts.scheme == 'file':
            _require(value.lower().startswith('file:///'))
            _require(not parts.netloc and parts.path.startswith('/') and len(parts.path) > 1)
            _require(not parts.path.startswith('//'))
            _require(not unquote_to_bytes(parts.path).startswith(b'//'))
            _require(not parts.query and '?' not in value)
            return 'file', None
    except (ValueError, UnicodeError):
        raise InvalidInput() from None
    raise InvalidInput()


def _hash_pair(name, digest):
    _require(isinstance(name, str) and _HASH_NAME.fullmatch(name))
    _require(isinstance(digest, str) and bool(_HEX.fullmatch(digest)) and len(digest) % 2 == 0)
    if name == 'sha256':
        _require(len(digest) == 64)
    return digest.lower()


def _archive(info):
    _require(isinstance(info, dict))
    hashes = info.get('hashes', {})
    _require(isinstance(hashes, dict))
    normalized = {name: _hash_pair(name, digest) for name, digest in hashes.items()}
    if 'hash' in info:
        legacy = info['hash']
        _require(isinstance(legacy, str) and legacy.count('=') == 1)
        name, digest = legacy.split('=')
        digest = _hash_pair(name, digest)
        if 'hashes' in info:
            _require(normalized.get(name) == digest)
        else:
            normalized[name] = digest
    return 'sha256' in normalized


def audit(report, policy):
    """Return data-free findings; raise InvalidInput for unsupported shapes."""
    _tree(report)
    _tree(policy)
    config = _policy(policy)
    _require(isinstance(report, dict) and report.get('version') == '1')
    _require(_text(report.get('pip_version')))
    environment = report.get('environment')
    _require(isinstance(environment, dict) and all(isinstance(v, str) for v in environment.values()))
    items = report.get('install')
    _require(isinstance(items, list) and len(items) <= MAX_ITEMS)
    findings = []
    requested_count = 0
    direct_count = 0
    origin_counts = {'archive': 0, 'vcs': 0, 'local': 0}
    for ordinal, item in enumerate(items, 1):
        _require(isinstance(item, dict))
        metadata = item.get('metadata')
        _require(isinstance(metadata, dict) and _text(metadata.get('name')) and _text(metadata.get('version')))
        _require(all(type(item.get(flag)) is bool for flag in ('is_direct', 'is_yanked', 'requested')))
        if 'requested_extras' in item:
            extras = item['requested_extras']
            _require(item['requested'] and isinstance(extras, list) and all(_text(extra) for extra in extras))
        source = item.get('download_info')
        _require(isinstance(source, dict))
        if 'subdirectory' in source:
            _require(_text(source['subdirectory']))
        kinds = [key for key in ('archive_info', 'vcs_info', 'dir_info') if key in source]
        _require(len(kinds) == 1)
        kind = kinds[0]
        info = source[kind]
        _require(isinstance(info, dict))
        scheme, host = _url(source.get('url'))
        codes = []
        if item['is_yanked'] and not config['allow_yanked']:
            codes.append('YANKED')
        if kind == 'archive_info':
            if not _archive(info):
                codes.append('SHA256_MISSING')
            if scheme == 'https' and host not in config['allowed_hosts']:
                codes.append('HOST_NOT_ALLOWED')
        elif kind == 'vcs_info':
            _require(info.get('vcs') in ('git', 'hg', 'bzr', 'svn'))
            _require(_text(info.get('commit_id')))
            if 'requested_revision' in info:
                _require(_text(info['requested_revision']))
            if not config['allow_vcs']:
                codes.append('VCS_DISALLOWED')
        else:
            _require(scheme == 'file')
            _require(type(info.get('editable', False)) is bool)
        if scheme == 'file' and not config['allow_local']:
            codes.append('LOCAL_DISALLOWED')
        requested_count += int(item['requested'])
        direct_count += int(item['is_direct'])
        origin = {'archive_info': 'archive', 'vcs_info': 'vcs', 'dir_info': 'local'}[kind]
        origin_counts[origin] += 1
        findings.extend({'item': ordinal, 'code': code} for code in codes)
    return {'items': len(items), 'requested_count': requested_count, 'direct_count': direct_count,
            'origin_counts': origin_counts, 'findings': findings}


HELP = ('USAGE: python pip_report_audit.py REPORT --policy POLICY [--json]\n'
        'EXIT_CODES: 0 CLEAN; 1 FINDINGS; 2 INVALID_INPUT_OR_OUTPUT\n')


def _args(args):
    values = {}
    as_json = False
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == '--json' and not as_json:
            as_json = True
        elif arg == '--policy' and 'policy' not in values and index + 1 < len(args):
            index += 1
            _require(not args[index].startswith('-'))
            values['policy'] = args[index]
        elif not arg.startswith('-') and 'report' not in values:
            values['report'] = arg
        else:
            raise InvalidInput()
        index += 1
    _require(set(values) == {'report', 'policy'})
    return values, as_json


def main(args=None):
    args = sys.argv[1:] if args is None else args
    try:
        if args == ['--help']:
            output, status = HELP, 0
        else:
            as_json = '--json' in args
            try:
                values, as_json = _args(args)
                result = audit(read_json(values['report']), read_json(values['policy']))
                status = int(bool(result['findings']))
                payload = {'code': 'FINDINGS' if status else 'CLEAN', 'items': result['items'],
                           'requested_count': result['requested_count'], 'direct_count': result['direct_count'],
                           'origin_counts': result['origin_counts'],
                           'finding_count': len(result['findings']), 'findings': result['findings']}
            except (InvalidInput, OSError, RecursionError):
                payload, status = {'code': 'INVALID_INPUT'}, 2
            if as_json:
                output = json.dumps(payload, separators=(',', ':')) + '\n'
            elif status == 2:
                output = 'INVALID_INPUT\n'
            else:
                output = f"{payload['code']} items={payload['items']} findings={payload['finding_count']}\n"
                origins = payload['origin_counts']
                output += (f"requested={payload['requested_count']} direct={payload['direct_count']} "
                           f"archive={origins['archive']} vcs={origins['vcs']} local={origins['local']}\n")
                output += ''.join(f"item={entry['item']} {entry['code']}\n" for entry in payload['findings'])
        sys.stdout.write(output)
        sys.stdout.flush()
        return status
    except (OSError, UnicodeError, ValueError):
        # Prevent interpreter shutdown from retrying a failed flush and printing
        # an exception. No replacement file, device, or log is opened.
        sys.stdout = None
        return 2


if __name__ == '__main__':
    sys.exit(main())
