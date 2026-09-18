"""
Fetch the "ads" domain blocklist from a configurable list of sources.

HOW TO ADD A NEW SOURCE
------------------------
Most ad-blocklist feeds ship in one of a handful of well-known formats.
To add one, just append a `Source(...)` entry to the SOURCES list below —
no new parsing code needed:

    Source(
        name="some_new_list",
        url="https://example.com/list.txt",
        format=Format.DOMAIN_LIST,   # pick the matching format, see below
    ),

Supported formats:
  - Format.DOMAIN_LIST      Plain domain per line. `#` / `!` lines and blanks
                             are treated as comments and skipped.
  - Format.WILDCARD_LIST    Same as DOMAIN_LIST but each line may be prefixed
                             with `*.` (e.g. OISD's `*.example.com`); the
                             prefix is stripped before validation.
  - Format.ABP_BARE         AdBlock-Plus-style rules, but ONLY bare
                             `||domain^` lines are accepted (see the safety
                             note below). Anything else on the line
                             ($options, paths, @@ exceptions, etc.) is
                             rejected wholesale rather than best-effort
                             parsed.
  - Format.HOSTS_FILE       Classic `/etc/hosts` sinkhole format:
                             `0.0.0.0 example.com` or `127.0.0.1 example.com`.

If a new source ships something genuinely different (e.g. a JSON API),
write a small dedicated parser function and reference it via
Format.CUSTOM + a `parser=` callable — see `_FORMAT_PARSERS` below for
how the dispatch works.

SAFETY NOTES (do not weaken without re-reading these)
-------------------------------------------------------
- ABP_BARE uses a STRICT fullmatch: only `||domain^`, nothing else. A loose
  prefix match would silently accept `||domain^$options` and drop the
  options, turning a site-scoped rule like
  `||cloudfront.net^$domain=piratesite.io` into a GLOBAL block of all of
  CloudFront. That's exactly the bug that once broke video players
  app-wide (jwplayer.com, b-cdn.net, cdn77.org all globally blocked).
- NEVER_BLOCK is a canary of load-bearing CDN/player apexes. If any source
  — old or newly added — starts shipping one of these as an exact entry,
  the whole build hard-fails instead of silently shipping a poisoned list.
  When you add a new source, you do NOT need to touch this list; the check
  runs automatically over the merged domain set.
- Each source is best-effort: if one fails to fetch/parse, the others still
  contribute. The build only fails if ALL sources fail, or if the canary
  above trips.
"""
from __future__ import annotations

import json
import pathlib
import re
import sys
import urllib.request
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Iterable, Optional

TIMEOUT = 60
UA = "jackszb-ads-bot/1.0 (+https://github.com/jackszb/mix)"

VALID_DOMAIN = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)

# Strict ABP bare-domain matcher: only `||domain^`, nothing else.
_ABP_BARE_DOMAIN = re.compile(r"^\|\|([a-z0-9.\-]+)\^$")

# Apexes that must never appear as an exact blocklist entry.
NEVER_BLOCK = {
    "cloudfront.net", "b-cdn.net", "cdn77.org", "akamaized.net", "akamai.net",
    "fastly.net", "jsdelivr.net", "cloudflare.com", "googleusercontent.com",
    "googlevideo.com", "ytimg.com", "googleapis.com", "gstatic.com",
    "jwplayer.com", "jwpcdn.com", "imasdk.googleapis.com", "vimeocdn.com",
    "googletagmanager.com", "cloudflareinsights.com",
}


# ---------- Formats ----------

class Format(str, Enum):
    DOMAIN_LIST = "domain_list"
    WILDCARD_LIST = "wildcard_list"
    ABP_BARE = "abp_bare"
    HOSTS_FILE = "hosts_file"
    CUSTOM = "custom"


@dataclass(frozen=True)
class Source:
    name: str
    url: str
    format: Format
    # Only used when format == Format.CUSTOM: a function that takes the raw
    # fetched text and yields candidate domain strings (pre-validation).
    parser: Optional[Callable[[str], Iterable[str]]] = None


def _parse_domain_list(text: str) -> Iterable[str]:
    for line in text.splitlines():
        d = line.strip().lower().rstrip(".")
        if not d or d.startswith("#") or d.startswith("!"):
            continue
        yield d


def _parse_wildcard_list(text: str) -> Iterable[str]:
    for d in _parse_domain_list(text):
        if d.startswith("*."):
            d = d[2:]
        yield d


def _parse_abp_bare(text: str) -> Iterable[str]:
    for line in text.splitlines():
        m = _ABP_BARE_DOMAIN.match(line.strip().lower())
        if m:
            yield m.group(1)


def _parse_hosts_file(text: str) -> Iterable[str]:
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
            yield parts[1].strip().lower().rstrip(".")


_FORMAT_PARSERS: dict[Format, Callable[[str], Iterable[str]]] = {
    Format.DOMAIN_LIST: _parse_domain_list,
    Format.WILDCARD_LIST: _parse_wildcard_list,
    Format.ABP_BARE: _parse_abp_bare,
    Format.HOSTS_FILE: _parse_hosts_file,
}


# ---------- Sources ----------
# Add new ad-blocklist download links HERE. That's the only edit needed for
# any source in one of the four built-in formats.

SOURCES: list[Source] = [
    Source(
        name="oisd_big",
        url="https://big.oisd.nl/domainswild",
        format=Format.WILDCARD_LIST,
    ),
    Source(
        name="adguard_dns",
        url="https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
        format=Format.ABP_BARE,
    ),
    # Example of how to add another one:
    # Source(
    #     name="someother_ads_list",
    #     url="https://example.com/ads-hosts.txt",
    #     format=Format.HOSTS_FILE,
    # ),
]


# ---------- Fetch / validate ----------

def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        raw = resp.read()
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="ignore")


def fetch_source(source: Source) -> Iterable[str]:
    text = fetch(source.url)
    parser = source.parser if source.format == Format.CUSTOM else _FORMAT_PARSERS[source.format]
    if parser is None:
        raise ValueError(f"Source {source.name!r} uses Format.CUSTOM but no parser was given")
    for candidate in parser(text):
        if VALID_DOMAIN.match(candidate):
            yield candidate


def to_srs_json(domains: Iterable[str]) -> dict:
    """sing-box rule-set JSON format."""
    return {
        "version": 5,
        "rules": [
            {"domain_suffix": sorted(domains)}
        ],
    }


def _canary_violations(domains: set[str]) -> list[str]:
    return sorted(NEVER_BLOCK & domains)


def main() -> int:
    out_dir = pathlib.Path("rules")
    out_dir.mkdir(exist_ok=True)
    out_path = out_dir / "ads.txt"
    out_json_path = out_dir / "ads.json"

    seen: set[str] = set()
    warnings = 0

    for source in SOURCES:
        try:
            before = len(seen)
            for d in fetch_source(source):
                seen.add(d)
            print(f"  [ads] {source.name}: +{len(seen) - before} domains")
        except Exception as exc:
            warnings += 1
            print(f"  [ads] {source.name}: WARN {exc!r}", file=sys.stderr)

    violations = _canary_violations(seen)
    if violations:
        print(
            "ERROR: NEVER_BLOCK canary tripped — refusing to ship. "
            f"Offending apexes: {', '.join(violations)}",
            file=sys.stderr,
        )
        return 2

    if not seen:
        print("ERROR: zero domains collected — all sources failed", file=sys.stderr)
        return 1

    out_path.write_text("\n".join(sorted(seen)) + "\n", encoding="utf-8")
    print(f"ads: {len(seen)} unique domains -> {out_path}")

    out_json_path.write_text(
        json.dumps(to_srs_json(seen), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"ads: {len(seen)} unique domains -> {out_json_path}")

    if warnings:
        print(f"\n{warnings} source(s) failed — see WARN lines above.", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
