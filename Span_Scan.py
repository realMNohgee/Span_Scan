from __future__ import annotations

"""Span_Scan — find, merge, and gap-fill overlapping intervals.

A zero-dependency interval algebra for the agentic-AI toolchain. Feed it any
list of inclusive intervals — numbers, calendar dates (YYYY-MM-DD), clock
times (HH:MM), or IP ranges (CIDR) — and it will:

  overlap   report every pair of intervals that intersect
  merge     collapse overlapping intervals into a minimal disjoint set
  gaps      report the empty spans *between* intervals
  free      given busy intervals and a containing window, report the free spans

Domains: scheduling · calendars · networking · log analysis · capacity planning.
"""

import argparse
import ipaddress
import json
import re
import sys
from datetime import date

# ---------------------------------------------------------------------------
# Token / type classification (used by --type auto)
# ---------------------------------------------------------------------------

DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")          # 2024-01-31
TIME_RE = re.compile(r"^\d{1,2}:\d{2}$")              # 9:00 or 09:00
IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")      # 10.0.0.1
IP_DASH_RE = re.compile(
    r"^\d{1,3}(\.\d{1,3}){3}\s*-\s*\d{1,3}(\.\d{1,3}){3}$"
)                                                     # 10.0.0.1-10.0.0.5


def _classify_line(line: str) -> str:
    """Guess the interval type of one raw input line."""
    s = line.strip()
    if "/" in s:                       # CIDR like 10.0.0.0/8
        return "ip"
    if IP_DASH_RE.match(s):            # explicit IP range with a dash
        return "ip"
    # Endpoints are separated by a comma or whitespace (never by '-').
    parts = [p for p in re.split(r"[,\s]+", s) if p]
    for p in parts:
        if IPV4_RE.match(p):
            return "ip"
        if ":" in p and not TIME_RE.match(p):   # bare IPv6 (has colons)
            return "ip"
    for p in parts:
        if DATE_RE.match(p):
            return "date"
    for p in parts:
        if TIME_RE.match(p):
            return "time"
    return "number"


def detect_type(lines: list[str]) -> str:
    """Pick one type that fits every line (ip > date > time > number)."""
    for candidate in ("ip", "date", "time"):
        if any(_classify_line(line) == candidate for line in lines):
            return candidate
    return "number"


# ---------------------------------------------------------------------------
# Endpoint normalization: every type becomes a comparable integer/float key.
# ---------------------------------------------------------------------------

def _normalize_endpoint(token: str, itype: str) -> "int | float":
    """Convert a single START/END token to its comparable key."""
    if itype == "number":
        return float(token)                       # raises ValueError if bogus
    if itype == "date":
        return date.fromisoformat(token).toordinal()   # days since 0001-01-01
    if itype == "time":
        m = re.fullmatch(r"(\d{1,2}):(\d{2})", token)
        if not m:
            raise ValueError(f"expected HH:MM, got {token!r}")
        hh, mm = int(m.group(1)), int(m.group(2))
        if hh > 23 or mm > 59:
            raise ValueError(f"out of range HH:MM: {token!r}")
        return hh * 60 + mm                        # minutes since midnight
    if itype == "ip":
        return _as_ip_int(token)
    raise ValueError(f"unknown type {itype!r}")


def _as_ip_int(token: str) -> int:
    """Parse an IP address string to its integer, requiring a dot or colon."""
    if not re.search(r"[.:]", token):
        raise ValueError(f"not an IP address: {token!r}")
    return int(ipaddress.ip_address(token))


def _fmt_key(value: "int | float", itype: str) -> str:
    """Render a normalized key back to a human-readable string."""
    if itype == "date":
        return date.fromordinal(int(value)).isoformat()
    if itype == "time":
        return f"{int(value) // 60:02d}:{int(value) % 60:02d}"
    if itype == "ip":
        return str(ipaddress.ip_address(int(value)))
    return _fmt_number(value)


def _fmt_number(value: "int | float") -> str:
    """Print a float without trailing zeros (3.0 -> '3')."""
    if isinstance(value, float) and value == int(value):
        return str(int(value))
    return ("%.15g" % value) if isinstance(value, float) else str(value)


def _fmt_span(start: "int | float", end: "int | float", itype: str) -> str:
    """Format an inclusive interval as 'START-END'."""
    return f"{_fmt_key(start, itype)}-{_fmt_key(end, itype)}"


# ---------------------------------------------------------------------------
# Interval model
# ---------------------------------------------------------------------------

class Interval:
    """A single inclusive interval, already normalized to comparable keys."""
    __slots__ = ("start", "end")

    def __init__(self, start: "int | float", end: "int | float"):
        self.start = start
        self.end = end

    def __repr__(self) -> str:
        return f"Interval({self.start!r}, {self.end!r})"


def parse_interval(line: str, itype: str) -> Interval:
    """Parse one raw line ('START,END' or 'START END') into an Interval."""
    s = line.strip()
    if not s:
        raise ValueError("empty interval")
    if itype == "ip":
        return _parse_ip_interval(s)
    parts = [p for p in re.split(r"[,\s]+", s) if p]
    if len(parts) != 2:
        raise ValueError(f"expected START,END (or 'START END'), got {line!r}")
    start = _normalize_endpoint(parts[0], itype)
    end = _normalize_endpoint(parts[1], itype)
    if start > end:
        raise ValueError(f"start is after end: {line!r}")
    return Interval(start, end)


def _parse_ip_interval(s: str) -> Interval:
    """Parse an IP interval: CIDR, a single address, or two addresses."""
    if "/" in s:
        net = ipaddress.ip_network(s, strict=False)   # CIDR -> full range
        return Interval(int(net.network_address), int(net.broadcast_address))
    parts = [p for p in re.split(r"[,\s-]+", s) if p]
    if len(parts) == 1:                                # single address
        a = _as_ip_int(parts[0])
        return Interval(a, a)
    if len(parts) == 2:                                # explicit range
        a, b = _as_ip_int(parts[0]), _as_ip_int(parts[1])
        return Interval(min(a, b), max(a, b))
    raise ValueError(f"expected CIDR, IP, or two IPs: {s!r}")


# ---------------------------------------------------------------------------
# Core interval algorithms (inclusive endpoints, discrete unit step)
# ---------------------------------------------------------------------------

def merge_intervals(intervals: list[Interval]) -> list[Interval]:
    """Collapse overlapping/touching intervals into a minimal disjoint set."""
    if not intervals:
        return []
    ordered = sorted(intervals, key=lambda iv: (iv.start, iv.end))
    merged = [Interval(ordered[0].start, ordered[0].end)]
    for iv in ordered[1:]:
        current = merged[-1]
        if iv.start <= current.end:          # overlap or touch -> extend
            current.end = max(current.end, iv.end)
        else:                                # disjoint -> start a new span
            merged.append(Interval(iv.start, iv.end))
    return merged


def compute_gaps(intervals: list[Interval]) -> list[Interval]:
    """Return the empty spans between merged intervals (inclusive)."""
    merged = merge_intervals(intervals)
    gaps = []
    for prev, nxt in zip(merged, merged[1:]):
        if nxt.start > prev.end + 1:         # at least one free unit between
            gaps.append(Interval(prev.end + 1, nxt.start - 1))
    return gaps


def compute_free(busy: list[Interval],
                 window: tuple[int, int]) -> list[Interval]:
    """Free spans inside `window` not covered by any busy interval."""
    wstart, wend = window
    # Clip every busy interval to the window; drop ones fully outside.
    clipped = []
    for iv in busy:
        s, e = max(iv.start, wstart), min(iv.end, wend)
        if s <= e:
            clipped.append(Interval(s, e))
    free_spans = []
    cursor = wstart
    for iv in merge_intervals(clipped):
        if cursor < iv.start:
            free_spans.append(Interval(cursor, iv.start - 1))
        cursor = iv.end + 1
    if cursor <= wend:
        free_spans.append(Interval(cursor, wend))
    return free_spans


# ---------------------------------------------------------------------------
# Input plumbing
# ---------------------------------------------------------------------------

def _die(msg: str) -> "NoReturn":
    """Print an error to stderr and exit nonzero."""
    print(f"error: {msg}", file=sys.stderr)
    raise SystemExit(1)


def collect_lines(args: argparse.Namespace) -> list[str]:
    """Gather raw interval lines from --file, positional args, or stdin."""
    lines = []
    if getattr(args, "file", None):
        try:
            with open(args.file, "r") as fh:
                lines = [ln.strip() for ln in fh if ln.strip()]
        except OSError as exc:
            _die(f"cannot read {args.file}: {exc}")
    if getattr(args, "intervals", None):
        lines.extend(args.intervals)
    if not lines and not sys.stdin.isatty():     # piped stdin fallback
        lines = [ln.strip() for ln in sys.stdin if ln.strip()]
    return lines


def _resolve_type(lines: list[str], itype: str) -> str:
    """Resolve 'auto' to a concrete type; pass explicit types through."""
    return detect_type(lines) if itype == "auto" else itype


def _load_intervals(args: argparse.Namespace) -> tuple[list[Interval], str]:
    """Read + normalize all intervals (dies on the first malformed line)."""
    lines = collect_lines(args)
    if not lines:
        _die("no intervals provided (positional args, --file, or stdin)")
    itype = _resolve_type(lines, args.type)
    intervals = []
    for line in lines:
        try:
            intervals.append(parse_interval(line, itype))
        except (ValueError, ipaddress.AddressValueError) as exc:
            _die(f"bad interval {line!r}: {exc}")
    return intervals, itype


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def _span_dict(start: "int | float", end: "int | float",
               itype: str) -> dict:
    """JSON object for one interval/span."""
    return {"span": _fmt_span(start, end, itype),
            "start": start, "end": end}


def _emit_spans(spans: list[Interval], itype: str, fmt: str) -> None:
    """Emit a list of spans in text or JSON form."""
    if fmt == "json":
        json.dump([_span_dict(s.start, s.end, itype) for s in spans],
                  sys.stdout, indent=2)
        sys.stdout.write("\n")
        return
    for s in spans:
        print(_fmt_span(s.start, s.end, itype))


def _emit_pairs(pairs: list[tuple[str, str, str]], fmt: str) -> None:
    """Emit overlapping pairs (a, b, overlap) in text or JSON form."""
    if fmt == "json":
        json.dump([{"a": a, "b": b, "overlap": o} for a, b, o in pairs],
                  sys.stdout, indent=2)
        sys.stdout.write("\n")
        return
    for a, b, o in pairs:
        print(f"{a} overlaps {b} (overlap: {o})")


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------

def cmd_overlap(args: argparse.Namespace) -> int:
    intervals, itype = _load_intervals(args)
    if args.sort:
        intervals.sort(key=lambda iv: (iv.start, iv.end))
    pairs = []
    for i in range(len(intervals)):
        for j in range(i + 1, len(intervals)):
            a, b = intervals[i], intervals[j]
            if a.start <= b.end and b.start <= a.end:   # inclusive overlap
                ov_start = max(a.start, b.start)
                ov_end = min(a.end, b.end)
                pairs.append((_fmt_span(a.start, a.end, itype),
                              _fmt_span(b.start, b.end, itype),
                              _fmt_span(ov_start, ov_end, itype)))
    _emit_pairs(pairs, args.format)
    return 0


def cmd_merge(args: argparse.Namespace) -> int:
    intervals, itype = _load_intervals(args)
    _emit_spans(merge_intervals(intervals), itype, args.format)
    return 0


def cmd_gaps(args: argparse.Namespace) -> int:
    intervals, itype = _load_intervals(args)
    _emit_spans(compute_gaps(intervals), itype, args.format)
    return 0


def cmd_free(args: argparse.Namespace) -> int:
    lines = collect_lines(args)
    itype = _resolve_type(lines + [args.window], args.type)
    try:
        window = _parse_window(args.window, itype)
    except (ValueError, ipaddress.AddressValueError) as exc:
        _die(f"bad window {args.window!r}: {exc}")
    busy = []
    for line in lines:
        try:
            busy.append(parse_interval(line, itype))
        except (ValueError, ipaddress.AddressValueError) as exc:
            _die(f"bad interval {line!r}: {exc}")
    if args.sort:
        busy.sort(key=lambda iv: (iv.start, iv.end))
    _emit_spans(compute_free(busy, window), itype, args.format)
    return 0


def _parse_window(wstr: str, itype: str) -> tuple[int, int]:
    """Parse a containing window 'START,END' (or CIDR / two IPs for ip)."""
    s = wstr.strip()
    if itype == "ip":
        if "/" in s:
            net = ipaddress.ip_network(s, strict=False)
            return int(net.network_address), int(net.broadcast_address)
        parts = [p for p in re.split(r"[,\s]+", s) if p]
        if len(parts) == 1:
            a = _as_ip_int(parts[0])
            return a, a
        if len(parts) == 2:
            a, b = _as_ip_int(parts[0]), _as_ip_int(parts[1])
            return min(a, b), max(a, b)
        raise ValueError(f"expected CIDR or two IPs: {wstr!r}")
    parts = [p for p in re.split(r"[,\s]+", s) if p]
    if len(parts) != 2:
        raise ValueError(f"expected START,END, got {wstr!r}")
    start = _normalize_endpoint(parts[0], itype)
    end = _normalize_endpoint(parts[1], itype)
    if start > end:
        raise ValueError(f"window start is after end: {wstr!r}")
    return start, end   # keys are already the right int/float type


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="Span_Scan",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version="Span_Scan 1.0.0")

    # --format / --type / --sort are declared on BOTH the top-level parser and
    # the shared parent so they work before OR after the subcommand name. The
    # parent copies use default=argparse.SUPPRESS so their "default" never
    # clobbers a value the top-level parser already captured (the classic
    # argparse double-default footgun).
    parser.add_argument("--format", choices=["text", "json"], default="text",
                        help="output format: text or json (default: text)")
    parser.add_argument("--type", choices=["auto", "number", "date", "time",
                                           "ip"], default="auto",
                        help="interval type (default: auto-detect)")
    parser.add_argument("--sort", action="store_true",
                        help="sort intervals by start before processing")

    # Shared parent parser: every subcommand inherits these flags.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--format", choices=["text", "json"],
                        default=argparse.SUPPRESS,
                        help="output format: text or json (default: text)")
    common.add_argument("--type", choices=["auto", "number", "date", "time",
                                           "ip"], default=argparse.SUPPRESS,
                        help="interval type (default: auto-detect)")
    common.add_argument("--sort", action="store_true",
                        default=argparse.SUPPRESS,
                        help="sort intervals by start before processing")
    common.add_argument("-f", "--file",
                        help="read intervals from FILE (one per line)")

    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("overlap", parents=[common],
                       help="report every overlapping pair of intervals")
    p.add_argument("intervals", nargs="*", help="interval args, e.g. '1,5' '3,7'")
    p.set_defaults(func=cmd_overlap)

    p = sub.add_parser("merge", parents=[common],
                       help="merge overlapping intervals into a disjoint set")
    p.add_argument("intervals", nargs="*", help="interval args, e.g. '1,5' '3,7'")
    p.set_defaults(func=cmd_merge)

    p = sub.add_parser("gaps", parents=[common],
                       help="report the gaps between intervals")
    p.add_argument("intervals", nargs="*", help="interval args, e.g. '1,5' '10,12'")
    p.set_defaults(func=cmd_gaps)

    p = sub.add_parser("free", parents=[common],
                       help="report free spans inside a window minus busy time")
    p.add_argument("window", help="containing window, e.g. '8,18'")
    p.add_argument("intervals", nargs="*", help="busy intervals, e.g. '9,12' '14,16'")
    p.set_defaults(func=cmd_free)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
