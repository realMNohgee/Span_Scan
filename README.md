# Span_Scan
![CI](https://github.com/realMNohgee/Span_Scan/actions/workflows/ci.yml/badge.svg) ![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg) ![License](https://img.shields.io/badge/license-MIT-blue.svg)

**Find, merge, and gap-fill overlapping intervals — one tiny, zero-dependency CLI.**

Feed Span_Scan a pile of inclusive intervals — numbers, calendar dates, clock
times, or IP ranges (CIDR) — and it answers the questions every scheduler,
auditor, and planner keeps re-deriving by hand:

| Subcommand | Question it answers | Example output |
|---|---|---|
| `overlap` | Which pairs of intervals collide? | `1-5 overlaps 3-7 (overlap: 3-5)` |
| `merge`   | What is the minimal disjoint set? | `1-7`, `10-12` |
| `gaps`    | What empty spans sit *between* intervals? | `6-9` |
| `free`    | Given a window and busy time, what's left? | `8-8`, `13-13`, `17-18` |

Intervals are **inclusive** and treated as **discrete units** (integers, days,
minutes, addresses), so `gaps '1,5' '10,12'` → `6-9`, not an open interval.

## One tool, many domains

The same "normalize → sort → walk" engine serves every field that reasons
about spans of a comparable dimension:

| Domain | What you scan | Interval type |
|---|---|---|
| Scheduling / calendars | Meeting, shift, and room conflicts | `time` (`09:00,10:30`) |
| Capacity planning | Resource allocation overlaps | `number` (`1,5`) |
| Date-range auditing | License, lease, and warranty windows | `date` (`2024-01-01,2024-06-30`) |
| Networking / security | CIDR collision and subnet gaps | `ip` (`10.0.0.0/24`) |
| Log / timeline analysis | Event windows, request latencies | `number` / `time` |
| Genetics / genomics | Exon, read, or feature intervals | `number` |

## Install & run

Pure Python standard library — **no dependencies, no pip install**.
Works on Python 3.7+ (including the 3.9 that ships on macOS).

```bash
python3 Span_Scan.py overlap '1,5' '3,7'          # 1-5 overlaps 3-7 (overlap: 3-5)
python3 Span_Scan.py merge   '1,5' '3,7' '10,12'  # 1-7 / 10-12
python3 Span_Scan.py gaps    '1,5' '10,12'        # 6-9
python3 Span_Scan.py free    '8,18' '9,12' '14,16'  # 8-8 / 13-13 / 17-18
```

Intervals come from **positional args**, a **file**, or **stdin** — one
`START,END` (or `START END`) per line:

```bash
python3 Span_Scan.py merge -f meetings.txt
cat meetings.txt | python3 Span_Scan.py overlap --type time
```

### Options (on every subcommand, before or after the command name)

- `--type auto|number|date|time|ip` — force a type or auto-detect (default).
- `--sort` — sort intervals by start before processing.
- `--format text|json` — machine-readable output for scripts and agents.
- `-f, --file FILE` — read intervals from a file instead of args/stdin.

```bash
python3 Span_Scan.py merge '1,5' '3,7' '10,12' --format json
python3 Span_Scan.py --format json merge '1,5' '3,7' '10,12'   # either side works
```

Malformed input (bad number, `2024-13-01`, `25:00`, `999.999.999.999/8`, or
`START > END`) prints a clear error to stderr and exits nonzero — safe to use
as a CI or pipeline gate.

## Built for agentic AI

Span_Scan is one of the small, deterministic primitives agentic systems reach
for constantly: give an autonomous agent a list of busy calendar blocks and a
working window, and it needs the free spans *now*, as structured data — not a
paragraph. Every subcommand speaks `--format json` with a stable schema
(`span` / `start` / `end`), so an LLM can call it as a subprocess, parse the
JSON, and reason over conflicts, gaps, and availability without reimplementing
the merge algorithm itself. One tool, many domains: the same interval algebra
works for calendars, CIDR blocks, leases, and genomic features alike.

## License

MIT — see [LICENSE](LICENSE).

🧰 **[Tool on Hermtica Marketplace](https://hermtica.com/marketplace)**
