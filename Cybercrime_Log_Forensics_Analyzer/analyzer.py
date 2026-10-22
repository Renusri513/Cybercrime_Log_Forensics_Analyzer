"""
Cybercrime Log Forensics Analyzer
A defensive, offline tool for analyzing authentication log files.

Usage:
    python analyzer.py --input sample_auth.log --output results

Notes:
- Only analyzes a local text log file supplied by the user.
- Does not connect to any network or attempt any login.
- Heuristic findings are leads for review, not proof of malicious activity.
"""
from __future__ import annotations

import argparse
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Optional

import pandas as pd
import matplotlib.pyplot as plt

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}

# Supports common Linux/SSH syslog-style lines and ISO-style timestamps.
SYSLOG_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<message>.*)$"
)
ISO_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?\s+(?P<message>.*)$"
)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
FAILED_RE = re.compile(
    r"failed password|authentication failure|failed password|"
    r"login failed|failed login|invalid password|authentication failed",
    re.IGNORECASE
)
SUCCESS_RE = re.compile(
    r"accepted password|accepted publickey|successful login|"
    r"login successful|session opened for user",
    re.IGNORECASE
)
USER_RE = re.compile(r"\b(?:for|user=|user\s+)(?:invalid user\s+)?([A-Za-z0-9_.@-]+)", re.I)


def parse_timestamp(line: str, default_year: Optional[int] = None) -> Optional[datetime]:
    """Extract a timestamp from a log line. Syslog timestamps use the supplied year."""
    year = default_year or datetime.now().year
    iso = ISO_RE.match(line)
    if iso:
        raw = iso.group("timestamp").replace("T", " ")
        try:
            return datetime.strptime(raw, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass
    syslog = SYSLOG_RE.match(line)
    if syslog:
        try:
            month = MONTHS[syslog.group("month")]
            return datetime(year, month, int(syslog.group("day")),
                            *[int(x) for x in syslog.group("time").split(":")])
        except (ValueError, KeyError):
            return None
    return None


def extract_message(line: str) -> str:
    iso = ISO_RE.match(line)
    if iso:
        return iso.group("message")
    syslog = SYSLOG_RE.match(line)
    if syslog:
        return syslog.group("message")
    return line.strip()


def parse_line(line: str, line_number: int, default_year: Optional[int] = None) -> dict:
    timestamp = parse_timestamp(line, default_year)
    message = extract_message(line)
    lower = message.lower()

    if FAILED_RE.search(message):
        event_type = "failed_login"
    elif SUCCESS_RE.search(message):
        event_type = "successful_login"
    else:
        event_type = "other"

    ips = IP_RE.findall(message)
    ip = ips[0] if ips else "unknown"
    user_match = USER_RE.search(message)
    username = user_match.group(1) if user_match else "unknown"

    return {
        "line_number": line_number,
        "timestamp": timestamp,
        "event_type": event_type,
        "source_ip": ip,
        "username": username,
        "message": message,
        "raw_line": line.rstrip("\n"),
    }


def analyze_log(input_path: str | Path, output_dir: str | Path,
                failed_threshold: int = 5, unusual_start: int = 0,
                unusual_end: int = 5, default_year: Optional[int] = None) -> dict:
    """Analyze a local log file and save CSV reports plus a chart."""
    input_path = Path(input_path)
    output_dir = Path(output_dir)
    if not input_path.exists() or not input_path.is_file():
        raise FileNotFoundError(f"Input log file not found: {input_path}")
    if failed_threshold < 1:
        raise ValueError("failed_threshold must be at least 1")
    if not (0 <= unusual_start <= 23 and 0 <= unusual_end <= 23):
        raise ValueError("Unusual hours must be between 0 and 23")

    output_dir.mkdir(parents=True, exist_ok=True)
    with input_path.open("r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    rows = [parse_line(line, i, default_year) for i, line in enumerate(lines, start=1) if line.strip()]
    df = pd.DataFrame(rows, columns=[
        "line_number", "timestamp", "event_type", "source_ip",
        "username", "message", "raw_line"
    ])

    if df.empty:
        df.to_csv(output_dir / "event_timeline.csv", index=False)
        pd.DataFrame(columns=["source_ip", "failed_attempts", "finding"]).to_csv(
            output_dir / "suspicious_ips.csv", index=False)
        pd.DataFrame(columns=["line_number", "timestamp", "event_type", "source_ip",
                              "username", "message", "raw_line", "finding"]).to_csv(
            output_dir / "flagged_events.csv", index=False)
        (output_dir / "summary.txt").write_text("No non-empty log lines were found.\n", encoding="utf-8")
        return {"events": 0, "failed": 0, "successful": 0, "flagged_ips": 0, "output_dir": str(output_dir)}

    # Stable, chronological timeline; unparseable timestamps are placed at the end.
    df["_sort_timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.sort_values(["_sort_timestamp", "line_number"], na_position="last").drop(columns=["_sort_timestamp"])
    df.to_csv(output_dir / "event_timeline.csv", index=False)

    failed = df[df["event_type"] == "failed_login"].copy()
    successful = df[df["event_type"] == "successful_login"].copy()

    ip_counts = failed[failed["source_ip"] != "unknown"].groupby("source_ip").size().sort_values(ascending=False)
    suspicious = ip_counts[ip_counts >= failed_threshold].rename("failed_attempts").reset_index()
    suspicious["finding"] = suspicious["failed_attempts"].apply(
        lambda n: f"At least {failed_threshold} failed login attempts from this IP")
    suspicious.to_csv(output_dir / "suspicious_ips.csv", index=False)

    if unusual_start < unusual_end:
        unusual_mask = df["timestamp"].apply(
            lambda t: isinstance(t, datetime) and unusual_start <= t.hour < unusual_end)
    elif unusual_start > unusual_end:
        unusual_mask = df["timestamp"].apply(
            lambda t: isinstance(t, datetime) and (t.hour >= unusual_start or t.hour < unusual_end))
    else:
        unusual_mask = pd.Series(False, index=df.index)
    unusual = df[unusual_mask & df["event_type"].isin(["failed_login", "successful_login"])].copy()
    if not unusual.empty:
        unusual["finding"] = f"Authentication event during configured unusual hours ({unusual_start:02d}:00–{unusual_end:02d}:00)"
    flagged = pd.concat([
        failed[failed["source_ip"].isin(suspicious["source_ip"])].assign(
            finding=f"Source IP reached failed-login threshold ({failed_threshold}+ attempts)"),
        unusual
    ], ignore_index=True).drop_duplicates(subset=["line_number"]).sort_values("line_number")
    flagged.to_csv(output_dir / "flagged_events.csv", index=False)

    # Chart: counts by event type.
    counts = df["event_type"].value_counts().reindex(
        ["failed_login", "successful_login", "other"], fill_value=0)
    fig, ax = plt.subplots(figsize=(8, 4.5))
    counts.plot(kind="bar", ax=ax)
    ax.set_title("Authentication Log Event Counts")
    ax.set_xlabel("Event type")
    ax.set_ylabel("Number of log lines")
    ax.tick_params(axis="x", rotation=15)
    fig.tight_layout()
    fig.savefig(output_dir / "event_counts.png", dpi=150)
    plt.close(fig)

    top_ips = ip_counts.head(10)
    fig, ax = plt.subplots(figsize=(8, 4.5))
    if len(top_ips):
        top_ips.sort_values().plot(kind="barh", ax=ax)
        ax.set_title("Top Source IPs by Failed Login Attempts")
        ax.set_xlabel("Failed attempts")
        ax.set_ylabel("Source IP")
    else:
        ax.text(0.5, 0.5, "No failed-login source IPs found", ha="center", va="center")
        ax.set_axis_off()
    fig.tight_layout()
    fig.savefig(output_dir / "failed_attempts_by_ip.png", dpi=150)
    plt.close(fig)

    summary = [
        "CYBERCRIME LOG FORENSICS ANALYZER — SUMMARY",
        "=" * 48,
        f"Input file: {input_path.name}",
        f"Total non-empty log lines: {len(df)}",
        f"Failed-login events: {len(failed)}",
        f"Successful-login events: {len(successful)}",
        f"Other/unclassified events: {(df['event_type'] == 'other').sum()}",
        f"Source IPs meeting failed-attempt threshold ({failed_threshold}): {len(suspicious)}",
        f"Authentication events in configured unusual hours ({unusual_start:02d}:00–{unusual_end:02d}:00): {len(unusual)}",
        f"Flagged events (deduplicated): {len(flagged)}",
        "",
        "Interpretation:",
        "- Flags are heuristic leads, not proof of a cybercrime or compromise.",
        "- Confirm time zones, host configuration, NAT/shared IPs, and user context.",
        "- Preserve the original log and document how it was obtained.",
        "",
        "Generated files: event_timeline.csv, suspicious_ips.csv, flagged_events.csv,",
        "event_counts.png, failed_attempts_by_ip.png, summary.txt",
    ]
    (output_dir / "summary.txt").write_text("\n".join(summary) + "\n", encoding="utf-8")
    return {
        "events": len(df), "failed": len(failed), "successful": len(successful),
        "flagged_ips": len(suspicious), "flagged_events": len(flagged),
        "output_dir": str(output_dir)
    }


def main():
    parser = argparse.ArgumentParser(description="Offline authentication log forensics analyzer")
    parser.add_argument("--input", required=True, help="Path to a local authentication log text file")
    parser.add_argument("--output", default="results", help="Directory for reports (default: results)")
    parser.add_argument("--threshold", type=int, default=5, help="Failed logins from one IP needed to flag it")
    parser.add_argument("--unusual-start", type=int, default=0, help="Start hour for unusual window (0–23)")
    parser.add_argument("--unusual-end", type=int, default=5, help="End hour for unusual window (0–23)")
    parser.add_argument("--year", type=int, default=None, help="Year for syslog timestamps that omit a year")
    args = parser.parse_args()
    result = analyze_log(args.input, args.output, args.threshold,
                         args.unusual_start, args.unusual_end, args.year)
    print("Analysis complete.")
    for key, value in result.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    main()
