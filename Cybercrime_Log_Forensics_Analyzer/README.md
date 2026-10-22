# Cybercrime Log Forensics Analyzer

A beginner-friendly, offline Python project that analyzes authentication logs to help an investigator triage suspicious activity and reconstruct an event timeline.

## Features

- Detect common failed and successful authentication messages.
- Count repeated failed login attempts by source IP.
- Flag source IPs meeting a configurable failed-login threshold.
- Highlight authentication events during a configurable unusual-hours window.
- Sort events chronologically when timestamps can be parsed.
- Export a CSV timeline, flagged events, suspicious IP summary, text summary, and charts.
- Includes a small synthetic sample log for safe demonstration.

## Technologies

- Python 3.10+
- Pandas
- Matplotlib
- Regular expressions (`re`)
- `argparse`, `pathlib`, and `datetime` from the Python standard library
- Jupyter Notebook (optional, for the notebook version)

## Dataset / sample data

The included `sample_auth.log` is synthetic demonstration data. The IP addresses use documentation ranges and are not intended to identify real attackers.

For real-world use, analyze only logs you are authorized to access. You can also use your own sanitized authentication log file. Do not upload sensitive logs publicly.

## Setup

1. Install Python 3.10 or newer.
2. Open a terminal in this project folder.
3. (Recommended) Create and activate a virtual environment.
4. Install dependencies:

   ```bash
   python -m pip install -r requirements.txt
   ```

## Run the analyzer

```bash
python analyzer.py --input sample_auth.log --output results
```

Optional settings:

```bash
python analyzer.py --input sample_auth.log --output results --threshold 5 --unusual-start 0 --unusual-end 5 --year 2026
```

- `--threshold`: number of failed logins from one IP required to flag it.
- `--unusual-start` and `--unusual-end`: start and end hours for the unusual-hours window (24-hour clock). The default window is 00:00–05:00.
- `--year`: year used for syslog timestamps, which usually omit the year.

## Output files

The `results/` folder contains:

- `event_timeline.csv` — parsed log lines sorted by timestamp where possible.
- `suspicious_ips.csv` — source IPs that meet the failed-login threshold.
- `flagged_events.csv` — failed login events from flagged IPs and authentication events in the unusual-hours window.
- `summary.txt` — counts, settings, and interpretation notes.
- `event_counts.png` — bar chart of event types.
- `failed_attempts_by_ip.png` — chart of failed attempts by source IP.

## Notebook

Open `YourName_CybercrimeLogForensics.ipynb` in Jupyter and run the cells from top to bottom. The notebook uses the included sample log by default. Change `INPUT_FILE` to analyze another authorized text log.

## Important limitations

- Log formats differ across operating systems and services. This prototype recognizes common Linux SSH-style messages and ISO-style timestamps; it may not parse every format.
- Syslog timestamps often omit the year and time zone. Supply the correct year and confirm the host's time zone before interpreting a timeline.
- A shared IP, automated service, or mistyped password can produce repeated failures. A flag is not proof of malicious activity.
- This is a triage/educational tool, not a replacement for a full forensic suite or incident-response process.
- Preserve original evidence, record acquisition details, and work on copies where possible.

## Project objective

Demonstrate how Python can support digital forensics through repeatable parsing, event classification, timeline reconstruction, anomaly flagging, and report generation.
