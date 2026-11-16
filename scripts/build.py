#!/usr/bin/env python3
"""Build a small CISA KEV index enriched with FIRST EPSS scores."""
import argparse
import csv
from datetime import date, datetime, timezone
import gzip
import io
import json
from pathlib import Path
import re
import shutil
import tempfile
import time
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
CISA = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
EPSS = "https://epss.cyentia.com/epss_scores-current.csv.gz"
ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}\Z")


def download(url, limit):
    for attempt in range(3):
        try:
            with urlopen(Request(url, headers={"User-Agent": "CoolCode Patch Signal/1.0"}), timeout=35) as response:
                data = response.read(limit + 1)
            if len(data) > limit:
                raise ValueError("Source exceeded configured download size")
            return data
        except (ValueError, OSError):
            if attempt == 2:
                raise
            time.sleep(2 ** attempt)


def kev_rows(payload):
    rows = payload.get("vulnerabilities", [])
    if not isinstance(rows, list) or not rows or payload.get("count") != len(rows):
        raise ValueError("Invalid KEV source catalogue count")
    datetime.fromisoformat(payload["dateReleased"].replace("Z", "+00:00"))
    seen = set()
    for row in rows:
        cve = row["cveID"]
        if not ID.fullmatch(cve) or cve in seen:
            raise ValueError(f"Invalid or repeated CVE: {cve}")
        seen.add(cve)
        date.fromisoformat(row["dateAdded"])
        date.fromisoformat(row["dueDate"])
        yield {
            "id": cve, "vendor": row["vendorProject"], "product": row["product"],
            "name": row["vulnerabilityName"], "added": row["dateAdded"], "due": row["dueDate"],
            "ransomware": row.get("knownRansomwareCampaignUse"), "action": row["requiredAction"],
            "description": row["shortDescription"],
        }


def epss_scores(payload, ids):
    with gzip.GzipFile(fileobj=io.BytesIO(payload)) as zipped, io.TextIOWrapper(zipped, encoding="utf-8", newline="") as source:
        header = source.readline(1024)
        day = re.search(r"score_date:([0-9-]+)", header)
        if not day:
            raise ValueError("EPSS source is missing its score date")
        date.fromisoformat(day[1])
        reader = csv.DictReader(source)
        if reader.fieldnames != ["cve", "epss", "percentile"]:
            raise ValueError("Unexpected EPSS schema")
        scores = {}
        for i, item in enumerate(reader, 1):
            if i > 2_000_000:
                raise ValueError("EPSS record limit exceeded")
            if item["cve"] in ids:
                epss, rank = float(item["epss"]), float(item["percentile"])
                if not (0 <= epss <= 1 and 0 <= rank <= 1):
                    raise ValueError("EPSS value out of range")
                scores[item["cve"]] = [epss, rank]
        if not scores:
            raise ValueError("No EPSS scores matched the CISA catalogue")
        return day[1], scores


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kev", type=Path, help="Build from a saved official KEV JSON")
    parser.add_argument("--epss", type=Path, help="Build from a saved official EPSS daily CSV.gz")
    args = parser.parse_args()
    source = json.loads(args.kev.read_bytes() if args.kev else download(CISA, 8_000_000))
    rows = list(kev_rows(source))
    try:
        day, scores = epss_scores(args.epss.read_bytes() if args.epss else download(EPSS, 20_000_000), {row["id"] for row in rows})
    except (OSError, ValueError, EOFError) as error:
        if args.epss:
            raise
        print(f"EPSS build-time enrichment unavailable. Live CVE scores remain available: {error}")
        day, scores = None, {}
    for row in rows:
        row["score"] = scores.get(row["id"])
    snapshot = {"rows": rows, "kevDate": source["dateReleased"], "epssDate": day,
                "built": datetime.now(timezone.utc).isoformat()}
    output = ROOT / "dist"
    with tempfile.TemporaryDirectory(dir=ROOT) as temp:
        staged = Path(temp) / "site"
        shutil.copytree(ROOT / "web", staged)
        (staged / "kev.json").write_text(json.dumps(snapshot, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
        if output.exists():
            shutil.rmtree(output)
        staged.rename(output)
    print(f"Built {len(rows):,} KEV rows with {len(scores):,} EPSS matches, score date {day or 'unavailable'}")


if __name__ == "__main__":
    main()
