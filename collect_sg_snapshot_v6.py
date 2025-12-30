#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
from pathlib import Path

from mongobleed_snapshot_lib_v6 import (
    DEFAULT_BASTION,
    DEFAULT_REGION,
    DEFAULT_SNAPSHOT_DIR,
    collect_arch_snapshot,
    default_snapshot_name,
    save_snapshot,
)


def main() -> int:
    ap = argparse.ArgumentParser(description="Collect MongoBleed architecture/security snapshot (v6)")
    ap.add_argument("--region", default=DEFAULT_REGION)
    ap.add_argument("--bastion", default=DEFAULT_BASTION, help="SSH host (default: david-bastion)")
    ap.add_argument("--out", default="", help="Output JSON path (default: snapshots/<timestamp>.json)")
    ap.add_argument("--snapshot-dir", default=DEFAULT_SNAPSHOT_DIR)

    ap.add_argument("--include-node-instances", action="store_true", help="Heavier; may slow down")
    ap.add_argument("--include-non-internet-lbs", action="store_true", help="Include internal LBs too")
    ap.add_argument("--include-s3", action="store_true", help="Collect S3 versioning report (fault-tolerant)")
    ap.add_argument("--s3-bucket-limit", type=int, default=200)

    args = ap.parse_args()

    out_path = Path(args.out) if args.out else Path(args.snapshot_dir) / default_snapshot_name()

    snap = collect_arch_snapshot(
        region=args.region,
        bastion=args.bastion,
        include_node_instances=args.include_node_instances,
        include_non_internet_lbs=args.include_non_internet_lbs,
        include_s3=args.include_s3,
        s3_bucket_limit=args.s3_bucket_limit,
    )
    save_snapshot(snap, out_path)
    print(f"Wrote snapshot: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
