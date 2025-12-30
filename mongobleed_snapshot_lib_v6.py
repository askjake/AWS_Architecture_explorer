#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""MongoBleed - AWS architecture + security snapshot library (v6)

Fixes in v6:
- Keep SSH quoting correct so remote bash receives ONE -c string.
- Robust JSON parsing that tolerates MOTD/banner/profile noise.
- Disable AWS pager (AWS_PAGER="") so JSON isn't paged.
- Default bastion = david-bastion (override via MONGOBLEED_BASTION env var).
- S3 versioning collection is now fault-tolerant:
    * AccessDenied (including explicit deny) is recorded per-bucket
    * collection continues (no hard-fail)
"""

from __future__ import annotations

import datetime as dt
import json
import os
import shlex
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_BASTION = os.environ.get("MONGOBLEED_BASTION", "david-bastion")
DEFAULT_REGION = os.environ.get("AWS_REGION", "us-west-2")
DEFAULT_SNAPSHOT_DIR = os.environ.get("MONGOBLEED_SNAPSHOT_DIR", "snapshots")


def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def save_snapshot(snapshot: Dict[str, Any], out_path: Path) -> Path:
    out_path = Path(out_path)
    _ensure_dir(out_path.parent)
    tmp = out_path.with_suffix(out_path.suffix + ".tmp")
    tmp.write_text(json.dumps(snapshot, indent=2, default=str), encoding="utf-8")
    tmp.replace(out_path)
    return out_path


def load_snapshot(path: Path) -> Dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def list_snapshots(snapshot_dir: Path | str = DEFAULT_SNAPSHOT_DIR) -> List[Path]:
    d = Path(snapshot_dir)
    if not d.exists():
        return []
    return sorted(d.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)


# Back-compat alias (so older apps won't break)
def list_snapshot_files(snapshot_dir: Path | str = DEFAULT_SNAPSHOT_DIR) -> List[Path]:
    return list_snapshots(snapshot_dir)


def default_snapshot_name(prefix: str = "mongobleed_snapshot") -> str:
    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{prefix}_{ts}.json"


def parse_json_loose(stdout: str) -> Any:
    """Try strict JSON first, then scan stdout for first JSON object/array.

    This recovers from MOTD/banner/profile noise.
    """
    s = (stdout or "").strip()
    if not s:
        return {}
    try:
        return json.loads(s)
    except Exception:
        pass

    dec = json.JSONDecoder()
    for i, ch in enumerate(s):
        if ch not in "{[":
            continue
        try:
            obj, _end = dec.raw_decode(s[i:])
            return obj
        except Exception:
            continue

    raise json.JSONDecodeError("No JSON found in output", s, 0)


def _run(cmd: List[str], timeout_s: int = 180) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)


def run_cmd_json(cmd: List[str], timeout_s: int = 180) -> Dict[str, Any]:
    p = _run(cmd, timeout_s=timeout_s)

    if p.returncode != 0:
        raise RuntimeError(
            "Command failed (rc=%s).\nCMD: %s\nSTDERR:\n%s\nSTDOUT:\n%s"
            % (p.returncode, " ".join(cmd), (p.stderr or ""), (p.stdout or ""))
        )

    out = (p.stdout or "")
    try:
        obj = parse_json_loose(out)
    except json.JSONDecodeError as e:
        raise RuntimeError(
            "Command did not return JSON.\nCMD: %s\nERR: %s\nRAW (first 4000 chars):\n%s"
            % (" ".join(cmd), str(e), out[:4000])
        )

    if isinstance(obj, dict):
        return obj
    return {"_list": obj}


def build_aws_cli_str(
    service: str,
    *args: str,
    region: Optional[str],
    output: str = "json",
    profile: Optional[str] = None,
) -> str:
    parts = ["aws", service, *args]
    if region:
        parts += ["--region", region]
    if output:
        parts += ["--output", output]

    cmd = " ".join(shlex.quote(p) for p in parts)

    env_prefix = 'AWS_PAGER=""'
    if profile:
        env_prefix += f" AWS_PROFILE={shlex.quote(profile)}"

    return f"{env_prefix} {cmd}"


def build_ssh_bash_cmd(bastion: str, inner_cmd: str, login_shell: bool = True) -> List[str]:
    """Return SSH command list that safely executes inner_cmd via bash -lc on remote."""
    bash_flags = "-lc" if login_shell else "-c"
    wrapped = f"set -euo pipefail; {inner_cmd}"
    wrapped_q = shlex.quote(wrapped)
    return ["ssh", bastion, "--", "bash", bash_flags, wrapped_q]


def run_aws_json(
    service: str,
    *args: str,
    region: str,
    bastion: Optional[str] = DEFAULT_BASTION,
    timeout_s: int = 180,
    profile: Optional[str] = None,
) -> Dict[str, Any]:
    inner = build_aws_cli_str(service, *args, region=region, output="json", profile=profile)

    if bastion:
        return run_cmd_json(build_ssh_bash_cmd(bastion, inner, login_shell=True), timeout_s=timeout_s)

    return run_cmd_json(shlex.split(inner), timeout_s=timeout_s)


def as_list_of_dicts(x: Any) -> List[Dict[str, Any]]:
    """Accept list[dict], dict[id->dict], or single dict; return list[dict]."""
    if x is None:
        return []
    if isinstance(x, list):
        return [i for i in x if isinstance(i, dict)]
    if isinstance(x, dict):
        vals = list(x.values())
        if vals and all(isinstance(v, dict) for v in vals):
            return vals
        return [x]
    return []


def discover_vpcs(region: str, bastion: str) -> Dict[str, Any]:
    vpcs = run_aws_json("ec2", "describe-vpcs", region=region, bastion=bastion).get("Vpcs", [])
    subs = run_aws_json("ec2", "describe-subnets", region=region, bastion=bastion).get("Subnets", [])
    sgs = run_aws_json("ec2", "describe-security-groups", region=region, bastion=bastion).get("SecurityGroups", [])
    return {"vpcs": vpcs, "subnets": subs, "security_groups": sgs}


def discover_eks(region: str, bastion: str, include_node_instances: bool = False) -> Dict[str, Any]:
    clusters = run_aws_json("eks", "list-clusters", region=region, bastion=bastion).get("clusters", [])
    out_clusters: List[Dict[str, Any]] = []

    for name in clusters:
        desc = run_aws_json("eks", "describe-cluster", "--name", name, region=region, bastion=bastion).get("cluster", {})
        nodegroups = run_aws_json("eks", "list-nodegroups", "--cluster-name", name, region=region, bastion=bastion).get("nodegroups", [])
        ng_descs: List[Dict[str, Any]] = []
        for ng in nodegroups:
            ngd = run_aws_json(
                "eks", "describe-nodegroup",
                "--cluster-name", name, "--nodegroup-name", ng,
                region=region, bastion=bastion
            ).get("nodegroup", {})
            ng_descs.append(ngd)

        desc["nodegroups"] = ng_descs
        out_clusters.append(desc)

    node_instances_raw: List[Dict[str, Any]] = []
    if include_node_instances:
        node_instances_raw = run_aws_json("ec2", "describe-instances", region=region, bastion=bastion).get("Reservations", [])

    return {"clusters": out_clusters, "node_instances_raw": node_instances_raw}


def discover_load_balancers(region: str, bastion: str, include_non_internet_lbs: bool = False) -> Dict[str, Any]:
    lbs = run_aws_json("elbv2", "describe-load-balancers", region=region, bastion=bastion).get("LoadBalancers", [])
    if not include_non_internet_lbs:
        lbs = [lb for lb in lbs if lb.get("Scheme") == "internet-facing"]
    return {"load_balancers": lbs}


def discover_rds(region: str, bastion: str) -> Dict[str, Any]:
    dbs = run_aws_json("rds", "describe-db-instances", region=region, bastion=bastion).get("DBInstances", [])
    return {"db_instances": dbs}


def _classify_s3_versioning_error(err: str) -> Tuple[str, str]:
    e = (err or "").lower()
    if "accessdenied" in e or "explicit deny" in e:
        return ("AccessDenied", err.strip())
    if "nosuchbucket" in e:
        return ("NoSuchBucket", err.strip())
    if "invalidbucketname" in e:
        return ("InvalidBucketName", err.strip())
    return ("Error", err.strip())


def discover_s3_versioning(region: str, bastion: str, bucket_limit: int = 200) -> Dict[str, Any]:
    buckets = run_aws_json("s3api", "list-buckets", region=region, bastion=bastion).get("Buckets", [])
    buckets = buckets[: max(0, int(bucket_limit))]

    rows: List[Dict[str, Any]] = []
    for b in buckets:
        name = b.get("Name")
        if not name:
            continue

        row = {
            "Bucket": name,
            "Versioning": "Unknown",
            "MFADelete": "Unknown",
            "Created": b.get("CreationDate"),
            "ErrorType": "",
            "ErrorDetail": "",
        }

        try:
            ver = run_aws_json("s3api", "get-bucket-versioning", "--bucket", name, region=region, bastion=bastion)
            row["Versioning"] = ver.get("Status") or "None"  # Enabled | Suspended | None
            row["MFADelete"] = ver.get("MFADelete") or "None"
        except Exception as e:
            status, detail = _classify_s3_versioning_error(str(e))
            row["Versioning"] = status
            row["MFADelete"] = status
            row["ErrorType"] = status
            row["ErrorDetail"] = detail[:2000]

        rows.append(row)

    return {"s3_versioning": rows}


def collect_arch_snapshot(
    *,
    region: str = DEFAULT_REGION,
    bastion: str = DEFAULT_BASTION,
    include_node_instances: bool = False,
    include_non_internet_lbs: bool = False,
    include_s3: bool = False,
    s3_bucket_limit: int = 200,
) -> Dict[str, Any]:
    base: Dict[str, Any] = {
        "schema_version": 6,
        "generated_at": utc_now_iso(),
        "region": region,
        "bastion": bastion,
        "options": {
            "include_node_instances": bool(include_node_instances),
            "include_non_internet_lbs": bool(include_non_internet_lbs),
            "include_s3": bool(include_s3),
            "s3_bucket_limit": int(s3_bucket_limit),
        },
    }

    base["vpc"] = discover_vpcs(region=region, bastion=bastion)
    base["eks"] = discover_eks(region=region, bastion=bastion, include_node_instances=include_node_instances)
    base["elbv2"] = discover_load_balancers(region=region, bastion=bastion, include_non_internet_lbs=include_non_internet_lbs)
    base["rds"] = discover_rds(region=region, bastion=bastion)

    if include_s3:
        base["s3"] = discover_s3_versioning(region=region, bastion=bastion, bucket_limit=s3_bucket_limit)
    else:
        base["s3"] = {"s3_versioning": []}

    return base
