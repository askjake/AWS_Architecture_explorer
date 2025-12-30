#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import inspect
from pathlib import Path
from typing import Any, Dict, List, Tuple

import streamlit as st

try:
    from streamlit_agraph import agraph, Config, Node, Edge
    HAS_AGRAPH = True
except Exception:
    HAS_AGRAPH = False

from mongobleed_snapshot_lib_v6 import (
    DEFAULT_BASTION,
    DEFAULT_REGION,
    DEFAULT_SNAPSHOT_DIR,
    collect_arch_snapshot,
    list_snapshots,
    load_snapshot,
    save_snapshot,
    default_snapshot_name,
    as_list_of_dicts,
)


def ss_init() -> None:
    ss = st.session_state
    ss.setdefault("snapshot", None)
    ss.setdefault("snapshot_path", "")
    ss.setdefault("snapshot_dir", DEFAULT_SNAPSHOT_DIR)
    ss.setdefault("selected_node", "")
    ss.setdefault("last_error", "")


def df(data, *, hide_index: bool = True):
    """Streamlit dataframe compatibility wrapper.

    Your environment crashes if you pass width='stretch'. Some environments warn that
    use_container_width is deprecated. So we use whichever param exists.
    """
    sig = inspect.signature(st.dataframe)
    if "use_container_width" in sig.parameters:
        return st.dataframe(data, use_container_width=True, hide_index=hide_index)
    # fallback: no special sizing
    return st.dataframe(data, hide_index=hide_index)


def _id(label: str, kind: str) -> str:
    return f"{kind}:{label}"


def _safe_get(container: Any, key: str, default: Any) -> Any:
    if isinstance(container, dict):
        return container.get(key, default)
    return default


def build_hierarchy_graph(snapshot: Dict[str, Any], *, max_edges: int = 1200):
    nodes: List[Any] = []
    edges_raw: List[Dict[str, str]] = []
    payloads: Dict[str, Any] = {}

    vpc_container = snapshot.get("vpc", {})
    vpcs = as_list_of_dicts(_safe_get(vpc_container, "vpcs", vpc_container))
    subnets = as_list_of_dicts(_safe_get(vpc_container, "subnets", []))
    sgs = as_list_of_dicts(_safe_get(vpc_container, "security_groups", []))

    for v in vpcs:
        vid = v.get("VpcId", "unknown")
        nid = _id(vid, "vpc")
        payloads[nid] = v
        nodes.append({"id": nid, "label": f"VPC {vid}"})

    for sn in subnets:
        sid = sn.get("SubnetId", "unknown")
        vpcid = sn.get("VpcId", "unknown")
        nid = _id(sid, "subnet")
        payloads[nid] = sn
        nodes.append({"id": nid, "label": f"Subnet {sid}"})
        edges_raw.append({"source": _id(vpcid, "vpc"), "target": nid, "label": "has"})

    for sg in sgs:
        sgid = sg.get("GroupId", "unknown")
        vpcid = sg.get("VpcId", "unknown")
        nid = _id(sgid, "sg")
        payloads[nid] = sg
        nodes.append({"id": nid, "label": f"SG {sgid}"})
        edges_raw.append({"source": _id(vpcid, "vpc"), "target": nid, "label": "sg"})

    lbs_container = snapshot.get("elbv2", {})
    lbs = as_list_of_dicts(_safe_get(lbs_container, "load_balancers", lbs_container))
    for lb in lbs:
        arn = lb.get("LoadBalancerArn", "unknown")
        name = lb.get("LoadBalancerName") or arn.split("/")[-1]
        nid = _id(name, "lb")
        payloads[nid] = lb
        nodes.append({"id": nid, "label": f"LB {name}"})

        for az in lb.get("AvailabilityZones", []) or []:
            if isinstance(az, dict):
                sid = az.get("SubnetId")
                if sid:
                    edges_raw.append({"source": nid, "target": _id(sid, "subnet"), "label": "in"})

        for sgid in lb.get("SecurityGroups", []) or []:
            edges_raw.append({"source": nid, "target": _id(sgid, "sg"), "label": "uses"})

    eks_container = snapshot.get("eks", {})
    eks_clusters = as_list_of_dicts(_safe_get(eks_container, "clusters", eks_container))
    for c in eks_clusters:
        name = c.get("name") or c.get("clusterName") or c.get("Arn", "unknown").split("/")[-1]
        nid = _id(name, "eks")
        payloads[nid] = c
        nodes.append({"id": nid, "label": f"EKS {name}"})

        vpc_cfg = c.get("resourcesVpcConfig", {}) or {}
        for sid in vpc_cfg.get("subnetIds", []) or []:
            edges_raw.append({"source": nid, "target": _id(sid, "subnet"), "label": "subnet"})
        for sgid in vpc_cfg.get("securityGroupIds", []) or []:
            edges_raw.append({"source": nid, "target": _id(sgid, "sg"), "label": "cluster-sg"})

        for ng in as_list_of_dicts(c.get("nodegroups")):
            ngn = ng.get("nodegroupName", "nodegroup")
            ngid = _id(f"{name}/{ngn}", "ng")
            payloads[ngid] = ng
            nodes.append({"id": ngid, "label": f"NG {ngn}"})
            edges_raw.append({"source": nid, "target": ngid, "label": "has"})
            for sid in ng.get("subnets", []) or []:
                edges_raw.append({"source": ngid, "target": _id(sid, "subnet"), "label": "subnet"})
            ra = ng.get("remoteAccess", {}) or {}
            for sgid in ra.get("sourceSecurityGroups", []) or []:
                edges_raw.append({"source": ngid, "target": _id(sgid, "sg"), "label": "remote-access"})

    rds_container = snapshot.get("rds", {})
    dbs = as_list_of_dicts(_safe_get(rds_container, "db_instances", rds_container))
    for db in dbs:
        ident = db.get("DBInstanceIdentifier", "db")
        nid = _id(ident, "rds")
        payloads[nid] = db
        nodes.append({"id": nid, "label": f"RDS {ident}"})

        subnet_grp = db.get("DBSubnetGroup", {}) or {}
        for sn in subnet_grp.get("Subnets", []) or []:
            sid = (sn.get("SubnetIdentifier") if isinstance(sn, dict) else None) or ""
            if sid:
                edges_raw.append({"source": nid, "target": _id(sid, "subnet"), "label": "subnet"})
        for vsg in db.get("VpcSecurityGroups", []) or []:
            sgid = vsg.get("VpcSecurityGroupId") if isinstance(vsg, dict) else None
            if sgid:
                edges_raw.append({"source": nid, "target": _id(sgid, "sg"), "label": "uses"})

    seen = set()
    deduped: List[Dict[str, str]] = []
    for e in edges_raw:
        k = (e["source"], e["target"], e.get("label", ""))
        if k in seen:
            continue
        seen.add(k)
        deduped.append(e)
        if len(deduped) >= max_edges:
            break

    if HAS_AGRAPH:
        n_objs = [Node(id=n["id"], label=n["label"]) for n in nodes]
        e_objs = [Edge(source=e["source"], target=e["target"], label=e.get("label", "")) for e in deduped]
        return n_objs, e_objs, payloads

    return nodes, deduped, payloads


def outside_in_findings(snapshot: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    lbs_container = snapshot.get("elbv2", {})
    lbs = as_list_of_dicts(_safe_get(lbs_container, "load_balancers", lbs_container))
    for lb in lbs:
        if lb.get("Scheme") != "internet-facing":
            continue
        sgs = lb.get("SecurityGroups", []) or []
        findings.append({
            "Type": "LoadBalancer",
            "Name": lb.get("LoadBalancerName"),
            "DNS": lb.get("DNSName"),
            "VpcId": lb.get("VpcId"),
            "SGs": ",".join(sgs),
            "Notes": "Internet-facing LB",
        })

    eks_container = snapshot.get("eks", {})
    for c in as_list_of_dicts(_safe_get(eks_container, "clusters", eks_container)):
        name = c.get("name") or c.get("clusterName") or c.get("Arn", "").split("/")[-1]
        vpc_cfg = c.get("resourcesVpcConfig", {}) or {}
        findings.append({
            "Type": "EKS",
            "Name": name,
            "DNS": c.get("endpoint"),
            "VpcId": vpc_cfg.get("vpcId") or "",
            "SGs": ",".join(vpc_cfg.get("securityGroupIds", []) or []),
            "Notes": f"Endpoint public={vpc_cfg.get('endpointPublicAccess')} private={vpc_cfg.get('endpointPrivateAccess')}",
        })

    rds_container = snapshot.get("rds", {})
    for db in as_list_of_dicts(_safe_get(rds_container, "db_instances", rds_container)):
        if db.get("PubliclyAccessible"):
            findings.append({
                "Type": "RDS",
                "Name": db.get("DBInstanceIdentifier"),
                "DNS": (db.get("Endpoint", {}) or {}).get("Address"),
                "VpcId": (db.get("DBSubnetGroup", {}) or {}).get("VpcId", ""),
                "SGs": ",".join([v.get("VpcSecurityGroupId","") for v in (db.get("VpcSecurityGroups") or []) if isinstance(v, dict)]),
                "Notes": "PubliclyAccessible=True",
            })

    return findings


def s3_versioning_rows(snapshot: Dict[str, Any]) -> List[Dict[str, Any]]:
    s3 = snapshot.get("s3", {})
    if isinstance(s3, dict):
        return list(s3.get("s3_versioning", []) or [])
    return []


def sidebar_controls() -> Dict[str, Any]:
    ss = st.session_state

    st.sidebar.header("MongoBleed Controls")

    snapshot_dir = st.sidebar.text_input("Snapshot directory", value=str(ss["snapshot_dir"]))
    ss["snapshot_dir"] = snapshot_dir

    region = st.sidebar.text_input("AWS Region", value=DEFAULT_REGION)
    bastion = st.sidebar.text_input("SSH Bastion host", value=DEFAULT_BASTION)

    st.sidebar.divider()
    st.sidebar.subheader("Collect new snapshot")

    include_node_instances = st.sidebar.checkbox("Include EC2 node instances (heavy)", value=False)
    include_non_internet_lbs = st.sidebar.checkbox("Include internal (non-internet) LBs", value=False)
    include_s3 = st.sidebar.checkbox("Include S3 versioning report", value=True)
    s3_bucket_limit = st.sidebar.number_input("S3 bucket limit", min_value=0, max_value=5000, value=200, step=50)

    if st.sidebar.button("Collect snapshot now", type="primary"):
        try:
            with st.status("Collecting snapshot via bastion…", expanded=True) as status:
                snap = collect_arch_snapshot(
                    region=region,
                    bastion=bastion,
                    include_node_instances=include_node_instances,
                    include_non_internet_lbs=include_non_internet_lbs,
                    include_s3=include_s3,
                    s3_bucket_limit=int(s3_bucket_limit),
                )
                out = Path(snapshot_dir) / default_snapshot_name()
                save_snapshot(snap, out)

                ss["snapshot"] = snap
                ss["snapshot_path"] = str(out)
                ss["selected_node"] = ""
                ss["last_error"] = ""

                status.update(label=f"Snapshot collected: {out}", state="complete", expanded=False)
        except Exception as e:
            ss["last_error"] = str(e)
            st.sidebar.error("Snapshot collection failed. See error at top of page.")

    st.sidebar.divider()
    st.sidebar.subheader("Load existing snapshot")

    files = list_snapshots(snapshot_dir)
    labels = [p.name for p in files]
    choice = st.sidebar.selectbox("Saved snapshots", options=[""] + labels, index=0)

    cols = st.sidebar.columns(2)
    if cols[0].button("Load selected") and choice:
        try:
            path = Path(snapshot_dir) / choice
            ss["snapshot"] = load_snapshot(path)
            ss["snapshot_path"] = str(path)
            ss["selected_node"] = ""
            ss["last_error"] = ""
        except Exception as e:
            ss["last_error"] = str(e)
            st.sidebar.error("Failed to load snapshot.")

    up = st.sidebar.file_uploader("…or upload snapshot JSON", type=["json"])
    if cols[1].button("Load upload") and up is not None:
        try:
            ss["snapshot"] = json.loads(up.read().decode("utf-8"))
            ss["snapshot_path"] = f"(uploaded) {up.name}"
            ss["selected_node"] = ""
            ss["last_error"] = ""
        except Exception as e:
            ss["last_error"] = str(e)
            st.sidebar.error("Failed to parse uploaded JSON.")

    st.sidebar.divider()
    max_edges = st.sidebar.slider("Graph density (max edges)", min_value=200, max_value=5000, value=1200, step=200)

    return {"max_edges": int(max_edges)}


def main() -> int:
    st.set_page_config(page_title="MongoBleed Architecture Explorer", layout="wide")
    ss_init()

    controls = sidebar_controls()

    if st.session_state.get("last_error"):
        st.error(st.session_state["last_error"])

    snap = st.session_state.get("snapshot")
    if not snap:
        st.info("Load or collect a snapshot from the sidebar.")
        return 0

    st.title("MongoBleed Architecture Explorer")
    st.caption(f"Snapshot: {st.session_state.get('snapshot_path','(in-memory)')}")
    meta = {
        "schema_version": snap.get("schema_version"),
        "generated_at": snap.get("generated_at"),
        "region": snap.get("region"),
        "bastion": snap.get("bastion"),
        "options": snap.get("options", {}),
    }
    st.code(json.dumps(meta, indent=2), language="json")

    tabA, tabB = st.tabs(["A) Hierarchy view", "B) Outside-in security review"])

    with tabA:
        st.subheader("Architecture hierarchy")
        left, right = st.columns([2, 1], gap="large")

        with left:
            if not HAS_AGRAPH:
                st.warning("streamlit-agraph is not installed; showing JSON only.")
                st.json(snap)
            else:
                nodes, edges, payloads = build_hierarchy_graph(snap, max_edges=controls["max_edges"])
                config = Config(width="100%", height=650, directed=True, physics=True)
                selected = agraph(nodes=nodes, edges=edges, config=config)

                node_id = ""
                if isinstance(selected, dict) and selected.get("nodes"):
                    node_id = selected["nodes"][0]
                elif isinstance(selected, str):
                    node_id = selected

                if node_id:
                    st.session_state["selected_node"] = node_id

        with right:
            st.markdown("### Selection details (persistent)")
            node_id = st.session_state.get("selected_node", "")
            if node_id:
                _, _, payloads = build_hierarchy_graph(snap, max_edges=controls["max_edges"])
                st.code(json.dumps(payloads.get(node_id, {}), indent=2), language="json")
            else:
                st.write("Click a node to view details. Snapshot stays loaded during reruns.")

    with tabB:
        st.subheader("Outside-in security review")
        findings = outside_in_findings(snap)

        q = st.text_input("Search findings (name/dns/sg/vpc)", value="")
        if q.strip():
            qq = q.strip().lower()
            findings = [
                r for r in findings
                if qq in (
                    str(r.get("Name", "")).lower()
                    + " " + str(r.get("DNS", "")).lower()
                    + " " + str(r.get("SGs", "")).lower()
                    + " " + str(r.get("VpcId", "")).lower()
                )
            ]

        df(findings, hide_index=True)
        st.markdown("### S3 bucket versioning")
        rows = s3_versioning_rows(snap)

        # Fast filters for "send me the list of buckets"
        all_statuses = sorted({str(r.get("Versioning", "Unknown")) for r in rows})
        status_filter = st.multiselect(
            "Filter by versioning status",
            options=all_statuses,
            default=all_statuses,
        )

        only_enabled = st.checkbox("Only show Enabled", value=False)
        if only_enabled:
            status_filter = ["Enabled"]

        if status_filter:
            rows = [r for r in rows if str(r.get("Versioning", "Unknown")) in status_filter]

        s3q = st.text_input("Search buckets", value="", key="s3_search")
        if s3q.strip():
            sq = s3q.strip().lower()
            rows = [r for r in rows if sq in str(r.get("Bucket", "")).lower()]

        df(rows, hide_index=True)

        # Downloads
        st.download_button(
            "Download S3 versioning as JSON",
            data=json.dumps(rows, indent=2).encode("utf-8"),
            file_name="s3_versioning.json",
            mime="application/json",
        )

        # CSV without pandas
        import csv, io
        buf = io.StringIO()
        if rows:
            w = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
            w.writeheader()
            for r in rows:
                w.writerow(r)
        st.download_button(
            "Download S3 versioning as CSV",
            data=buf.getvalue().encode("utf-8"),
            file_name="s3_versioning.csv",
            mime="text/csv",
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
