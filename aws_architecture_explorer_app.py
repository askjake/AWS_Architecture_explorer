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

from aws_architecture_snapshot_lib import (
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


def build_hierarchy_graph(
    snapshot: dict,
    *,
    style: str = "vpc",
    max_edges: int = 2500,
    detail_level: int = 2,
    show_subnet_nodes: bool = False,
    show_sg_nodes: bool = False,
    show_placement_edges: bool = False,
    max_nodes: int = 1800,
    ingress_include_internal: bool = False,
):
    """
    Tree-first architecture view with three styles:

      - vpc:     Region → VPC → buckets → resources
      - eks:     Region → EKS → Nodegroups → (subnets/SGs)
      - ingress: Internet-facing LBs → VPC → downstream (EKS/RDS/etc)

    To keep the diagram readable and avoid overlaps, we default to a "family tree":
    each visual node has a single parent. When you enable placement edges, we add
    extra cross-links that can increase clutter.
    """
    payloads: dict[str, dict] = {}

    # If agraph isn't available we still return payloads so the rest of the app works.
    if not HAS_AGRAPH:
        return [], [], payloads

    def g(obj: Any, *path: str, default=None):
        cur = obj
        for k in path:
            if isinstance(cur, dict):
                cur = cur.get(k)
            else:
                return default
        return default if cur is None else cur

    def as_list(x, prefer_key: str | None = None) -> list:
        if x is None:
            return []
        if isinstance(x, list):
            return x
        if isinstance(x, dict):
            if prefer_key and isinstance(x.get(prefer_key), list):
                return x.get(prefer_key) or []
            # AWS-style outputs often look like {"Subnets":[...]} etc.
            for _, v in x.items():
                if isinstance(v, list):
                    return v
            return []
        return []

    def _bool(v):
        return bool(v) if v is not None else False

    def _short_id(s: str, n: int = 8) -> str:
        s = str(s or "")
        return s if len(s) <= n else (s[:n] + "…")

    # ---- Visual style (vis-network shapes) ----
    STYLE = {
        "root":     dict(shape="diamond",  color="#E0E0E0", size=28),
        "region":   dict(shape="diamond",  color="#E0E0E0", size=28),
        "vpc":      dict(shape="box",      color="#BBDEFB", size=24),
        "bucket":   dict(shape="box",      color="#ECEFF1", size=18),

        "subnet":   dict(shape="box",      color="#FFF9C4", size=16),
        "sg":       dict(shape="hexagon",  color="#FFCDD2", size=16),

        "eks":      dict(shape="ellipse",  color="#C8E6C9", size=18),
        "nodegroup":dict(shape="square",   color="#DCEDC8", size=16),
        "instance": dict(shape="dot",      color="#FFFFFF", size=10),

        "lb":       dict(shape="triangle", color="#FFE0B2", size=16),
        "rds":      dict(shape="database", color="#F8BBD0", size=16),

        "other":    dict(shape="box",      color="#EEEEEE", size=14),
    }

    def _make_node(**kw):
        # Be resilient across streamlit-agraph versions.
        # Some versions don't accept arbitrary kwargs; we progressively drop them.
        for drop_keys in ([], ["level"], ["level", "group"], ["level", "group", "shape", "color", "size"]):
            try_kw = dict(kw)
            for k in drop_keys:
                try_kw.pop(k, None)
            try:
                return Node(**try_kw)
            except TypeError:
                continue
        return Node(id=kw["id"], label=kw.get("label", kw["id"]))

    def _make_edge(source: str, target: str, label: str = ""):
        try:
            return Edge(source=source, target=target, label=label)
        except TypeError:
            return Edge(source=source, target=target)

    nodes: list[Node] = []
    edges: list[Edge] = []
    seen_edges: set[tuple[str, str, str]] = set()
    seen_nodes: set[str] = set()

    def add_node(nid: str, label: str, kind: str, payload: dict | None = None, level: int | None = None, group: str | None = None):
        if nid in seen_nodes:
            return
        seen_nodes.add(nid)
        payloads[nid] = payload or {}
        style_kw = STYLE.get(kind, STYLE["other"])
        kw = dict(id=nid, label=label, **style_kw)
        if level is not None:
            kw["level"] = level
        if group is not None:
            kw["group"] = group
        nodes.append(_make_node(**kw))

    def add_edge(src: str, dst: str, label: str = ""):
        if len(edges) >= max_edges:
            return
        key = (src, dst, label)
        if key in seen_edges:
            return
        seen_edges.add(key)
        edges.append(_make_edge(src, dst, label))

    # ---- Pull normalized snapshot lists ----
    meta = g(snapshot, "meta", default={}) if isinstance(g(snapshot, "meta", default={}), dict) else {}
    region = meta.get("region") or snapshot.get("region") or snapshot.get("Region") or "unknown-region"

    # accept either "vpcs" or nested containers
    vpcs = as_list(snapshot.get("vpcs"), "Vpcs") or as_list(g(snapshot, "vpc"), "vpcs") or as_list(g(snapshot, "vpc", "vpcs"), "Vpcs")
    subnets = as_list(snapshot.get("subnets"), "Subnets") or as_list(g(snapshot, "vpc", "subnets"), "Subnets")
    sgs = as_list(snapshot.get("security_groups"), "SecurityGroups") or as_list(g(snapshot, "vpc", "security_groups"), "SecurityGroups")

    lbs = as_list(snapshot.get("load_balancers"), "LoadBalancers") or as_list(g(snapshot, "elbv2", "load_balancers"), "LoadBalancers")
    rds_list = as_list(snapshot.get("rds"), "DBInstances") or as_list(g(snapshot, "rds", "db_instances"), "DBInstances")

    eks_obj = snapshot.get("eks") or {}
    eks_clusters = as_list(g(eks_obj, "clusters"), "clusters") or as_list(eks_obj, "clusters")

    # Normalize VPC list items (sometimes strings)
    norm_vpcs = []
    for v in vpcs:
        if isinstance(v, dict):
            norm_vpcs.append(v)
        elif isinstance(v, str):
            norm_vpcs.append({"VpcId": v})
    vpcs = sorted(norm_vpcs, key=lambda x: str(x.get("VpcId") or ""))

    from collections import defaultdict

    # Index helpers
    subnets_by_vpc = defaultdict(list)
    for s in subnets:
        if isinstance(s, dict):
            subnets_by_vpc[s.get("VpcId")].append(s)

    sgs_by_vpc = defaultdict(list)
    for sg in sgs:
        if isinstance(sg, dict):
            sgs_by_vpc[sg.get("VpcId")].append(sg)

    lbs_by_vpc = defaultdict(list)
    for lb in lbs:
        if isinstance(lb, dict):
            lbs_by_vpc[lb.get("VpcId")].append(lb)

    rds_by_vpc = defaultdict(list)
    for db in rds_list:
        if not isinstance(db, dict):
            continue
        vpc_id = g(db, "DBSubnetGroup", "VpcId")
        rds_by_vpc[vpc_id].append(db)

    eks_by_vpc = defaultdict(list)
    for c in eks_clusters:
        if not isinstance(c, dict):
            continue
        vpc_id = g(c, "resourcesVpcConfig", "vpcId")
        eks_by_vpc[vpc_id].append(c)

    style = (style or "vpc").strip().lower()

    # ---- Builders ----

    def build_vpc_centered():
        root = _id(region, "region")
        add_node(root, f"Region\n{region}", "region", payload={"region": region}, level=0, group="root")

        for v in vpcs:
            vpc_id = v.get("VpcId") or "unknown-vpc"
            vpc_nid = _id(vpc_id, "vpc")

            n_subnets = len(subnets_by_vpc.get(vpc_id, []))
            n_sgs = len(sgs_by_vpc.get(vpc_id, []))
            n_eks = len(eks_by_vpc.get(vpc_id, []))
            n_lbs = len(lbs_by_vpc.get(vpc_id, []))
            n_rds = len(rds_by_vpc.get(vpc_id, []))

            cidr = v.get("CidrBlock") or ""
            vpc_label = f"VPC\n{vpc_id}"
            if cidr:
                vpc_label += f"\n{cidr}"
            if detail_level == 0:
                vpc_label += f"\nSubnets:{n_subnets}  SGs:{n_sgs}\nEKS:{n_eks}  LBs:{n_lbs}  RDS:{n_rds}"

            add_node(vpc_nid, vpc_label, "vpc", payload=v, level=1, group="vpc")
            add_edge(root, vpc_nid)

            if detail_level <= 0:
                continue

            def bucket(kind: str, label: str, count: int):
                nid = _id(f"{vpc_id}:{kind}", "bucket")
                add_node(nid, f"{label}\n({count})", "bucket", payload={"vpc": vpc_id, "bucket": kind, "count": count}, level=2, group="bucket")
                add_edge(vpc_nid, nid)
                return nid

            b_subnets = bucket("subnets", "Subnets", n_subnets)
            b_sgs = bucket("sgs", "Security Groups", n_sgs)
            b_eks = bucket("eks", "EKS", n_eks)
            b_lbs = bucket("lbs", "Load Balancers", n_lbs)
            b_rds = bucket("rds", "RDS", n_rds)

            eff_show_subnets = show_subnet_nodes or detail_level >= 3
            eff_show_sgs = show_sg_nodes or detail_level >= 3

            subnet_nodes_by_id: dict[str, str] = {}
            sg_nodes_by_id: dict[str, str] = {}

            if eff_show_subnets:
                for s in sorted(subnets_by_vpc.get(vpc_id, []), key=lambda x: str(x.get("SubnetId") or "")):
                    sid = s.get("SubnetId") or "unknown-subnet"
                    nid = _id(sid, "subnet")
                    az = s.get("AvailabilityZone") or ""
                    cidr = s.get("CidrBlock") or ""
                    label = f"Subnet\n{_short_id(sid, 10)}"
                    if az:
                        label += f"\n{az}"
                    if cidr:
                        label += f"\n{cidr}"
                    add_node(nid, label, "subnet", payload=s, level=3, group="subnet")
                    add_edge(b_subnets, nid)
                    subnet_nodes_by_id[sid] = nid

            if eff_show_sgs:
                for sg in sorted(sgs_by_vpc.get(vpc_id, []), key=lambda x: str(x.get("GroupId") or "")):
                    sgid = sg.get("GroupId") or "unknown-sg"
                    nid = _id(sgid, "sg")
                    name = sg.get("GroupName") or ""
                    label = f"SG\n{_short_id(sgid, 10)}"
                    if name:
                        label += f"\n{name}"
                    add_node(nid, label, "sg", payload=sg, level=3, group="sg")
                    add_edge(b_sgs, nid)
                    sg_nodes_by_id[sgid] = nid

            if detail_level < 2:
                return

            # EKS clusters / nodegroups
            for c in sorted(eks_by_vpc.get(vpc_id, []), key=lambda x: str(x.get("name") or "")):
                cname = c.get("name") or c.get("clusterName") or "eks"
                cnid = _id(cname, "eks")

                rvpc = c.get("resourcesVpcConfig") or {}
                pub = _bool(rvpc.get("endpointPublicAccess"))
                priv = _bool(rvpc.get("endpointPrivateAccess"))
                ep = ("pub" if pub else "") + ("+" if (pub and priv) else "") + ("priv" if priv else "")
                label = f"EKS\n{cname}" + (f"\nendpoint: {ep}" if ep else "")

                add_node(cnid, label, "eks", payload=c, level=3, group="eks")
                add_edge(b_eks, cnid)

                for ng in as_list(c.get("nodegroups")):
                    if not isinstance(ng, dict):
                        continue
                    ng_name = ng.get("nodegroupName") or ng.get("name") or "nodegroup"
                    ng_key = f"{cname}:{ng_name}"
                    ngnid = _id(ng_key, "ng")

                    scaling = ng.get("scalingConfig") or {}
                    desired = scaling.get("desiredSize")
                    minsz = scaling.get("minSize")
                    maxsz = scaling.get("maxSize")

                    its = ng.get("instanceTypes") or []
                    it_s = ", ".join(its[:2]) + ("…" if len(its) > 2 else "")

                    ng_label = f"Nodegroup\n{ng_name}"
                    if it_s:
                        ng_label += f"\n{it_s}"
                    if desired is not None or minsz is not None or maxsz is not None:
                        ng_label += f"\n{minsz}-{desired}-{maxsz}"

                    add_node(ngnid, ng_label, "nodegroup", payload=ng, level=4, group="nodegroup")
                    add_edge(cnid, ngnid, "has")

                    if show_placement_edges and (eff_show_subnets or eff_show_sgs):
                        for sid in (ng.get("subnets") or []):
                            if sid in subnet_nodes_by_id:
                                add_edge(ngnid, subnet_nodes_by_id[sid], "subnet")
                        ra = ng.get("remoteAccess") or {}
                        for sgid in (ra.get("sourceSecurityGroups") or []):
                            if sgid in sg_nodes_by_id:
                                add_edge(ngnid, sg_nodes_by_id[sgid], "remote-access")

                if show_placement_edges and (eff_show_subnets or eff_show_sgs):
                    for sid in (rvpc.get("subnetIds") or []):
                        if sid in subnet_nodes_by_id:
                            add_edge(cnid, subnet_nodes_by_id[sid], "subnet")
                    for sgid in (rvpc.get("securityGroupIds") or []):
                        if sgid in sg_nodes_by_id:
                            add_edge(cnid, sg_nodes_by_id[sgid], "sg")
                    csg = rvpc.get("clusterSecurityGroupId")
                    if csg and csg in sg_nodes_by_id:
                        add_edge(cnid, sg_nodes_by_id[csg], "cluster-sg")

            # Load balancers
            for lb in sorted(lbs_by_vpc.get(vpc_id, []), key=lambda x: str(x.get("LoadBalancerName") or "")):
                name = lb.get("LoadBalancerName") or "lb"
                arn = lb.get("LoadBalancerArn") or name
                nid = _id(arn, "lb")
                scheme = (lb.get("Scheme") or "").replace("internet-facing", "internet")
                lb_type = lb.get("Type") or ""
                label = f"LB\n{name}"
                if lb_type or scheme:
                    label += f"\n{(lb_type + ' ' + scheme).strip()}"
                add_node(nid, label, "lb", payload=lb, level=3, group="lb")
                add_edge(b_lbs, nid)

                if show_placement_edges and eff_show_subnets:
                    for az in (lb.get("AvailabilityZones") or []):
                        sid = g(az, "SubnetId")
                        if sid and sid in subnet_nodes_by_id:
                            add_edge(nid, subnet_nodes_by_id[sid], "subnet")

                if show_placement_edges and eff_show_sgs:
                    for sgid in (lb.get("SecurityGroups") or []):
                        if sgid in sg_nodes_by_id:
                            add_edge(nid, sg_nodes_by_id[sgid], "sg")

            # RDS
            for db in sorted(rds_by_vpc.get(vpc_id, []), key=lambda x: str(x.get("DBInstanceIdentifier") or "")):
                dbid = db.get("DBInstanceIdentifier") or db.get("DbiResourceId") or "rds"
                nid = _id(dbid, "rds")
                engine = db.get("Engine") or ""
                public = db.get("PubliclyAccessible")
                label = f"RDS\n{dbid}"
                if engine:
                    label += f"\n{engine}"
                if public is not None:
                    label += f"\nPublic:{public}"
                add_node(nid, label, "rds", payload=db, level=3, group="rds")
                add_edge(b_rds, nid)

                if show_placement_edges and eff_show_subnets:
                    for sn in (g(db, "DBSubnetGroup", "Subnets") or []):
                        sid = g(sn, "SubnetIdentifier")
                        if sid and sid in subnet_nodes_by_id:
                            add_edge(nid, subnet_nodes_by_id[sid], "subnet")

                if show_placement_edges and eff_show_sgs:
                    for sgref in (db.get("VpcSecurityGroups") or []):
                        sgid = g(sgref, "VpcSecurityGroupId")
                        if sgid and sgid in sg_nodes_by_id:
                            add_edge(nid, sg_nodes_by_id[sgid], "sg")

            if len(nodes) > max_nodes:
                break

    def build_eks_centered():
        root = _id(region, "region")
        add_node(root, f"Region\n{region}", "region", payload={"region": region}, level=0, group="root")

        for c in sorted(eks_clusters, key=lambda x: str((x or {}).get("name") if isinstance(x, dict) else "")):
            if not isinstance(c, dict):
                continue
            cname = c.get("name") or c.get("clusterName") or "eks"
            cnid = _id(cname, "eks")

            rvpc = c.get("resourcesVpcConfig") or {}
            vpc_id = rvpc.get("vpcId") or "unknown-vpc"
            pub = _bool(rvpc.get("endpointPublicAccess"))
            priv = _bool(rvpc.get("endpointPrivateAccess"))
            ep = ("pub" if pub else "") + ("+" if (pub and priv) else "") + ("priv" if priv else "")
            label = f"EKS\n{cname}" + (f"\n{vpc_id}" if vpc_id else "") + (f"\nendpoint: {ep}" if ep else "")

            add_node(cnid, label, "eks", payload=c, level=1, group="eks")
            add_edge(root, cnid)

            # Cluster-level networking (kept tidy via buckets)
            eff_show_subnets = show_subnet_nodes or detail_level >= 3
            eff_show_sgs = show_sg_nodes or detail_level >= 3

            cluster_subnet_ids = list(rvpc.get("subnetIds") or [])
            cluster_sg_ids = list(rvpc.get("securityGroupIds") or [])
            csg = rvpc.get("clusterSecurityGroupId")
            if csg:
                cluster_sg_ids.append(csg)

            if detail_level >= 2 and (eff_show_subnets or eff_show_sgs):
                if eff_show_subnets:
                    bsn = _id(f"{cname}:subnets", "bucket")
                    add_node(bsn, f"Cluster subnets\n({len(cluster_subnet_ids)})", "bucket", payload={"cluster": cname, "bucket": "subnets"}, level=2, group="bucket")
                    add_edge(cnid, bsn)
                    for sid in cluster_subnet_ids:
                        # duplicate "ref" nodes so the tree stays a tree
                        ref_id = _id(f"{cname}:cluster:{sid}", "subnet")
                        s_payload = {"ref": {"kind": "subnet", "id": sid}, "data": (subnets_by_vpc.get(vpc_id, []) and None)}
                        add_node(ref_id, f"Subnet\n{_short_id(sid, 10)}", "subnet", payload={"ref": {"kind": "subnet", "id": sid}}, level=3, group="subnet")
                        add_edge(bsn, ref_id)

                if eff_show_sgs:
                    bsg = _id(f"{cname}:sgs", "bucket")
                    add_node(bsg, f"Cluster SGs\n({len(cluster_sg_ids)})", "bucket", payload={"cluster": cname, "bucket": "sgs"}, level=2, group="bucket")
                    add_edge(cnid, bsg)
                    for sgid in cluster_sg_ids:
                        ref_id = _id(f"{cname}:cluster:{sgid}", "sg")
                        add_node(ref_id, f"SG\n{_short_id(sgid, 10)}", "sg", payload={"ref": {"kind": "sg", "id": sgid}}, level=3, group="sg")
                        add_edge(bsg, ref_id)

            # Nodegroups
            for ng in as_list(c.get("nodegroups")):
                if not isinstance(ng, dict):
                    continue
                ng_name = ng.get("nodegroupName") or ng.get("name") or "nodegroup"
                ng_key = f"{cname}:{ng_name}"
                ngnid = _id(ng_key, "ng")

                scaling = ng.get("scalingConfig") or {}
                desired = scaling.get("desiredSize")
                minsz = scaling.get("minSize")
                maxsz = scaling.get("maxSize")

                its = ng.get("instanceTypes") or []
                it_s = ", ".join(its[:2]) + ("…" if len(its) > 2 else "")

                ng_subnets = list(ng.get("subnets") or [])
                ra = ng.get("remoteAccess") or {}
                ng_sgs = list(ra.get("sourceSecurityGroups") or [])

                ng_label = f"Nodegroup\n{ng_name}"
                if it_s:
                    ng_label += f"\n{it_s}"
                if desired is not None or minsz is not None or maxsz is not None:
                    ng_label += f"\n{minsz}-{desired}-{maxsz}"
                if detail_level <= 1 and (ng_subnets or ng_sgs):
                    ng_label += f"\nSubnets:{len(ng_subnets)}  SGs:{len(ng_sgs)}"

                add_node(ngnid, ng_label, "nodegroup", payload=ng, level=2, group="nodegroup")
                add_edge(cnid, ngnid, "has")

                if eff_show_subnets and ng_subnets:
                    bsn = _id(f"{ng_key}:subnets", "bucket")
                    add_node(bsn, f"Subnets\n({len(ng_subnets)})", "bucket", payload={"nodegroup": ng_key, "bucket": "subnets"}, level=3, group="bucket")
                    add_edge(ngnid, bsn)
                    for sid in ng_subnets:
                        ref_id = _id(f"{ng_key}:{sid}", "subnet")
                        add_node(ref_id, f"Subnet\n{_short_id(sid, 10)}", "subnet", payload={"ref": {"kind": "subnet", "id": sid}}, level=4, group="subnet")
                        add_edge(bsn, ref_id)

                if eff_show_sgs and ng_sgs:
                    bsg = _id(f"{ng_key}:sgs", "bucket")
                    add_node(bsg, f"SGs\n({len(ng_sgs)})", "bucket", payload={"nodegroup": ng_key, "bucket": "sgs"}, level=3, group="bucket")
                    add_edge(ngnid, bsg)
                    for sgid in ng_sgs:
                        ref_id = _id(f"{ng_key}:{sgid}", "sg")
                        add_node(ref_id, f"SG\n{_short_id(sgid, 10)}", "sg", payload={"ref": {"kind": "sg", "id": sgid}}, level=4, group="sg")
                        add_edge(bsg, ref_id)

                if len(nodes) > max_nodes:
                    break

            if len(nodes) > max_nodes:
                break

    def build_ingress_centered():
        root = _id(region, "ingress")
        add_node(root, f"Ingress\n{region}", "root", payload={"region": region, "style": "ingress"}, level=0, group="root")

        internet_lbs = [lb for lb in lbs if isinstance(lb, dict) and lb.get("Scheme") == "internet-facing"]
        internet_lbs = sorted(internet_lbs, key=lambda x: str(x.get("LoadBalancerName") or ""))

        for lb in internet_lbs:
            name = lb.get("LoadBalancerName") or "lb"
            arn = lb.get("LoadBalancerArn") or name
            lbid = _id(arn, "lb")
            dns = lb.get("DNSName") or ""
            label = f"LB\n{name}" + (f"\n{dns}" if dns else "")
            add_node(lbid, label, "lb", payload=lb, level=1, group="lb")
            add_edge(root, lbid)

            vpc_id = lb.get("VpcId") or "unknown-vpc"
            vpc_ref = _id(f"{arn}:{vpc_id}", "vpc")
            add_node(vpc_ref, f"VPC\n{vpc_id}", "vpc", payload={"ref": {"kind": "vpc", "id": vpc_id}, "lb": name}, level=2, group="vpc")
            add_edge(lbid, vpc_ref, "targets-vpc")

            # Downstream buckets
            n_eks = len(eks_by_vpc.get(vpc_id, []))
            n_rds = len(rds_by_vpc.get(vpc_id, []))
            n_lbs = len(lbs_by_vpc.get(vpc_id, []))

            b_down = _id(f"{arn}:{vpc_id}:downstream", "bucket")
            add_node(b_down, "Downstream", "bucket", payload={"vpc": vpc_id, "bucket": "downstream"}, level=3, group="bucket")
            add_edge(vpc_ref, b_down)

            b_eks = _id(f"{arn}:{vpc_id}:eks", "bucket")
            add_node(b_eks, f"EKS\n({n_eks})", "bucket", payload={"vpc": vpc_id, "bucket": "eks"}, level=4, group="bucket")
            add_edge(b_down, b_eks)

            b_rds = _id(f"{arn}:{vpc_id}:rds", "bucket")
            add_node(b_rds, f"RDS\n({n_rds})", "bucket", payload={"vpc": vpc_id, "bucket": "rds"}, level=4, group="bucket")
            add_edge(b_down, b_rds)

            if ingress_include_internal:
                b_lbs = _id(f"{arn}:{vpc_id}:lbs", "bucket")
                add_node(b_lbs, f"Load Balancers\n({n_lbs})", "bucket", payload={"vpc": vpc_id, "bucket": "lbs"}, level=4, group="bucket")
                add_edge(b_down, b_lbs)

            # EKS clusters under VPC
            for c in sorted(eks_by_vpc.get(vpc_id, []), key=lambda x: str(x.get("name") or "")):
                cname = c.get("name") or c.get("clusterName") or "eks"
                cnid = _id(f"{arn}:{vpc_id}:{cname}", "eks")
                add_node(cnid, f"EKS\n{cname}", "eks", payload=c, level=5, group="eks")
                add_edge(b_eks, cnid)

                # keep it simple unless you ask for more
                if detail_level >= 2:
                    for ng in as_list(c.get("nodegroups")):
                        if not isinstance(ng, dict):
                            continue
                        ng_name = ng.get("nodegroupName") or "nodegroup"
                        ngnid = _id(f"{arn}:{vpc_id}:{cname}:{ng_name}", "ng")
                        add_node(ngnid, f"Nodegroup\n{ng_name}", "nodegroup", payload=ng, level=6, group="nodegroup")
                        add_edge(cnid, ngnid, "has")

            # RDS
            for db in sorted(rds_by_vpc.get(vpc_id, []), key=lambda x: str(x.get("DBInstanceIdentifier") or "")):
                dbid = db.get("DBInstanceIdentifier") or "rds"
                rnid = _id(f"{arn}:{vpc_id}:{dbid}", "rds")
                engine = db.get("Engine") or ""
                label = f"RDS\n{dbid}" + (f"\n{engine}" if engine else "")
                add_node(rnid, label, "rds", payload=db, level=5, group="rds")
                add_edge(b_rds, rnid)

            # internal LBs
            if ingress_include_internal:
                for ilb in sorted(lbs_by_vpc.get(vpc_id, []), key=lambda x: str(x.get("LoadBalancerName") or "")):
                    if not isinstance(ilb, dict):
                        continue
                    if ilb.get("Scheme") == "internet-facing":
                        continue
                    iname = ilb.get("LoadBalancerName") or "lb"
                    iarn = ilb.get("LoadBalancerArn") or iname
                    inid = _id(f"{arn}:{vpc_id}:{iarn}", "lb")
                    add_node(inid, f"LB\n{iname}", "lb", payload=ilb, level=5, group="lb")
                    add_edge(b_lbs, inid)

            if len(nodes) > max_nodes:
                break

    if style.startswith("eks"):
        build_eks_centered()
    elif style.startswith("ing"):
        build_ingress_centered()
    else:
        build_vpc_centered()

    return nodes, edges, payloads

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

        if not HAS_AGRAPH:
            st.warning("streamlit-agraph is not installed; showing JSON only.")
            st.json(snap)
        else:
            with st.expander("Hierarchy view controls", expanded=True):
                view_style_label = st.selectbox(
                    "Diagram style",
                    [
                        "VPC-centered (default)",
                        "EKS-centered",
                        "Ingress-centered",
                    ],
                    index=0,
                    help="Switch the root of the diagram. All styles render as a hierarchy-first (family tree) to stay readable.",
                )
                view_style = {
                    "VPC-centered (default)": "vpc",
                    "EKS-centered": "eks",
                    "Ingress-centered": "ingress",
                }[view_style_label]

                if view_style == "vpc":
                    st.caption("**VPC-centered:** Region → VPC → buckets → resources. Best default for most accounts.")
                elif view_style == "eks":
                    st.caption("**EKS-centered:** Region → EKS → Nodegroups → (subnets/SGs). Great for cluster troubleshooting.")
                else:
                    st.caption("**Ingress-centered:** Internet-facing load balancers → VPC → downstream (EKS/RDS/etc). Great for traffic-path conversations.")

                ingress_include_internal = False
                if view_style == "ingress":
                    ingress_include_internal = st.checkbox(
                        "Include internal load balancers under downstream",
                        value=False,
                        help="Adds internal LBs found in the same VPC as additional downstream nodes (requires \"Include non-internet LBs in snapshot\" in the sidebar).",
                    )

                detail_level = st.slider(
                    "Detail level (0 = VPC summary, 3 = full subnets/SGs + placement edges)",
                    min_value=0,
                    max_value=3,
                    value=2,
                )
                show_subnet_nodes = st.checkbox("Show subnet nodes", value=(detail_level >= 3))
                show_sg_nodes = st.checkbox("Show security group nodes", value=(detail_level >= 3))
                show_placement_edges = st.checkbox(
                    "Show placement edges (resource → subnet/SG). Can add clutter.",
                    value=False,
                    disabled=not (show_subnet_nodes or show_sg_nodes),
                )

            nodes, edges, payloads = build_hierarchy_graph(
                snap,
                style=view_style,
                ingress_include_internal=ingress_include_internal,
                max_edges=controls["max_edges"],
                detail_level=detail_level,
                show_subnet_nodes=show_subnet_nodes,
                show_sg_nodes=show_sg_nodes,
                show_placement_edges=show_placement_edges,
            )

            left, right = st.columns([2, 1], gap="large")

            with left:
                # Prefer a tree layout to avoid node overlap.
                try:
                    config = Config(
                        width="100%",
                        height=720,
                        directed=True,
                        physics=False,
                        hierarchical=True,
                    )
                except TypeError:
                    # Older streamlit-agraph versions may not support hierarchical=True.
                    config = Config(
                        width="100%",
                        height=720,
                        directed=True,
                        physics=False,
                    )

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
