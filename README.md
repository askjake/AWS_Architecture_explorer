# AWS Architecture Explorer

Interactive Streamlit app + snapshot collector that builds an **AWS architecture graph** from the outside-in and a hierarchy view.

It’s designed for architecture/security discovery without requiring `kubectl`:
- Discover **EKS clusters → nodegroups → subnets → security groups**
- Discover **internet-facing ALB/NLB** first, then expand into SG relationships (“outside-in” review)
- Pull **RDS** exposure context
- Report **S3 bucket versioning** status (handles AccessDenied gracefully)

> Default SSH host: `david-bastion` (override via `--bastion`).

---

## Repo contents

- `collect_snapshot.py` – CLI snapshot collector (writes a JSON snapshot)
- `aws_architecture_snapshot_lib.py` – discovery + snapshot library
- `aws_architecture_explorer_app.py` – Streamlit UI (2 tabs: hierarchy + outside-in)
- `requirements.txt` – Python deps
- `snapshots/` – local snapshot storage (ignored by git except `.gitkeep`)
- `scripts/` – install/update/run helpers for Windows + Linux

---

## Prerequisites

### 1) SSH access to a bastion that can run AWS CLI
These tools execute AWS CLI **on the bastion** via:

```
ssh david-bastion -- bash -lc '<aws ... --output json>'
```

So you need:
- `ssh` working from your machine (`ssh david-bastion` succeeds)
- AWS CLI installed + configured on the bastion for the target account/role
- Network access to AWS APIs from the bastion

Tip: put a `Host david-bastion` entry in your SSH config (`~/.ssh/config` on Linux/macOS, `C:\Users\<you>\.ssh\config` on Windows).

### 2) Python 3.10+ locally
Windows: `py -3.12 --version` should work  
Linux: `python3 --version` should work

---

## Quick start

### A) Install deps
**Windows**
```bat
scripts\install_windows.bat
```

**Linux**
```bash
chmod +x scripts/*.sh
./scripts/install_linux.sh
```

### B) Collect a snapshot
Example (us-west-2, include S3 versioning report):
```bash
python collect_snapshot.py --region us-west-2 --include-s3 --out snapshots/my_snapshot.json
```

Notes:
- If an S3 bucket has an explicit deny, the snapshot will include an error string for that bucket instead of failing the whole run.

### C) Run the UI
```bash
streamlit run aws_architecture_explorer_app.py --server.address 0.0.0.0 --server.port 8504
```

The sidebar lets you:
- pick an existing snapshot JSON from `snapshots/`
- run a fresh snapshot and persist it
- tune graph density

---

## Common workflows

### Architecture overview (hierarchy)
Tab **Hierarchy view**:
- VPC → subnets → EKS clusters/nodegroups → SGs, etc.

### Security review (outside-in)
Tab **Outside‑in security review**:
- Internet → public ALB/NLB → SG relationships → downstream resources
- RDS: highlights `PubliclyAccessible` + SG exposure combo

### S3 versioning report
Sidebar → enable **Include S3 versioning** during snapshot collection.

---

## Troubleshooting

### “Command did not return JSON”
Your bastion command printed non-JSON output. Typical causes:
- shell startup scripts printing environment/debug output
- AWS CLI not installed, not on PATH, or `aws` alias/function conflicts

The snapshot lib runs `bash -lc` to use a predictable shell. If you still see noise, clean up `.bashrc/.bash_profile` on the bastion.

### AccessDenied for S3 versioning
Some buckets have explicit deny on `s3:GetBucketVersioning`. This is expected in some environments.
The collector will record the error per bucket and keep going.

---

## Repos

Primary (internal):
- `git@git.dtc.dish.corp:montjac/AWS_Architecture_explorer.git`

Backup (public):
- `https://github.com/askjake/AWS_Architecture_explorer.git`
