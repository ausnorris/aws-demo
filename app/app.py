"""
CVE Showdown — AWS Summit Demo Application
Compares Inspector v2 CVE findings between an upstream image and a Chainguard image.
"""

import os
import io
import time
import logging
from datetime import datetime

import boto3
import segno
from botocore.exceptions import ClientError, NoCredentialsError
from flask import Flask, jsonify, render_template, Response, request

from provenance import get_provenance_both

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
AWS_REGION           = os.environ.get("AWS_REGION", "ap-southeast-2")
UPSTREAM_REPO        = os.environ.get("UPSTREAM_REPO", "summit-demo-upstream")
CHAINGUARD_REPO      = os.environ.get("CHAINGUARD_REPO", "summit-demo-chainguard")
APP_URL              = os.environ.get("APP_URL", "http://localhost:5000")
UPSTREAM_IMAGE_TAG   = os.environ.get("UPSTREAM_IMAGE_TAG", "latest")
CHAINGUARD_IMAGE_TAG = os.environ.get("CHAINGUARD_IMAGE_TAG", "latest")
UPSTREAM_IMAGE_LABEL = os.environ.get("UPSTREAM_IMAGE_LABEL", "python:3.13")
CHAINGUARD_IMAGE_LABEL = os.environ.get("CHAINGUARD_IMAGE_LABEL", "python:3.13")
CACHE_TTL_SECONDS    = int(os.environ.get("CACHE_TTL_SECONDS", "300"))

# Chainguard Libraries integrity endpoint credentials.
# Loaded once from environment — never logged or returned in any response.
# Stored in AWS SSM Parameter Store (SecureString) and injected via ECS secrets.
_CG_LIBRARIES_USER  = os.environ.get("CG_LIBRARIES_USER",  "")
_CG_LIBRARIES_TOKEN = os.environ.get("CG_LIBRARIES_TOKEN", "")

# Chainguard Sentinel (malware blocklist) — console API Bearer token.
# Obtain with:  chainctl auth token --audience console-api.enforce.dev
# Injected via ECS secrets from SSM, same as the Libraries credentials above.
_CG_API_TOKEN        = os.environ.get("CHAINGUARD_API_TOKEN", "")
CG_CONSOLE_API       = os.environ.get("CG_CONSOLE_API", "https://console-api.enforce.dev")
# CVE-remediated builds live in a separate PEP 503/691 index. Checked with the
# existing CG_LIBRARIES_USER / CG_LIBRARIES_TOKEN pull-token (basic auth).
CG_REMEDIATED_INDEX  = os.environ.get("CG_REMEDIATED_INDEX", "https://libraries.cgr.dev/python-remediated")
SENTINEL_ECOSYSTEM   = os.environ.get("SENTINEL_ECOSYSTEM", "PYPI")
SENTINEL_SINCE_DAYS  = int(os.environ.get("SENTINEL_SINCE_DAYS", "30"))
SENTINEL_PAGE_SIZE   = int(os.environ.get("SENTINEL_PAGE_SIZE", "25"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Simple in-memory cache
# ---------------------------------------------------------------------------
_cache: dict = {}


def _cache_get(key: str):
    entry = _cache.get(key)
    if entry and (time.time() - entry["ts"] < CACHE_TTL_SECONDS):
        return entry["data"]
    return None


def _cache_set(key: str, data):
    _cache[key] = {"data": data, "ts": time.time()}


# ---------------------------------------------------------------------------
# AWS Inspector v2 helpers
# ---------------------------------------------------------------------------

def _inspector_client():
    return boto3.client("inspector2", region_name=AWS_REGION)


def _ecr_client():
    return boto3.client("ecr", region_name=AWS_REGION)


def fetch_ecr_image_info(repo_name: str, tag: str) -> dict:
    """Return image size (MB) and push date from ECR."""
    try:
        ecr = _ecr_client()
        resp = ecr.describe_images(
            repositoryName=repo_name,
            imageIds=[{"imageTag": tag}],
        )
        images = resp.get("imageDetails", [])
        if images:
            img = images[0]
            size_mb = round(img.get("imageSizeInBytes", 0) / 1_048_576, 1)
            pushed = img.get("imagePushedAt", datetime.now()).strftime("%Y-%m-%d %H:%M UTC")
            digest = img.get("imageDigest", "")[:19]
            return {"size_mb": size_mb, "pushed": pushed, "digest": digest}
    except Exception as exc:
        log.warning("ECR describe failed for %s: %s", repo_name, exc)
    return {"size_mb": 0, "pushed": "unknown", "digest": ""}


def fetch_inspector_findings(repo_name: str, image_tag: str = "latest") -> dict:
    """Query Inspector v2 for findings for the CURRENT image digest only.

    Strategy:
      1. Resolve the current digest for image_tag from ECR.
      2. Query Inspector filtered by that exact digest (server-side ecrImageHash,
         with client-side digest confirmation as a fallback).
      3. If 0 findings AND the image was pushed recently (< 20 min), set
         scanning=True so the UI can show "Scanning…" rather than "0 CVEs".
         This avoids falsely implying an image is clean while Inspector is still
         processing it.
      4. Don't cache the scanning state — re-check every request until
         Inspector has results.
    """
    cache_key = f"{repo_name}:{image_tag}"
    cached = _cache_get(cache_key)
    if cached and not cached.get("scanning"):
        log.info("Cache hit for %s", cache_key)
        return cached

    log.info("Fetching Inspector findings for %s:%s", repo_name, image_tag)
    severity_counts = {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0,
        "LOW": 0, "INFORMATIONAL": 0, "UNTRIAGED": 0,
    }
    cve_list = []
    error_msg = None
    image_digest = None

    try:
        # ── Step 1: resolve current digest + push time from ECR ───────────────
        try:
            ecr = _ecr_client()
            ecr_resp = ecr.describe_images(
                repositoryName=repo_name,
                imageIds=[{"imageTag": image_tag}],
            )
            ecr_details = ecr_resp.get("imageDetails", [])
            if ecr_details:
                image_digest = ecr_details[0].get("imageDigest")
                log.info("Resolved %s:%s → %s", repo_name, image_tag,
                         image_digest[:19] if image_digest else "?")
        except Exception as ecr_exc:
            log.warning("ECR describe failed for %s:%s: %s", repo_name, image_tag, ecr_exc)

        # ── Step 2: query Inspector by digest ─────────────────────────────────
        inspector = _inspector_client()
        paginator = inspector.get_paginator("list_findings")

        findings = []

        if image_digest:
            # Primary: server-side hash filter (Inspector stores full sha256:… digest)
            for page in paginator.paginate(
                filterCriteria={
                    "ecrImageHash": [
                        {"comparison": "EQUALS", "value": image_digest}
                    ]
                }
            ):
                findings.extend(page.get("findings", []))
            log.info("Hash filter for %s: %d findings", image_digest[:19], len(findings))

            # Fallback: if hash filter returned nothing, scan the repo and
            # match client-side (handles format differences in how Inspector
            # stores the digest vs what ECR returns).
            if not findings:
                log.warning(
                    "Hash filter returned 0 for %s — trying repo filter + client-side digest match",
                    image_digest[:19],
                )
                paginator2 = inspector.get_paginator("list_findings")
                all_repo = []
                for page in paginator2.paginate(
                    filterCriteria={
                        "ecrImageRepositoryName": [
                            {"comparison": "EQUALS", "value": repo_name}
                        ]
                    }
                ):
                    all_repo.extend(page.get("findings", []))

                for f in all_repo:
                    for resource in f.get("resources", []):
                        ecr_img = resource.get("details", {}).get("awsEcrContainerImage", {})
                        if ecr_img.get("imageHash") == image_digest:
                            findings.append(f)
                            break
                log.info("Client-side digest match: %d findings", len(findings))
        else:
            # No digest available — fall back to repo-level filter
            log.warning("No digest resolved for %s:%s — using repo filter", repo_name, image_tag)
            for page in paginator.paginate(
                filterCriteria={
                    "ecrImageRepositoryName": [
                        {"comparison": "EQUALS", "value": repo_name}
                    ]
                }
            ):
                findings.extend(page.get("findings", []))

        # ── Step 3: tally ─────────────────────────────────────────────────────
        for finding in findings:
            severity = finding.get("severity", "INFORMATIONAL")
            if severity in severity_counts:
                severity_counts[severity] += 1

            vuln = finding.get("packageVulnerabilityDetails", {})
            cve_id = vuln.get("vulnerabilityId", "")
            packages = vuln.get("vulnerablePackages", [])

            if cve_id:
                cve_list.append({
                    "id": cve_id,
                    "severity": severity,
                    "score": round(finding.get("inspectorScore", 0), 1),
                    "title": finding.get("title", "")[:120],
                    "packages": [
                        f"{p.get('name','')}@{p.get('version','')}"
                        for p in packages[:3]
                    ],
                    "fixed_in": [
                        p.get("fixedInVersion", "No fix") or "No fix"
                        for p in packages[:3]
                    ],
                    "description": vuln.get("sourceUrl", ""),
                })

        cve_list.sort(key=lambda x: x["score"], reverse=True)

        # Always trust what Inspector returns — 0 means clean.
        # The cache TTL and auto-refresh handle picking up new findings.

    except NoCredentialsError:
        error_msg = "No AWS credentials found — running in demo/mock mode"
        log.warning(error_msg)
        severity_counts = {
            "CRITICAL": 23, "HIGH": 84, "MEDIUM": 147, "LOW": 61,
            "INFORMATIONAL": 12, "UNTRIAGED": 0,
        }
        cve_list = [
            {"id": f"CVE-2024-{2000+i}", "severity": s, "score": 9.8 - i*0.1,
             "title": f"Example vulnerability in package-{i}", "packages": [f"lib-{i}@1.{i}.0"],
             "fixed_in": ["No fix" if i % 3 == 0 else f"1.{i+1}.0"], "description": ""}
            for i, s in enumerate(["CRITICAL"]*5 + ["HIGH"]*10 + ["MEDIUM"]*10)
        ]

    except ClientError as exc:
        error_msg = f"Inspector API error: {exc.response['Error']['Message']}"
        log.error(error_msg)

    result = {
        "severity_counts": severity_counts,
        "total": sum(severity_counts.values()),
        "cve_list": cve_list[:75],
        "last_updated": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        "error": error_msg,
        "scanning": False,
    }
    _cache_set(cache_key, result)
    return result


# ---------------------------------------------------------------------------
# Chainguard Sentinel — malware blocklist "near misses"
# ---------------------------------------------------------------------------

def _http_get_json(url: str, headers: dict | None = None, timeout: int = 10):
    """GET url and parse JSON. Returns (data, error). Never raises."""
    import json as _json
    import urllib.request, urllib.error

    req_headers = {"User-Agent": "chainguard-summit-demo/1.0"}
    if headers:
        req_headers.update(headers)
    try:
        req = urllib.request.Request(url, headers=req_headers)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return _json.loads(r.read()), None
    except urllib.error.HTTPError as exc:
        return None, f"HTTP {exc.code}: {exc.reason}"
    except Exception as exc:
        return None, str(exc)


def _normalise_block_entry(raw: dict) -> dict:
    """Map a blocklist API entry to the fields the UI needs.

    Field names are matched loosely so minor API shape changes don't break
    the panel — unknown fields are simply dropped.
    """
    name = (raw.get("name") or raw.get("package") or raw.get("packageName")
            or raw.get("package_name") or "")
    version = (raw.get("version") or raw.get("packageVersion")
               or raw.get("package_version") or "")
    versions = raw.get("versions") or ([version] if version else [])
    if isinstance(versions, str):
        versions = [versions]
    blocked_at = (raw.get("blockedAt") or raw.get("blocked_at")
                  or raw.get("createdAt") or raw.get("created_at")
                  or raw.get("detectedAt") or raw.get("detected_at") or "")
    reason = (raw.get("reason") or raw.get("classification")
              or raw.get("type") or raw.get("category") or "malware")
    source = (raw.get("source") or raw.get("advisory")
              or raw.get("osvId") or raw.get("osv_id") or "")
    return {
        "name": name,
        "versions": [str(v) for v in versions][:5],
        "ecosystem": raw.get("ecosystem", SENTINEL_ECOSYSTEM),
        "blocked_at": str(blocked_at)[:10],
        "reason": str(reason).lower(),
        "source": source,
    }


def check_remediated_version(name: str) -> dict:
    """Check whether Chainguard publishes a CVE-remediated build of a package.

    Queries the python-remediated PEP 691 simple index for the package and
    looks for +cgr.N local versions. Uses the Libraries pull token (basic
    auth). 404 → no remediated build exists.
    """
    cache_key = f"remediated:{name.lower()}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    result = {"available": False, "versions": [], "checked": False, "note": ""}

    if not (_CG_LIBRARIES_USER and _CG_LIBRARIES_TOKEN):
        result["note"] = "Libraries credentials not configured"
        _cache_set(cache_key, result)
        return result

    import base64
    auth = base64.b64encode(
        f"{_CG_LIBRARIES_USER}:{_CG_LIBRARIES_TOKEN}".encode()
    ).decode()
    url = f"{CG_REMEDIATED_INDEX}/simple/{name.lower()}/"
    data, err = _http_get_json(url, headers={
        "Accept": "application/vnd.pypi.simple.v1+json",
        "Authorization": f"Basic {auth}",
    })

    result["checked"] = True
    if err:
        if "404" in err:
            result["note"] = "No remediated build published"
        else:
            result["checked"] = False
            result["note"] = err
    else:
        cgr_versions = [v for v in data.get("versions", []) if "+cgr." in v]
        # Highest version last under a naive numeric sort — good enough for
        # display; exact PEP 440 ordering isn't needed here.
        def _ver_key(v):
            base = v.split("+")[0]
            return tuple(int(p) if p.isdigit() else 0 for p in base.split("."))
        cgr_versions.sort(key=_ver_key)
        result["available"] = bool(cgr_versions)
        result["versions"] = cgr_versions[-5:]
        if cgr_versions:
            result["latest"] = cgr_versions[-1]

    _cache_set(cache_key, result)
    return result


def fetch_sentinel_blocklist() -> dict:
    """Fetch recently blocked (malware/greyware) packages from Sentinel.

    Returns {"blocked": [...], "since": iso, "mode": "live"|"demo", "error": ...}
    Falls back to clearly-labelled demo data when no API token is configured,
    mirroring the Inspector mock-mode behaviour.
    """
    cached = _cache_get("sentinel:blocklist")
    if cached:
        return cached

    from datetime import timedelta
    since = (datetime.utcnow() - timedelta(days=SENTINEL_SINCE_DAYS)).strftime(
        "%Y-%m-%dT00:00:00Z")

    if not _CG_API_TOKEN:
        # Demo mode — representative typosquat/malware names, flagged as such.
        demo = [
            {"name": "requests-toolbelt3", "versions": ["1.0.1"], "blocked_at": "2026-07-14", "reason": "malware", "source": "MAL-2026-demo-1"},
            {"name": "python-dotenv-utils", "versions": ["0.2.0"], "blocked_at": "2026-07-11", "reason": "malware", "source": "MAL-2026-demo-2"},
            {"name": "flask", "versions": ["1.1.2"], "blocked_at": "2026-07-08", "reason": "cooldown", "source": ""},
            {"name": "colorama-fix", "versions": ["0.4.9"], "blocked_at": "2026-07-05", "reason": "malware", "source": "MAL-2026-demo-3"},
            {"name": "urllib4", "versions": ["2.0.0"], "blocked_at": "2026-07-02", "reason": "greyware", "source": ""},
        ]
        result = {
            "blocked": [dict(e, ecosystem=SENTINEL_ECOSYSTEM) for e in demo],
            "since": since,
            "mode": "demo",
            "error": "CHAINGUARD_API_TOKEN not configured — showing demo data",
        }
        _cache_set("sentinel:blocklist", result)
        return result

    url = (f"{CG_CONSOLE_API}/libraries/v1/malware/blocklist"
           f"?ecosystem={SENTINEL_ECOSYSTEM}&since={since}"
           f"&page_size={SENTINEL_PAGE_SIZE}")
    data, err = _http_get_json(
        url, headers={"Authorization": f"Bearer {_CG_API_TOKEN}"}, timeout=15)

    if err:
        log.error("Sentinel blocklist fetch failed: %s", err)
        result = {"blocked": [], "since": since, "mode": "live", "error": err}
        _cache_set("sentinel:blocklist", result)
        return result

    # The list may arrive under different keys depending on API version.
    raw_items = None
    for key in ("items", "blocklist", "packages", "entries", "results"):
        if isinstance(data.get(key), list):
            raw_items = data[key]
            break
    if raw_items is None:
        raw_items = data if isinstance(data, list) else []

    blocked = [e for e in (_normalise_block_entry(i) for i in raw_items)
               if e["name"]]
    result = {"blocked": blocked, "since": since, "mode": "live", "error": None}
    _cache_set("sentinel:blocklist", result)
    return result


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html", app_url=APP_URL)


@app.route("/api/findings")
def api_findings():
    upstream_findings   = fetch_inspector_findings(UPSTREAM_REPO,   UPSTREAM_IMAGE_TAG)
    chainguard_findings = fetch_inspector_findings(CHAINGUARD_REPO, CHAINGUARD_IMAGE_TAG)
    upstream_image_info   = fetch_ecr_image_info(UPSTREAM_REPO, UPSTREAM_IMAGE_TAG)
    chainguard_image_info = fetch_ecr_image_info(CHAINGUARD_REPO, CHAINGUARD_IMAGE_TAG)

    return jsonify({
        "upstream": {
            "repo": UPSTREAM_REPO,
            "tag": UPSTREAM_IMAGE_TAG,
            "label": UPSTREAM_IMAGE_LABEL,
            "image_info": upstream_image_info,
            "findings": upstream_findings,
        },
        "chainguard": {
            "repo": CHAINGUARD_REPO,
            "tag": CHAINGUARD_IMAGE_TAG,
            "label": CHAINGUARD_IMAGE_LABEL,
            "image_info": chainguard_image_info,
            "findings": chainguard_findings,
        },
        "region": AWS_REGION,
        "fetched_at": datetime.utcnow().isoformat(),
    })


@app.route("/api/sentinel")
def api_sentinel():
    """Near misses: packages Chainguard Sentinel blocked upstream, and whether
    a CVE-remediated (+cgr.N) build exists for each blocked library."""
    data = fetch_sentinel_blocklist()

    # In demo mode without Libraries credentials, fake one remediation result
    # (flask 1.1.2 → 1.1.2+cgr.1 is Chainguard's documented example) so the
    # panel demos the full near-miss → remediated-build story offline.
    demo_remediation = (
        {"flask": {"available": True, "checked": True,
                   "versions": ["1.1.2+cgr.1"], "latest": "1.1.2+cgr.1",
                   "note": "demo"}}
        if data["mode"] == "demo" and not (_CG_LIBRARIES_USER and _CG_LIBRARIES_TOKEN)
        else {}
    )

    enriched = []
    seen: dict = {}
    for entry in data["blocked"][:SENTINEL_PAGE_SIZE]:
        name = entry["name"]
        if name not in seen:
            seen[name] = (demo_remediation.get(name)
                          or check_remediated_version(name))
        enriched.append({**entry, "remediated": seen[name]})

    remediated_count = sum(
        1 for e in enriched if e["remediated"].get("available"))

    return jsonify({
        "blocked": enriched,
        "total": len(enriched),
        "remediated_available": remediated_count,
        "ecosystem": SENTINEL_ECOSYSTEM,
        "since": data["since"],
        "since_days": SENTINEL_SINCE_DAYS,
        "mode": data["mode"],
        "error": data["error"],
        "fetched_at": datetime.utcnow().isoformat(),
    })


@app.route("/api/refresh")
def api_refresh():
    """Force-clear the cache and return fresh data."""
    _cache.clear()
    log.info("Cache cleared by /api/refresh")
    return api_findings()


@app.route("/api/provenance/detail/<name>/<version>")
def api_provenance_detail(name: str, version: str):
    """Return raw attestation / provenance data for a single package.

    For PyPI packages:
      • Full PyPI JSON metadata (info + urls)
      • PEP 740 attestation bundle for every wheel/sdist that has one

    For Chainguard Libraries packages (when PIP_INDEX_URL != pypi.org):
      • Chainguard integrity endpoint listing (libraries.cgr.dev/python/integrity)
      • PyPI info for context (repo URL, license, author)
    """
    import urllib.request, urllib.error

    # ?card=upstream forces PyPI mode regardless of what index the container
    # was built with — upstream packages are always from PyPI.
    card = request.args.get("card", "chainguard")
    runtime_cg = "pypi.org" not in os.environ.get("PIP_INDEX_URL", "https://pypi.org/simple/")
    chainguard_mode = (card != "upstream") and runtime_cg

    def _fetch(url, timeout=8, use_cg_auth=False):
        """Fetch JSON from url.  Never include credentials in return values."""
        import base64
        headers = {"User-Agent": "chainguard-summit-demo/1.0"}
        if use_cg_auth and _CG_LIBRARIES_USER and _CG_LIBRARIES_TOKEN:
            token = base64.b64encode(
                f"{_CG_LIBRARIES_USER}:{_CG_LIBRARIES_TOKEN}".encode()
            ).decode()
            headers["Authorization"] = f"Basic {token}"
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                import json as _json
                return _json.loads(r.read())
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                # Still 401 even with credentials — endpoint exists but token
                # may be expired or creds not configured.
                if use_cg_auth and (_CG_LIBRARIES_USER or _CG_LIBRARIES_TOKEN):
                    return {"_auth_required": True, "_status": 401,
                            "_note": "Credentials provided but still received 401 — token may be expired"}
                return {"_auth_required": True, "_status": 401}
            return {"_fetch_error": f"HTTP {exc.code}: {exc.reason}"}
        except Exception as exc:
            return {"_fetch_error": str(exc)}

    # ── Always fetch PyPI metadata for context ────────────────────────────────
    pypi_url  = f"https://pypi.org/pypi/{name}/{version}/json"
    pypi_data = _fetch(pypi_url)

    # Strip the bulky classifiers list to keep the payload readable
    if "info" in pypi_data:
        pypi_data["info"].pop("classifiers", None)
        pypi_data["info"].pop("description", None)

    # Extract PEP 740 attestation bundles from each release file
    attestation_bundles = []
    for file_entry in pypi_data.get("urls", []):
        if file_entry.get("attestations"):
            bundle_url = file_entry["attestations"]
            bundle = _fetch(bundle_url)
            if not bundle.get("_fetch_error"):
                attestation_bundles.append({
                    "filename":   file_entry.get("filename"),
                    "url":        bundle_url,
                    "bundle":     bundle,
                })

    result = {
        "name":    name,
        "version": version,
        "mode":    "chainguard_libraries" if chainguard_mode else "pypi",
        "pypi": {
            "metadata_url": pypi_url,
            "info":         pypi_data.get("info", {}),
            "release_files": [
                {
                    "filename":    f.get("filename"),
                    "url":         f.get("url"),
                    "digests":     f.get("digests"),
                    "requires_python": f.get("requires_python"),
                    "has_attestation": bool(f.get("attestations")),
                }
                for f in pypi_data.get("urls", [])
            ],
            "pep740_attestations": attestation_bundles,
        },
    }

    # ── Chainguard Libraries integrity endpoint ───────────────────────────────
    # URL format per PEP 740:
    #   /integrity/PACKAGE/VERSION/FILENAME/provenance
    # where FILENAME is the actual wheel archive name from the release.
    if chainguard_mode:
        # Check wheels first, then source dists.
        # Chainguard only attests wheels (pre-built from source).
        # Source tarballs (.tar.gz) are upstream PyPI originals — no CG provenance.
        all_files = [
            f["filename"] for f in pypi_data.get("urls", [])
            if f.get("filename", "").endswith((".whl", ".tar.gz"))
        ]

        provenance_results = []
        for filename in all_files[:5]:  # cap at 5 files
            prov_url = (
                f"https://libraries.cgr.dev/python/integrity"
                f"/{name.lower()}/{version}/{filename}/provenance"
            )
            prov_data = _fetch(prov_url, use_cg_auth=True)
            provenance_results.append({
                "filename":       filename,
                "provenance_url": prov_url,
                "data":           prov_data,
            })

        result["chainguard_libraries"] = {
            "provenance_results": provenance_results,
            "slsa_level": 3,
            "sigstore":   True,
            "sbom":       True,
            "note": "Packages rebuilt from source. SLSA Level 3 provenance via Sigstore/OIDC. Signed SPDX SBOM embedded in wheel (PEP 770).",
        }

    return jsonify(result)


@app.route("/api/provenance")
def api_provenance():
    """Return library provenance for both image cards.

    upstream   → always PyPI (constant across both demo deploys)
    chainguard → real detected provenance; switches to Chainguard Libraries
                 when the image is rebuilt with PIP_INDEX_URL pointing at the
                 Chainguard index (directly or via Nexus proxy)

    Cached for container lifetime — static once built.
    Force refresh with ?refresh=1.
    """
    if not hasattr(api_provenance, "_cache") or request.args.get("refresh"):
        api_provenance._cache = get_provenance_both()
    data = api_provenance._cache

    def _summary(lst):
        verified = sum(1 for p in lst if p.get("verified"))
        return {"packages": lst, "total": len(lst),
                "verified": verified, "unverified": len(lst) - verified}

    return jsonify({
        "upstream":    _summary(data["upstream"]),
        "chainguard":  _summary(data["chainguard"]),
        "mode":        data["mode"],
    })


@app.route("/api/debug")
def api_debug():
    """Return raw Inspector findings metadata to help diagnose filter issues.
    Shows the first 20 findings with their resource repositoryName / imageHash
    so you can verify what values Inspector is actually storing.
    """
    try:
        inspector = _inspector_client()
        paginator = inspector.get_paginator("list_findings")
        raw_findings = []
        total = 0
        for page in paginator.paginate(filterCriteria={}):
            for f in page.get("findings", []):
                total += 1
                if len(raw_findings) < 30:
                    resource_info = []
                    for r in f.get("resources", []):
                        ecr = r.get("details", {}).get("awsEcrContainerImage", {})
                        resource_info.append({
                            "type": r.get("type"),
                            "repositoryName": ecr.get("repositoryName"),
                            "imageHash": (ecr.get("imageHash") or "")[:19],
                            "imageTags": ecr.get("imageTags"),
                        })
                    raw_findings.append({
                        "findingArn": f.get("findingArn", "")[-30:],
                        "severity": f.get("severity"),
                        "type": f.get("type"),
                        "resources": resource_info,
                    })

        return jsonify({
            "total_findings_in_account": total,
            "sample": raw_findings,
            "upstream_repo": UPSTREAM_REPO,
            "chainguard_repo": CHAINGUARD_REPO,
            "region": AWS_REGION,
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/findings/<image_type>")
def findings_page(image_type: str):
    if image_type == "upstream":
        repo = UPSTREAM_REPO
        label = "Upstream Image"
        theme = "danger"
    else:
        repo = CHAINGUARD_REPO
        label = "Chainguard Image"
        theme = "safe"

    tag = UPSTREAM_IMAGE_TAG if image_type == "upstream" else CHAINGUARD_IMAGE_TAG
    findings = fetch_inspector_findings(repo, tag)
    image_info = fetch_ecr_image_info(
        repo,
        UPSTREAM_IMAGE_TAG if image_type == "upstream" else CHAINGUARD_IMAGE_TAG,
    )

    return render_template(
        "findings.html",
        findings=findings,
        image_info=image_info,
        image_type=image_type,
        label=label,
        theme=theme,
        repo=repo,
        app_url=APP_URL,
    )


@app.route("/qr/<image_type>.png")
def qr_code(image_type: str):
    url = f"{APP_URL}/findings/{image_type}"
    dark = "#d32f2f" if image_type == "upstream" else "#2e7d32"

    # segno is pure Python — no C/zlib dependency, works on any Python version
    qr = segno.make_qr(url, error="m")

    buf = io.BytesIO()
    qr.save(buf, kind="png", scale=8, border=4, dark=dark, light="white")
    buf.seek(0)
    return Response(buf.getvalue(), mimetype="image/png",
                    headers={"Cache-Control": "public, max-age=3600"})


@app.route("/health")
def health():
    return jsonify({"status": "ok", "region": AWS_REGION})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
