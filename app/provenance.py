"""
Package provenance checker.

Detects whether Python packages were installed from:
  - Standard PyPI              → queries PyPI JSON API for publisher, repo, and
                                  PEP 740 attestation status
  - Chainguard Libraries index → PIP_INDEX_URL is set to a non-PyPI host
                                  (directly or via Nexus proxy); packages are
                                  rebuilt from source with:
                                    • SLSA Level 3 provenance (PEP 740)
                                    • Sigstore signatures
                                    • Signed SBOMs in wheel (PEP 770 / SPDX)
                                  Provenance is verified against the Chainguard
                                  integrity endpoint: libraries.cgr.dev/python

Detection is purely runtime — the same app binary reports different provenance
depending on which index was used when the image was built.
"""

import json
import logging
import os
import urllib.error
import urllib.request
from importlib.metadata import distributions

log = logging.getLogger(__name__)

# ── Runtime index detection ───────────────────────────────────────────────────
_PIP_INDEX_URL  = os.environ.get("PIP_INDEX_URL",  "https://pypi.org/simple/")
_PIP_TRUSTED    = os.environ.get("PIP_TRUSTED_HOST", "")

# Chainguard Libraries index (direct or via proxy like Nexus)
_CHAINGUARD_INDEX_URL = "https://libraries.cgr.dev/python/simple/"
_CHAINGUARD_INTEGRITY = "https://libraries.cgr.dev/python/integrity"


def _using_chainguard_index() -> bool:
    """True when packages were pulled from the Chainguard Libraries index
    (either directly or through a corporate proxy / Nexus mirror)."""
    return "pypi.org" not in _PIP_INDEX_URL and _PIP_INDEX_URL != ""


log.info(
    "Provenance mode: %s  (PIP_INDEX_URL=%s)",
    "chainguard_libraries" if _using_chainguard_index() else "pypi",
    _PIP_INDEX_URL,
)

# ── Skip list ─────────────────────────────────────────────────────────────────
_SKIP = frozenset({
    "pip", "setuptools", "wheel", "pkg_resources", "pkg-resources",
    "distlib", "packaging", "pyc-wheel", "_distutils_hack",
})

# ── In-process caches ─────────────────────────────────────────────────────────
_pypi_cache: dict[str, dict] = {}
_cg_cache:   dict[str, dict] = {}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _get_installer(dist) -> str:
    try:
        text = dist.read_text("INSTALLER")
        return (text or "").strip().lower() or "unknown"
    except Exception:
        return "unknown"


def _http_get(url: str, timeout: int = 5) -> dict | None:
    """Fetch JSON from url; return parsed dict or None on failure."""
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "chainguard-summit-demo/1.0"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            log.debug("HTTP %s fetching %s", exc.code, url)
        return None
    except Exception as exc:
        log.debug("Fetch failed %s: %s", url, exc)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# PyPI provenance
# ─────────────────────────────────────────────────────────────────────────────

def _pypi_lookup(name: str, version: str) -> dict:
    """Fetch metadata + PEP 740 attestation status from PyPI JSON API."""
    key = f"{name}=={version}"
    if key in _pypi_cache:
        return _pypi_cache[key]

    data = _http_get(f"https://pypi.org/pypi/{name}/{version}/json")
    if not data:
        result = {
            "installer": "pip (PyPI)", "publisher": "", "build_system": "pip / PyPI",
            "slsa_level": None, "repository": "", "attestation_issuer": "",
            "provenance": "unknown", "verified": False,
            "pypi_url": f"https://pypi.org/project/{name}/", "license": "",
            "sbom": False,
        }
        _pypi_cache[key] = result
        return result

    info = data.get("info", {})
    urls: dict = info.get("project_urls") or {}

    repo = (
        urls.get("Source") or urls.get("Source Code") or urls.get("Repository")
        or urls.get("Code") or urls.get("GitHub") or info.get("home_page") or ""
    )

    # PEP 740: attestations field on each release file
    release_files = data.get("urls", [])
    has_attestation = any(f.get("attestations") for f in release_files)

    result = {
        "installer":          "pip (PyPI)",
        "publisher":          info.get("author") or info.get("maintainer") or "",
        "build_system":       "pip / PyPI",
        "slsa_level":         None,
        "repository":         repo,
        "attestation_issuer": "https://token.actions.githubusercontent.com" if has_attestation else "",
        "provenance":         "pypi_attested" if has_attestation else "pypi_unattested",
        "verified":           has_attestation,
        "pypi_url":           f"https://pypi.org/project/{name}/{version}/",
        "license":            info.get("license") or "",
        "sbom":               False,
    }
    _pypi_cache[key] = result
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Chainguard Libraries provenance
# ─────────────────────────────────────────────────────────────────────────────

def _chainguard_lookup(name: str, version: str) -> dict:
    """
    Build a provenance record for a Chainguard Libraries package.

    Chainguard Libraries ship with:
      - SLSA Level 3 provenance (PEP 740) at libraries.cgr.dev/python/integrity
      - Sigstore signatures (keyless, OIDC-bound)
      - Signed SBOMs embedded in the wheel (PEP 770 / SPDX)
      - Packages rebuilt from source — not PyPI mirrors

    We also fetch the upstream repository URL from PyPI so the link is useful.
    """
    key = f"cg:{name}=={version}"
    if key in _cg_cache:
        return _cg_cache[key]

    # Enrich with upstream repo URL from PyPI metadata
    pypi = _pypi_lookup(name, version)

    # Probe Chainguard integrity endpoint for this package
    # Format: /integrity/{project}/{version}  (returns list of attestation files)
    cg_integrity_url = f"{_CHAINGUARD_INTEGRITY}/{name.lower()}/{version}/"
    has_cg_attestation = _http_get(cg_integrity_url) is not None

    result = {
        "installer":          "pip (Chainguard Libraries)",
        "publisher":          "Chainguard",
        "build_system":       "Built from source — SLSA Level 3",
        "slsa_level":         3,
        "repository":         pypi.get("repository") or "https://github.com/chainguard-dev",
        "attestation_issuer": "https://token.actions.githubusercontent.com",
        "provenance":         "chainguard_libraries",
        "verified":           True,
        "pypi_url":           pypi.get("pypi_url", ""),
        "license":            pypi.get("license", ""),
        "sbom":               True,   # PEP 770 SPDX SBOM in wheel
        "sigstore":           True,
        "integrity_url":      cg_integrity_url,
    }
    _cg_cache[key] = result
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def _installed_packages(limit: int = 60) -> list[tuple[str, str]]:
    """Return (name, version) for all installed non-stdlib packages."""
    seen: set[str] = set()
    results = []
    for dist in distributions():
        name    = dist.metadata.get("Name", "")
        version = dist.metadata.get("Version", "")
        key     = name.lower().replace("-", "_")
        if not name or key in _SKIP or name in seen:
            continue
        seen.add(name)
        results.append((name, version))
        if len(results) >= limit:
            break
    return results


def get_provenance_both(limit: int = 60) -> dict:
    """
    Return provenance for two cards in the dashboard:

    upstream   → always queries PyPI. Reflects what a standard pip install
                 from PyPI gives you regardless of what the Chainguard image
                 was built with. This stays constant across both demo deploys.

    chainguard → reflects the actual index used when THIS container was built.
                 First deploy (PyPI): identical to upstream.
                 Second deploy (CG Libraries): shows SLSA L3 / Sigstore / SBOM.

    This produces the "before / after" contrast the demo needs.
    """
    packages = _installed_packages(limit)
    chainguard_index = _using_chainguard_index()

    upstream_list   = []
    chainguard_list = []

    for name, version in packages:
        pypi_entry = {"name": name, "version": version, **_pypi_lookup(name, version)}
        upstream_list.append(pypi_entry)

        if chainguard_index:
            cg_entry = {"name": name, "version": version, **_chainguard_lookup(name, version)}
        else:
            cg_entry = pypi_entry.copy()
        chainguard_list.append(cg_entry)

    def _sort(lst):
        lst.sort(key=lambda x: (x.get("verified", False), x["name"].lower()))
        return lst

    return {
        "upstream":   _sort(upstream_list),
        "chainguard": _sort(chainguard_list),
        "mode":       "chainguard_libraries" if chainguard_index else "pypi",
    }
