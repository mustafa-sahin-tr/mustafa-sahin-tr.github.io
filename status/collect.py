#!/usr/bin/env python3
"""Builds surumler/status.json: which shared-package version each game pins and what is on each store track.

Reads status/games.json (the only hand-kept file), then:
  - GitHub: each game's Packages/manifest.json and ProjectSettings.asset, and each package's package.json
    on the packages repo's default branch (= its latest released version).
  - App Store Connect: App Store versions (live / in review) and the newest TestFlight build.
  - Google Play: production, open (beta), closed (alpha) and internal tracks (read-only edit, deleted afterwards).

Usage: python3 status/collect.py [--out surumler/status.json]
Credentials (environment; on the Mac each falls back to the local file):
  GH_TOKEN                   read access to the game repos and the packages repo (fallback: `gh auth token`)
  ASC_KEY_ID, ASC_ISSUER_ID, ASC_PRIVATE_KEY  App Store Connect API key (fallback: ~/Unity/keystores/tapaway-asc-api.json)
  PLAY_SERVICE_ACCOUNT_JSON  service account JSON text (fallback: ~/Unity/keystores/play-service-account.json)
Needs: pip install cryptography google-auth
The file is rewritten only when the data changed, so generatedAt is the time of the last change.
"""
import argparse
import base64
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KEYSTORES = Path.home() / "Unity/keystores"
GITHUB = "https://api.github.com/"
ASC = "https://api.appstoreconnect.apple.com/v1/"
PLAY = "https://androidpublisher.googleapis.com/androidpublisher/v3/applications/"
# App Store version states that mean "submitted, not live yet"; anything else that is not live is ignored.
REVIEW_STATES = {"WAITING_FOR_REVIEW", "IN_REVIEW", "PENDING_DEVELOPER_RELEASE", "PENDING_APPLE_RELEASE",
                 "PROCESSING_FOR_APP_STORE", "REJECTED", "METADATA_REJECTED", "INVALID_BINARY"}
LIVE_STATES = {"READY_FOR_SALE", "READY_FOR_DISTRIBUTION"}
SUBMISSION_OPEN_STATES = {"WAITING_FOR_REVIEW", "IN_REVIEW", "UNRESOLVED_ISSUES", "COMPLETING"}
PLAY_TRACKS = {"production": "production", "beta": "open", "alpha": "closed", "internal": "internal"}


def request(url, headers, method="GET", body=None, allow_404=False):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={**headers, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            text = response.read().decode()
            return json.loads(text) if text else {}
    except urllib.error.HTTPError as error:
        if allow_404 and error.code == 404:
            return None
        sys.exit(f"{method} {url} → {error.code}: {error.read().decode()[:500]}")


class GitHub:
    def __init__(self, owner):
        token = os.environ.get("GH_TOKEN") or subprocess.run(
            ["gh", "auth", "token"], capture_output=True, text=True, check=True).stdout.strip()
        self.owner = owner
        self.headers = {"Authorization": "Bearer " + token, "Accept": "application/vnd.github.raw+json"}

    def file(self, repo, path):
        """Raw file text from the repo's default branch, or None when the repo or file does not exist."""
        req = urllib.request.Request(f"{GITHUB}repos/{self.owner}/{repo}/contents/{path}", headers=self.headers)
        try:
            with urllib.request.urlopen(req, timeout=60) as response:
                return response.read().decode()
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            sys.exit(f"GitHub {repo}/{path} → {error.code}: {error.read().decode()[:500]}")


class AppStoreConnect:
    def __init__(self):
        from cryptography.hazmat.primitives import serialization
        if os.environ.get("ASC_PRIVATE_KEY"):
            self.key_id, self.issuer = os.environ["ASC_KEY_ID"], os.environ["ASC_ISSUER_ID"]
            pem = os.environ["ASC_PRIVATE_KEY"].encode()
        else:
            config = json.loads((KEYSTORES / "tapaway-asc-api.json").read_text())
            self.key_id, self.issuer = config["key_id"], config["issuer_id"]
            pem = (KEYSTORES / config["key_path"]).read_bytes()
        self.key = serialization.load_pem_private_key(pem, None)
        self.token = self._token()

    def _token(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils

        def b64(raw):
            return base64.urlsafe_b64encode(raw).rstrip(b"=")

        now = int(time.time())
        head = b64(json.dumps({"alg": "ES256", "kid": self.key_id, "typ": "JWT"}).encode())
        body = b64(json.dumps({"iss": self.issuer, "iat": now, "exp": now + 1200, "aud": "appstoreconnect-v1"}).encode())
        r, s = utils.decode_dss_signature(self.key.sign(head + b"." + body, ec.ECDSA(hashes.SHA256())))
        return (head + b"." + body + b"." + b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))).decode()

    def get(self, path):
        return request(ASC + path, {"Authorization": "Bearer " + self.token})

    def apps(self):
        return {app["attributes"]["bundleId"]: app["id"] for app in self.get("apps?limit=200")["data"]}

    def status(self, app_id):
        versions = self.get(f"apps/{app_id}/appStoreVersions?filter[platform]=IOS&limit=20")["data"]
        live = review = None
        for version in versions:  # newest first
            attributes = version["attributes"]
            state = attributes.get("appVersionState") or attributes.get("appStoreState")
            state = {"ACCEPTED": "PENDING_DEVELOPER_RELEASE"}.get(state, state)
            if state in LIVE_STATES and live is None:
                live = {"version": attributes["versionString"], "date": (attributes.get("createdDate") or "")[:10]}
            elif state in REVIEW_STATES and review is None and live is None:
                review = {"version": attributes["versionString"], "state": state,
                          "release": attributes.get("releaseType"), "submitted": None}
        if review:
            # The open submission's date = when it went to Apple; resubmissions after a rejection reset it.
            submissions = self.get(f"reviewSubmissions?filter[app]={app_id}&filter[platform]=IOS&limit=10")["data"]
            dates = [s["attributes"].get("submittedDate") for s in submissions
                     if s["attributes"].get("state") in SUBMISSION_OPEN_STATES]
            review["submitted"] = max((d for d in dates if d), default=None)
        builds = self.get(f"builds?filter[app]={app_id}&sort=-uploadedDate&limit=1&include=preReleaseVersion")
        testflight = None
        if builds["data"]:
            build = builds["data"][0]["attributes"]
            marketing = next((item["attributes"]["version"] for item in builds.get("included", [])), None)
            testflight = {"version": marketing, "build": build["version"], "date": build["uploadedDate"][:10],
                          "expired": build.get("expired", False)}
        return {"live": live, "review": review, "testflight": testflight}


class GooglePlay:
    def __init__(self):
        from google.auth.transport.requests import Request
        from google.oauth2 import service_account
        scopes = ["https://www.googleapis.com/auth/androidpublisher"]
        text = os.environ.get("PLAY_SERVICE_ACCOUNT_JSON")
        if text:
            credentials = service_account.Credentials.from_service_account_info(json.loads(text), scopes=scopes)
        else:
            credentials = service_account.Credentials.from_service_account_file(
                str(KEYSTORES / "play-service-account.json"), scopes=scopes)
        credentials.refresh(Request())
        self.headers = {"Authorization": "Bearer " + credentials.token}

    def status(self, package):
        edit = request(f"{PLAY}{package}/edits", self.headers, method="POST", body={}, allow_404=True)
        if edit is None:
            return None
        try:
            tracks = request(f"{PLAY}{package}/edits/{edit['id']}/tracks", self.headers).get("tracks", [])
        finally:
            request(f"{PLAY}{package}/edits/{edit['id']}", self.headers, method="DELETE", allow_404=True)
        result = {name: None for name in PLAY_TRACKS.values()}
        for track in tracks:
            name = PLAY_TRACKS.get(track["track"])
            releases = [r for r in track.get("releases", []) if r.get("status") in ("completed", "inProgress")]
            if name and releases:
                release = releases[0]
                codes = release.get("versionCodes", [])
                result[name] = {"version": (release.get("name") or "").split("-")[0] or None,
                                "code": max(codes, key=int) if codes else None,
                                "rollout": release.get("userFraction") if release["status"] == "inProgress" else None}
        return result


def pin_version(url):
    """'…?path=com.mtafasahin.cozycore#cozycore-v0.31.0' → '0.31.0'; file: and branch pins are returned as written."""
    if "#" not in url:
        return url
    tag = url.rsplit("#", 1)[1]
    match = re.search(r"v?(\d+\.\d+\.\d+(?:-[\w.]+)?)$", tag)
    return match.group(1) if match else tag


def project_setting(text, name):
    match = re.search(rf"^\s*{name}: *'?([^'\n]*)'?$", text or "", flags=re.M)
    return match.group(1).strip() if match else None


def collect():
    config = json.loads((ROOT / "status/games.json").read_text())
    github = GitHub(config["owner"])
    packages = []
    for package in config["packages"]:
        manifest = json.loads(github.file(config["packagesRepo"], f"com.mtafasahin.{package['id']}/package.json"))
        packages.append({**package, "latest": manifest["version"]})

    asc, play = AppStoreConnect(), GooglePlay()
    ios_apps = asc.apps()
    games = []
    for game in config["games"]:
        entry = {"name": game["name"], "repo": game["repo"], "planned": bool(game.get("planned")), "pins": {}}
        manifest = github.file(game["repo"], "Packages/manifest.json")
        if manifest:
            for name, source in json.loads(manifest)["dependencies"].items():
                if name.startswith("com.mtafasahin."):
                    entry["pins"][name.removeprefix("com.mtafasahin.")] = pin_version(source)
        settings = github.file(game["repo"], "ProjectSettings/ProjectSettings.asset")
        if settings:
            entry["project"] = {"version": project_setting(settings, "bundleVersion"),
                                "androidCode": project_setting(settings, "AndroidBundleVersionCode")}
        if game.get("bundle"):
            entry["bundle"] = game["bundle"]
            entry["android"] = play.status(game["bundle"])
            entry["ios"] = asc.status(ios_apps[game["bundle"]]) if game["bundle"] in ios_apps else None
        games.append(entry)
    return {"packages": packages, "games": games}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=ROOT / "surumler/status.json")
    args = parser.parse_args()
    data = collect()
    if args.out.exists():
        previous = json.loads(args.out.read_text())
        if {k: v for k, v in previous.items() if k != "generatedAt"} == data:
            print(f"{args.out}: unchanged")
            return
    data = {"generatedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"), **data}
    args.out.write_text(json.dumps(data, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"{args.out}: updated")


if __name__ == "__main__":
    main()
