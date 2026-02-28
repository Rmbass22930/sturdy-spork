#!/usr/bin/env python3
"""VPNGuard 2 standalone viewer protection utility.

The original VPNGuard focused on parsing SSH/web logs to detect hacking
attempts.  VPNGuard 2 is designed for creators streaming on MyFreeCams and
Chaturbate who need a local companion that continuously looks up viewer IP
addresses, detects VPN/proxy usage, and applies permanent Windows Firewall
blocks on abusive viewers.  The program stores per-model configuration,
fetches viewer rosters from JSON feeds or HTTPS endpoints, and can run in the
background while broadcast software is open.
"""

from __future__ import annotations

import ipaddress
import json
import os
import platform
import subprocess
import threading
import time
from dataclasses import dataclass, field
from sys import stdin
from pathlib import Path
from typing import Dict, Iterable, List, NamedTuple, Optional, Tuple

import requests

PROGRAM_NAME = "VPNGuard 2"
STATE_FILE = os.environ.get("VPN_GUARD_STATE", "./vpnguard2_state.json")
IP_LOOKUP_URL = "http://ip-api.com/json/{ip}?fields=status,proxy,hosting,query,country,isp"
DEFAULT_POLL_SECONDS = 45
LOOKUP_CACHE_SECONDS = 3600
SUPPORTED_SITES = ("myfreecams", "chaturbate", "onlyfans", "livejasmin")


class ConnectorError(RuntimeError):
    pass


class FeedUnavailableError(ConnectorError):
    pass


@dataclass
class ModelProfile:
    site: str
    handle: str
    display_name: str = ""
    viewer_feed: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    auto_block_vpn: bool = True
    metadata: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        self.site = self.site.lower()
        self.handle = self.handle.strip()

    @property
    def key(self) -> str:
        return f"{self.site}:{self.handle}".lower()

    def to_dict(self) -> Dict[str, object]:
        return {
            "site": self.site,
            "handle": self.handle,
            "display_name": self.display_name,
            "viewer_feed": self.viewer_feed,
            "tags": list(self.tags),
            "auto_block_vpn": self.auto_block_vpn,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "ModelProfile":
        return cls(
            site=str(data.get("site", "")).lower(),
            handle=str(data.get("handle", "")),
            display_name=str(data.get("display_name", "")),
            viewer_feed=data.get("viewer_feed"),
            tags=list(data.get("tags", [])),
            auto_block_vpn=bool(data.get("auto_block_vpn", True)),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass
class ViewerRecord:
    username: str
    ip_address: str
    source: str
    flags: List[str] = field(default_factory=list)
    metadata: Dict[str, str] = field(default_factory=dict)


class IPInfo(NamedTuple):
    ip: str
    is_vpn: bool
    country: str
    isp: str


class BaseConnector:
    site: str = "generic"
    friendly_name: str = "Generic"

    def fetch_viewers(self, profile: ModelProfile) -> List[ViewerRecord]:
        raise NotImplementedError


class JSONFeedConnector(BaseConnector):
    viewer_keys: Tuple[str, ...] = ("viewers",)

    def fetch_viewers(self, profile: ModelProfile) -> List[ViewerRecord]:
        feed = self._resolve_feed(profile)
        if not feed:
            raise FeedUnavailableError(
                f"No viewer feed configured for {profile.site}:{profile.handle}."
            )
        payload = self._load_payload(feed)
        rows = self._extract_rows(payload)
        viewers: List[ViewerRecord] = []
        for row in rows:
            record = self._row_to_viewer(row, feed)
            if record:
                viewers.append(record)
        return viewers

    def _resolve_feed(self, profile: ModelProfile) -> Optional[str]:
        if profile.viewer_feed:
            return profile.viewer_feed
        default_path = Path("feeds") / f"{profile.site}_{profile.handle}.json"
        if default_path.exists():
            return str(default_path)
        return None

    def _load_payload(self, feed: str):
        if feed.startswith(("http://", "https://")):
            resp = requests.get(feed, timeout=15)
            resp.raise_for_status()
            try:
                return resp.json()
            except ValueError as exc:
                raise FeedUnavailableError(f"Feed at {feed} is not valid JSON") from exc
        path = Path(feed).expanduser()
        if not path.exists():
            raise FeedUnavailableError(f"Feed file not found: {path}")
        text = path.read_text(encoding="utf-8")
        return json.loads(text)

    def _extract_rows(self, payload) -> List[object]:
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            for key in self.viewer_keys:
                value = payload.get(key)
                if isinstance(value, list):
                    return value
            data_value = payload.get("data")
            if isinstance(data_value, list):
                return data_value
        return []

    def _row_to_viewer(self, row, source: str) -> Optional[ViewerRecord]:
        username: Optional[str] = None
        ip_address: Optional[str] = None
        flags: List[str] = []
        metadata: Dict[str, str] = {}

        if isinstance(row, dict):
            username = row.get("username") or row.get("user") or row.get("handle")
            ip_address = row.get("ip") or row.get("ip_address") or row.get("address")
            flags_raw = row.get("flags") or row.get("labels") or []
            if isinstance(flags_raw, str):
                flags = [flags_raw]
            elif isinstance(flags_raw, list):
                flags = [str(f) for f in flags_raw]
            for key in ("notes", "reason", "country", "isp"):
                if key in row:
                    metadata[key] = str(row[key])
        elif isinstance(row, (list, tuple)) and len(row) >= 2:
            username = str(row[0])
            ip_address = str(row[1])
            if len(row) >= 3 and row[2]:
                flags = [str(row[2])]
        else:
            return None

        if not username or not ip_address:
            return None
        return ViewerRecord(
            username=str(username).strip(),
            ip_address=str(ip_address).strip(),
            source=source,
            flags=flags,
            metadata=metadata,
        )


class MyFreeCamsConnector(JSONFeedConnector):
    site = "myfreecams"
    friendly_name = "MyFreeCams"
    viewer_keys = ("viewers", "members", "users", "data")


class ChaturbateConnector(JSONFeedConnector):
    site = "chaturbate"
    friendly_name = "Chaturbate"
    viewer_keys = ("chatters", "viewers", "users", "data")


class OnlyFansConnector(JSONFeedConnector):
    site = "onlyfans"
    friendly_name = "OnlyFans"
    viewer_keys = ("viewers", "subscribers", "fans", "users", "data")


class LiveJasminConnector(JSONFeedConnector):
    site = "livejasmin"
    friendly_name = "LiveJasmin"
    viewer_keys = ("viewers", "members", "clients", "users", "data")


class GuardState:
    def __init__(self, state_file: str):
        self.state_file = Path(state_file)
        self.lock = threading.Lock()
        self.models: Dict[str, ModelProfile] = {}
        self.blocked_ips: Dict[str, Dict[str, object]] = {}
        self.blocked_viewers: Dict[str, Dict[str, object]] = {}
        self.allow_ips: set[str] = set()

    def load(self):
        if not self.state_file.exists():
            return
        try:
            raw = json.loads(self.state_file.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"[WARN] Failed to read state: {exc}")
            return
        for key, value in raw.get("models", {}).items():
            try:
                profile = ModelProfile.from_dict(value)
                self.models[key.lower()] = profile
            except Exception as exc:
                print(f"[WARN] Skipping invalid model entry {key}: {exc}")
        self.blocked_ips = dict(raw.get("blocked_ips", {}))
        self.blocked_viewers = dict(raw.get("blocked_viewers", {}))
        self.allow_ips = set(raw.get("allow_ips", []))

    def save(self):
        payload = {
            "models": {key: profile.to_dict() for key, profile in self.models.items()},
            "blocked_ips": self.blocked_ips,
            "blocked_viewers": self.blocked_viewers,
            "allow_ips": sorted(self.allow_ips),
        }
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.state_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def list_models(self) -> List[ModelProfile]:
        return sorted(self.models.values(), key=lambda p: (p.site, p.handle))

    def get_model(self, site: str, handle: str) -> Optional[ModelProfile]:
        key = f"{site}:{handle}".lower()
        return self.models.get(key)

    def upsert_model(self, profile: ModelProfile):
        with self.lock:
            self.models[profile.key] = profile
            self.save()

    def remove_model(self, site: str, handle: str) -> bool:
        key = f"{site}:{handle}".lower()
        with self.lock:
            if key in self.models:
                self.models.pop(key)
                self.save()
                return True
        return False

    def record_blocked_viewer(self, key: str, record: Dict[str, object]):
        with self.lock:
            self.blocked_viewers[key] = record
            self.save()

    def record_blocked_ip(self, ip: str, record: Dict[str, object]):
        with self.lock:
            self.blocked_ips[ip] = record
            self.save()

    def unrecord_ip(self, ip: str):
        with self.lock:
            if self.blocked_ips.pop(ip, None) is not None:
                self.save()


class VPNGuard2:
    def __init__(self, state_file: str = STATE_FILE):
        self.state = GuardState(state_file)
        self.state.load()
        self.lookup_cache: Dict[str, Tuple[float, Optional[IPInfo]]] = {}
        self.poll_thread: Optional[threading.Thread] = None
        self.poll_stop = threading.Event()
        self.active_site: Optional[str] = None
        self.active_model_key: Optional[str] = None
        self.site_initialized = False
        self.connectors: Dict[str, BaseConnector] = {
            "myfreecams": MyFreeCamsConnector(),
            "chaturbate": ChaturbateConnector(),
            "onlyfans": OnlyFansConnector(),
            "livejasmin": LiveJasminConnector(),
        }

    # ---------------- CLI helpers ----------------
    def cmd_loop(self):
        print(f"{PROGRAM_NAME} ready. Type 'help' for commands.")
        self.ensure_site_selected()
        self.ensure_model_scope()
        while True:
            try:
                raw = input("> ").strip()
            except (EOFError, KeyboardInterrupt):
                raw = "quit"
            if not raw:
                continue
            parts = raw.split()
            cmd = parts[0].lower()

            if cmd in {"quit", "exit"}:
                self.stop_poll()
                print("Stopping...")
                break
            if cmd == "help":
                self.print_help()
                continue
            if cmd == "status":
                self.print_status()
                continue
            if cmd == "site":
                desired = parts[1].lower() if len(parts) >= 2 else None
                self.prompt_site_selection(desired)
                continue
            if cmd == "model":
                self.handle_model_focus_command(parts[1:])
                continue
            if cmd == "start":
                interval = DEFAULT_POLL_SECONDS
                if len(parts) > 1:
                    try:
                        interval = max(10, float(parts[1]))
                    except ValueError:
                        print("Invalid interval; using default.")
                self.start_poll(interval)
                continue
            if cmd == "stop":
                self.stop_poll()
                continue
            if cmd == "scan":
                self.scan_once()
                continue
            if cmd == "models":
                self.handle_model_command(parts[1:])
                continue
            if cmd == "block-ip" and len(parts) >= 2:
                reason = " ".join(parts[2:]) if len(parts) > 2 else "manual"
                self.block_ip(parts[1], reason, context=None)
                continue
            if cmd == "block-viewer" and len(parts) >= 4:
                site, handle, viewer = parts[1], parts[2], parts[3]
                reason = " ".join(parts[4:]) if len(parts) > 4 else "manual"
                self.block_viewer_manual(site, handle, viewer, reason)
                continue
            if cmd == "unblock" and len(parts) >= 2:
                self.unblock_ip(parts[1])
                continue
            if cmd == "allow-ip" and len(parts) >= 2:
                self.state.allow_ips.add(parts[1])
                self.state.save()
                print(f"[ALLOW] {parts[1]}")
                continue
            if cmd == "allow-list":
                if not self.state.allow_ips:
                    print("No allow-listed IPs.")
                else:
                    for ip in sorted(self.state.allow_ips):
                        print(f"  {ip}")
                continue
            if cmd == "blocked":
                self.print_blocked()
                continue
            if cmd == "lookup" and len(parts) >= 2:
                info = self.lookup_ip(parts[1])
                if info:
                    status = "VPN/Proxy" if info.is_vpn else "Residential"
                    print(f"{parts[1]} -> {status} ({info.country}, {info.isp})")
                else:
                    print("Lookup failed")
                continue

            print("Unknown command. Type 'help' for assistance.")

    def ensure_site_selected(self):
        if not self.site_initialized:
            self.prompt_site_selection()

    def ensure_model_scope(self) -> bool:
        if self.active_site is None:
            self.active_model_key = None
            return True
        models = [m for m in self.state.list_models() if m.site == self.active_site]
        if not models:
            print(f"No models configured for {self.active_site.title()}.")
            return False
        if self.active_model_key and any(m.key == self.active_model_key for m in models):
            return True
        self.prompt_model_selection(models)
        return self.active_model_key is None or any(m.key == self.active_model_key for m in models)

    def prompt_site_selection(self, initial: Optional[str] = None):
        while True:
            if initial is not None:
                choice = initial.strip().lower()
                initial = None
            else:
                if stdin is not None and stdin.isatty():
                    prompt_text = (
                        "Select site to monitor "
                        f"({', '.join(SUPPORTED_SITES)} or 'all'): "
                    )
                    try:
                        choice = input(prompt_text).strip().lower()
                    except EOFError:
                        choice = "all"
                else:
                    choice = "all"
            if not choice or choice == "all":
                self.active_site = None
                print("Monitoring all configured sites.")
                self.site_initialized = True
                self.active_model_key = None
                return
            if choice in SUPPORTED_SITES:
                self.active_site = choice
                print(f"Monitoring only {choice}.")
                self.site_initialized = True
                self.active_model_key = None
                return
            print("Invalid site. Try again.")

    def prompt_model_selection(self, candidates: List[ModelProfile]):
        if not candidates:
            return
        if stdin is None or not stdin.isatty():
            self.active_model_key = candidates[0].key
            print(
                f"Monitoring {candidates[0].display_name or candidates[0].handle} "
                f"on {candidates[0].site}."
            )
            return
        while True:
            print("Select a model to monitor (or 'all' for every model on this site):")
            for idx, model in enumerate(candidates, start=1):
                label = model.display_name or model.handle
                print(f"  {idx}) {label} [{model.site}]")
            choice = input("Choice: ").strip().lower()
            if not choice or choice == "all":
                self.active_model_key = None
                print("Monitoring all models on the selected site.")
                return
            if choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(candidates):
                    self.active_model_key = candidates[idx].key
                    label = candidates[idx].display_name or candidates[idx].handle
                    print(f"Monitoring only {label}.")
                    return
            print("Invalid selection. Try again.")

    def handle_model_command(self, args: List[str]):
        if not args:
            print("Usage: models [list|add|remove|feed|toggle]")
            return
        sub = args[0].lower()
        if sub == "list":
            self.list_models()
        elif sub == "add" and len(args) >= 3:
            site = args[1].lower()
            handle = args[2]
            if site not in SUPPORTED_SITES:
                print(f"Unsupported site '{site}'. Supported: {', '.join(SUPPORTED_SITES)}")
                return
            display = " ".join(args[3:]) if len(args) > 3 else handle
            profile = ModelProfile(site=site, handle=handle, display_name=display)
            self.state.upsert_model(profile)
            print(f"[MODEL] Added {site}:{handle}")
            if not self.active_model_key:
                self.active_model_key = profile.key
                self.active_site = site
        elif sub == "remove" and len(args) >= 3:
            if self.state.remove_model(args[1], args[2]):
                print("Model removed.")
                if self.active_model_key == f"{args[1]}:{args[2]}".lower():
                    self.active_model_key = None
            else:
                print("Model not found.")
        elif sub == "feed" and len(args) >= 4:
            site, handle = args[1], args[2]
            profile = self.state.get_model(site, handle)
            if not profile:
                print("Model not found.")
                return
            profile.viewer_feed = " ".join(args[3:])
            self.state.upsert_model(profile)
            print(f"[MODEL] Updated feed for {site}:{handle}")
        elif sub == "toggle" and len(args) >= 4:
            site, handle, flag = args[1], args[2], args[3]
            profile = self.state.get_model(site, handle)
            if not profile:
                print("Model not found.")
                return
            if flag == "vpn":
                profile.auto_block_vpn = not profile.auto_block_vpn
                self.state.upsert_model(profile)
                state = "on" if profile.auto_block_vpn else "off"
                print(f"Auto VPN blocking {state} for {site}:{handle}")
            else:
                print("Only 'vpn' flag is supported right now.")
        else:
            print("Usage: models [list|add|remove|feed|toggle]")

    def handle_model_focus_command(self, args: List[str]):
        if not args:
            print("Usage: model [all|<site> <handle>]")
            return
        if args[0].lower() == "all":
            self.active_model_key = None
            print("Per-model focus cleared.")
            return
        if len(args) < 2:
            print("Usage: model <site> <handle>")
            return
        site, handle = args[0].lower(), args[1]
        profile = self.state.get_model(site, handle)
        if not profile:
            print("Model not found.")
            return
        self.active_site = site
        self.active_model_key = profile.key
        print(f"Monitoring only {profile.display_name or profile.handle} on {site}.")

    def start_poll(self, interval: float):
        if not self.state.models:
            print("Add at least one model before starting the poll loop.")
            return
        self.ensure_site_selected()
        if not self.ensure_model_scope():
            return
        if self.poll_thread and self.poll_thread.is_alive():
            print("Polling already running.")
            return
        self.poll_stop.clear()
        self.poll_thread = threading.Thread(
            target=self._poll_loop, args=(interval,), daemon=True
        )
        self.poll_thread.start()
        print(f"Polling every {interval:.0f}s. Use 'stop' to halt.")

    def stop_poll(self):
        if self.poll_thread and self.poll_thread.is_alive():
            self.poll_stop.set()
            self.poll_thread.join(timeout=2.0)
            print("Polling stopped.")

    def _poll_loop(self, interval: float):
        while not self.poll_stop.is_set():
            self.scan_once()
            waited = 0.0
            while waited < interval and not self.poll_stop.is_set():
                time.sleep(0.5)
                waited += 0.5

    # ---------------- Core logic ----------------
    def scan_once(self):
        models = self.state.list_models()
        if not models:
            print("No models configured. Use 'models add' first.")
            return
        self.ensure_site_selected()
        if not self.ensure_model_scope():
            return
        if self.active_site:
            models = [m for m in models if m.site == self.active_site]
            if not models:
                print("No models configured for the selected site.")
                return
        if self.active_model_key:
            models = [m for m in models if m.key == self.active_model_key]
            if not models:
                print("Active model not found; select again with 'model <site> <handle>'.")
                return
        for profile in models:
            connector = self.connectors.get(profile.site)
            if not connector:
                print(f"[WARN] No connector for {profile.site}")
                continue
            try:
                viewers = connector.fetch_viewers(profile)
            except FeedUnavailableError as exc:
                print(f"[FEED] {exc}")
                continue
            except Exception as exc:  # unexpected connector failure
                print(f"[ERROR] Connector failure for {profile.site}:{profile.handle}: {exc}")
                continue
            if not viewers:
                print(f"[SCAN] {profile.display_name or profile.handle}: no viewers retrieved.")
                continue
            blocked = 0
            for viewer in viewers:
                blocked += 1 if self.process_viewer(profile, viewer) else 0
            print(
                f"[SCAN] {profile.display_name or profile.handle}: {len(viewers)} viewers, {blocked} blocked"
            )

    def process_viewer(self, profile: ModelProfile, viewer: ViewerRecord) -> bool:
        ip = viewer.ip_address.strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            print(f"[SKIP] Invalid IP for {viewer.username}: {ip}")
            return False
        if ip in self.state.allow_ips:
            return False
        viewer_key = self._viewer_key(profile.site, profile.handle, viewer.username)
        if viewer_key in self.state.blocked_viewers:
            return False
        if ip in self.state.blocked_ips:
            return False
        info = self.lookup_ip(ip)
        should_block = False
        reasons: List[str] = []
        if info and info.is_vpn and profile.auto_block_vpn:
            should_block = True
            reasons.append("VPN/proxy detected")
        for flag in viewer.flags:
            if flag and flag.lower() in {"abuse", "harassment", "ban", "offensive"}:
                should_block = True
                reasons.append(f"flag:{flag}")
        if should_block:
            reason_text = ", ".join(reasons) if reasons else "auto"
            self.block_viewer(profile, viewer, reason_text, info)
            return True
        return False

    def _viewer_key(self, site: str, handle: str, username: str) -> str:
        return f"{site}:{handle}:{username}".lower()

    def block_viewer(self, profile: ModelProfile, viewer: ViewerRecord, reason: str, info: Optional[IPInfo]):
        blocked = self.block_ip(
            viewer.ip_address,
            reason,
            context={
                "site": profile.site,
                "handle": profile.handle,
                "viewer": viewer.username,
            },
        )
        record = {
            "site": profile.site,
            "handle": profile.handle,
            "viewer": viewer.username,
            "reason": reason,
            "timestamp": time.time(),
            "ip": viewer.ip_address,
            "flags": viewer.flags,
        }
        if info:
            record["ip_info"] = {
                "country": info.country,
                "isp": info.isp,
                "is_vpn": info.is_vpn,
            }
        key = self._viewer_key(profile.site, profile.handle, viewer.username)
        self.state.record_blocked_viewer(key, record)
        if blocked:
            print(
                f"[BLOCK] {viewer.username}@{profile.handle} ({viewer.ip_address}) -> {reason}"
            )
        else:
            print(f"[NOTE] Viewer {viewer.username} recorded without firewall change.")

    def block_viewer_manual(self, site: str, handle: str, username: str, reason: str):
        profile = self.state.get_model(site, handle)
        if not profile:
            print("Model not found.")
            return
        ip = input("Enter IP to block: ").strip()
        viewer = ViewerRecord(username=username, ip_address=ip, source="manual")
        self.block_viewer(profile, viewer, reason, self.lookup_ip(ip))

    def block_ip(self, ip: str, reason: str, context: Optional[Dict[str, str]]):
        ip = ip.strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            print(f"[ERR] Cannot block invalid IP {ip}")
            return False
        if ip in self.state.allow_ips:
            print(f"[INFO] {ip} is allow-listed; skipping")
            return False
        if ip in self.state.blocked_ips:
            return False
        success = self.firewall_block(ip)
        record = {
            "reason": reason,
            "timestamp": time.time(),
            "context": context or {},
        }
        if not success:
            record["firewall"] = "failed"
        self.state.record_blocked_ip(ip, record)
        return success

    def unblock_ip(self, ip: str):
        self.state.unrecord_ip(ip)
        self.firewall_unblock(ip)
        print(f"[UNBLOCK] {ip}")

    def firewall_block(self, ip: str) -> bool:
        system = platform.system().lower()
        try:
            if "windows" in system:
                cmd = [
                    "netsh",
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    f"name=VPNGuard2_{ip}",
                    "dir=in",
                    "action=block",
                    f"remoteip={ip}",
                ]
                subprocess.run(cmd, check=False, capture_output=True, text=True)
            else:
                subprocess.run(["ufw", "deny", "from", ip], check=False, capture_output=True, text=True)
            return True
        except Exception as exc:
            print(f"[WARN] Firewall update failed for {ip}: {exc}")
            return False

    def firewall_unblock(self, ip: str):
        system = platform.system().lower()
        try:
            if "windows" in system:
                subprocess.run(
                    [
                        "netsh",
                        "advfirewall",
                        "firewall",
                        "delete",
                        "rule",
                        f"name=VPNGuard2_{ip}",
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
            else:
                subprocess.run(["ufw", "delete", "deny", "from", ip], check=False, capture_output=True, text=True)
        except Exception as exc:
            print(f"[WARN] Failed to remove firewall rule for {ip}: {exc}")

    def lookup_ip(self, ip: str) -> Optional[IPInfo]:
        now = time.time()
        cached = self.lookup_cache.get(ip)
        if cached and now - cached[0] < LOOKUP_CACHE_SECONDS:
            return cached[1]
        try:
            resp = requests.get(IP_LOOKUP_URL.format(ip=ip), timeout=6)
            data = resp.json()
            if data.get("status") != "success":
                info = None
            else:
                info = IPInfo(
                    ip=ip,
                    is_vpn=bool(data.get("proxy") or data.get("hosting")),
                    country=str(data.get("country", "")),
                    isp=str(data.get("isp", "")),
                )
        except Exception:
            info = None
        self.lookup_cache[ip] = (now, info)
        return info

    # ---------------- Display helpers ----------------
    def print_status(self):
        print("\n--- STATUS ---")
        print(f"Models: {len(self.state.models)}")
        print(f"Blocked IPs: {len(self.state.blocked_ips)}")
        print(f"Blocked viewers: {len(self.state.blocked_viewers)}")
        print(f"Allow-listed IPs: {len(self.state.allow_ips)}")
        site_text = self.active_site or "all"
        print(f"Active site filter: {site_text}")
        if self.active_model_key:
            profile = self.state.models.get(self.active_model_key)
            label = profile.display_name or profile.handle if profile else "unknown"
            print(f"Active model: {label}")
        else:
            print("Active model: all")
        if self.poll_thread and self.poll_thread.is_alive():
            print("Polling: running")
        else:
            print("Polling: stopped")
        print("---------------\n")

    def list_models(self):
        models = self.state.list_models()
        if not models:
            print("No models configured.")
            return
        for profile in models:
            print(
                f"- {profile.site}:{profile.handle} -> feed={profile.viewer_feed or 'unset'}, VPN-block={'on' if profile.auto_block_vpn else 'off'}"
            )

    def print_blocked(self):
        if not self.state.blocked_ips:
            print("No blocked IPs yet.")
            return
        for ip, record in sorted(self.state.blocked_ips.items()):
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(record.get("timestamp", 0)))
            reason = record.get("reason", "?")
            ctx = record.get("context", {})
            ctx_text = f" {ctx}" if ctx else ""
            print(f"- {ip} [{ts}] {reason}{ctx_text}")

    def print_help(self):
        print(
            "Commands:\n"
            "  help                    Show this help\n"
            "  status                  Print current snapshot\n"
            "  site [name|all]         Set active site filter\n"
            "  model [all|<site> <handle>] Focus on a single model\n"
            "  models list             List configured models\n"
            "  models add <site> <handle> [display]   Add a model\n"
            "  models feed <site> <handle> <path|url> Set viewer feed source\n"
            "  models remove <site> <handle>          Remove a model\n"
            "  models toggle <site> <handle> vpn      Toggle VPN auto block\n"
            "  start [seconds]          Begin continuous polling\n"
            "  stop                     Stop polling\n"
            "  scan                     Run one immediate scan\n"
            "  block-ip <ip> [reason]   Manually block IP\n"
            "  block-viewer <site> <handle> <viewer> [reason]\n"
            "  unblock <ip>             Remove firewall rule\n"
            "  allow-ip <ip>            Add allow-list entry\n"
            "  allow-list               Show allow list\n"
            "  blocked                  Show blocked IPs\n"
            "  lookup <ip>              Manual IP lookup\n"
            "  quit                     Exit"
        )


def main():
    guard = VPNGuard2()
    guard.cmd_loop()


if __name__ == "__main__":
    main()
