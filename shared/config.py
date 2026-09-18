"""Configuration loading, shared by every service.

Two sources, in this order: the process environment (optionally seeded from a
`.env` file that is never committed) and `team.json`, which holds only the
team name and the four public endpoint URLs.

Both partners' settings names work, so one `.env` drives all four services:
`TEAM`/`HOST`/`SUBJECT_PORT` (Partner A's FastAPI services) are read as
fallbacks wherever the `LAB1_`-prefixed name is unset. The prefixed name wins
when both are present.

Shared tokens have no default. A service that cannot find its token refuses to
start rather than falling back to a value an attacker could read in this file.
"""

import json
import os
from typing import Dict, Optional

SERVICES = ("subject", "csp", "verifier", "rp")
PORT_OFFSETS = {"subject": 0, "csp": 1, "verifier": 2, "rp": 3}
SPEC_VERSION = "1.0"

# Bind on every interface: a service bound to 127.0.0.1 works on the server and
# is invisible from campus, which is the second most common way to fail the probe.
DEFAULT_BIND_HOST = "0.0.0.0"
DEFAULT_PORT_BLOCK = 4100

_ENV_LOADED = False


class ConfigError(Exception):
    """Configuration is missing or malformed; the service must not start."""


def setting(name: str, *aliases: str, default: Optional[str] = None) -> Optional[str]:
    """First non-empty value among `name` and its aliases, else `default`.

    The aliases are Partner A's unprefixed settings names. Keeping both readable
    from one file is what lets the two halves of the lab share a single `.env`.
    """
    load_env_file()
    for key in (name,) + aliases:
        value = os.environ.get(key, "").strip()
        if value:
            return value
    return default


def load_env_file(path: str = ".env") -> None:
    """Seed os.environ from a KEY=value file, without overriding real env vars."""
    global _ENV_LOADED
    if _ENV_LOADED or not os.path.exists(path):
        _ENV_LOADED = True
        return
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip().strip("'\""))
    _ENV_LOADED = True


def load_team_config(path: str = "team.json") -> Dict[str, object]:
    if not os.path.exists(path):
        return {"team": os.environ.get("LAB1_TEAM", "unset-team"), "endpoints": {}}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            config = json.load(handle)
    except ValueError as exc:
        raise ConfigError("team.json is not valid JSON: %s" % exc) from None
    if not isinstance(config, dict):
        raise ConfigError("team.json must contain a JSON object")
    config.setdefault("team", "unset-team")
    config.setdefault("endpoints", {})
    return config


def team_name() -> str:
    return setting("LAB1_TEAM", "TEAM") or str(
        load_team_config().get("team", "unset-team")
    )


def port_for(service: str) -> int:
    """Port for `service`: an explicit override, else block + the fixed offset."""
    load_env_file()
    if service not in PORT_OFFSETS:
        raise ConfigError("unknown service %r" % (service,))
    name = "LAB1_%s_PORT" % service.upper()
    override = setting(name, "%s_PORT" % service.upper())
    if override:
        return _as_port(override, name)
    block = setting("LAB1_PORT_BLOCK", default=str(DEFAULT_PORT_BLOCK))
    return _as_port(block, "LAB1_PORT_BLOCK") + PORT_OFFSETS[service]


def bind_host() -> str:
    return setting("LAB1_BIND_HOST", "HOST", default=DEFAULT_BIND_HOST)


def endpoint_for(service: str, config: Optional[Dict[str, object]] = None) -> str:
    """Base URL of a peer service: env override, else team.json, else localhost."""
    load_env_file()
    if service not in SERVICES:
        raise ConfigError("unknown service %r" % (service,))
    override = setting("LAB1_%s_URL" % service.upper(), "%s_URL" % service.upper())
    if override:
        return override.rstrip("/")
    endpoints = (config or load_team_config()).get("endpoints", {})
    if isinstance(endpoints, dict) and endpoints.get(service):
        return str(endpoints[service]).rstrip("/")
    return "http://127.0.0.1:%d" % port_for(service)


def internal_endpoint_for(service: str) -> str:
    """Base URL for a *service-to-service* call, inside the trust boundary.

    All four services run on one host, so the Verifier -> RP edge has no reason
    to leave it: the default is the loopback address, not the public URL in
    team.json. Sending an assertion out across the campus network and back
    would put the load-bearing edge of the design on an untrusted wire.
    """
    load_env_file()
    if service not in SERVICES:
        raise ConfigError("unknown service %r" % (service,))
    override = setting("LAB1_%s_URL" % service.upper(), "%s_URL" % service.upper())
    if override:
        return override.rstrip("/")
    return "http://127.0.0.1:%d" % port_for(service)


def require_secret(name: str) -> str:
    """Read a shared token, or refuse to start."""
    value = setting(name, name.replace("LAB1_", ""), default="")
    if len(value) < 16:
        raise ConfigError(
            "%s is missing or too short. Copy .env.example to .env and fill it in "
            "with a value of at least 16 characters (see README.md)." % name
        )
    return value


def int_setting(name: str, default: int, *, minimum: int = 1) -> int:
    raw = setting(name, name.replace("LAB1_", ""))
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError("%s must be an integer, got %r" % (name, raw)) from None
    if value < minimum:
        raise ConfigError("%s must be >= %d" % (name, minimum))
    return value


def bool_setting(name: str, default: bool) -> bool:
    raw = setting(name, name.replace("LAB1_", ""))
    if raw is None:
        return default
    return raw.lower() in ("1", "true", "yes", "on")


def _as_port(raw: str, name: str) -> int:
    try:
        port = int(raw)
    except ValueError:
        raise ConfigError("%s must be a port number, got %r" % (name, raw)) from None
    if not (1 <= port <= 65535):
        raise ConfigError("%s out of range: %d" % (name, port))
    return port
