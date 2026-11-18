"""Splunk-specific plumbing: settings and secrets, the KV store cache, and logging."""

import json
import logging
import logging.handlers
import os

from .client import ConfigurationError
from .enrich import Settings

APP_NAME = "TA-viewdns"
SETTINGS_CONF = "ta_viewdns_settings"
CREDENTIAL_REALM = "__REST_CREDENTIAL__#{0}#configs/conf-{1}".format(APP_NAME, SETTINGS_CONF)
CACHE_COLLECTION = "viewdns_cache"

# KV store limits: keep requests well under the default batch limits.
CACHE_READ_BATCH = 200
CACHE_WRITE_BATCH = 500

_LOGGING_READY = False
logger = logging.getLogger("ta_viewdns.settings")


def setup_logging(level="INFO"):
    """Logs to $SPLUNK_HOME/var/log/splunk/ta_viewdns.log (indexed into _internal)."""
    global _LOGGING_READY
    root = logging.getLogger("ta_viewdns")
    root.setLevel(getattr(logging, str(level).upper(), logging.INFO))
    if _LOGGING_READY:
        return root
    home = os.environ.get("SPLUNK_HOME")
    if home:
        path = os.path.join(home, "var", "log", "splunk", "ta_viewdns.log")
        try:
            handler = logging.handlers.RotatingFileHandler(path, maxBytes=10 * 1024 * 1024, backupCount=5)
            handler.setFormatter(
                logging.Formatter("%(asctime)s %(levelname)s pid=%(process)d %(name)s - %(message)s")
            )
            root.addHandler(handler)
        except (IOError, OSError):
            pass
    root.propagate = False
    _LOGGING_READY = True
    return root


def _int(value, default, low, high):
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    return max(low, min(high, number))


def _truthy(value):
    return str(value).strip().lower() in ("1", "true", "yes", "t", "y")


def build_proxies(proxy):
    """Builds a requests ``proxies`` dict from the proxy settings stanza. Returns (proxies, secrets)."""
    if not proxy or not _truthy(proxy.get("proxy_enabled")) or not proxy.get("proxy_url"):
        return None, ()
    try:
        from urllib.parse import quote
    except ImportError:  # pragma: no cover
        from urllib import quote  # type: ignore
    host = str(proxy["proxy_url"]).strip()
    port = str(proxy.get("proxy_port") or "").strip()
    auth = ""
    secrets = []
    username = proxy.get("proxy_username")
    password = proxy.get("proxy_password")
    if username:
        auth = quote(str(username), safe="")
        if password:
            auth += ":" + quote(str(password), safe="")
            secrets.extend([str(password), quote(str(password), safe="")])
        auth += "@"
    url = "http://{0}{1}{2}".format(auth, host, ":" + port if port else "")
    return {"http": url, "https": url}, tuple(secrets)


def settings_from_stanzas(viewdns, proxy):
    viewdns = viewdns or {}
    proxies, secrets = build_proxies(proxy)
    return Settings(
        api_key=(viewdns.get("api_key") or "").strip() or None,
        base_url=(viewdns.get("base_url") or "https://api.viewdns.info").strip(),
        timeout=_int(viewdns.get("timeout"), 100, 1, 300),
        max_results=_int(viewdns.get("max_results"), 100, 1, 10000),
        max_lookups=_int(viewdns.get("max_lookups"), 1000, 1, 100000),
        cache_ttl=_int(viewdns.get("cache_ttl"), 86400, 0, 2592000),
        proxies=proxies,
        secrets=secrets,
    )


def load_settings(session_key, splunkd_uri=None):
    """Reads the add-on settings and decrypts the API key and proxy password. Returns (Settings, log_level)."""
    from solnlib import conf_manager

    kwargs = {}
    if splunkd_uri:
        scheme, host, port = _split_uri(splunkd_uri)
        kwargs = {"scheme": scheme, "host": host, "port": port}
    try:
        manager = conf_manager.ConfManager(session_key, APP_NAME, realm=CREDENTIAL_REALM, **kwargs)
        conf = manager.get_conf(SETTINGS_CONF)
    except Exception as error:
        raise ConfigurationError(
            "ViewDNS: the add-on is not configured yet. Open the ViewDNS add-on's Configuration page and save "
            "your API key. ({0})".format(type(error).__name__)
        )
    stanzas = {}
    for name in ("viewdns", "proxy", "logging"):
        try:
            stanzas[name] = conf.get(name)
        except Exception as error:
            # Missing stanza (not saved yet). Settings are read with the system token by the lookup endpoint,
            # so permission errors are not expected here.
            logger.debug("settings stanza %s unavailable: %s", name, type(error).__name__)
            stanzas[name] = {}
    if not (stanzas.get("viewdns") or {}).get("api_key"):
        raise ConfigurationError(
            "ViewDNS: no API key is configured. Open the ViewDNS add-on's Configuration page and save your API key."
        )
    level = (stanzas.get("logging") or {}).get("loglevel") or "INFO"
    return settings_from_stanzas(stanzas["viewdns"], stanzas["proxy"]), level


def _split_uri(uri):
    try:
        from urllib.parse import urlsplit
    except ImportError:  # pragma: no cover
        from urlparse import urlsplit  # type: ignore
    parts = urlsplit(uri)
    return parts.scheme or "https", parts.hostname or "127.0.0.1", parts.port or 8089


def connect_service(session_key, splunkd_uri):
    """A splunklib Service bound to this app's namespace (owner nobody), for KV store access."""
    from splunklib import client

    scheme, host, port = _split_uri(splunkd_uri)
    return client.Service(scheme=scheme, host=host, port=port, token=session_key, owner="nobody", app=APP_NAME)


class KVCache(object):
    """The ``viewdns_cache`` KV store collection."""

    def __init__(self, service, collection=CACHE_COLLECTION):
        self._data = service.kvstore[collection].data

    def get_many(self, keys):
        found = {}
        keys = list(keys)
        for start in range(0, len(keys), CACHE_READ_BATCH):
            batch = keys[start:start + CACHE_READ_BATCH]
            query = {"query": {"$or": [{"_key": key} for key in batch]}, "limit": len(batch)}
            for result in self._data.batch_find(query):
                for doc in result:
                    found[doc.get("_key")] = doc
        return found

    def put_many(self, docs):
        docs = list(docs)
        for start in range(0, len(docs), CACHE_WRITE_BATCH):
            self._data.batch_save(*docs[start:start + CACHE_WRITE_BATCH])


def make_client_factory(settings):
    from .client import ViewDNSClient

    def factory():
        return ViewDNSClient(
            settings.api_key,
            base_url=settings.base_url,
            timeout=settings.timeout,
            proxies=settings.proxies,
            secrets=settings.secrets,
        )

    return factory


def dumps(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True)
