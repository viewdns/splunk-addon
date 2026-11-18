from ta_viewdns import splunk_env


def test_proxy_disabled_or_incomplete():
    assert splunk_env.build_proxies(None) == (None, ())
    assert splunk_env.build_proxies({"proxy_enabled": "0", "proxy_url": "p"}) == (None, ())
    assert splunk_env.build_proxies({"proxy_enabled": "1"}) == (None, ())


def test_proxy_with_credentials_is_quoted_and_secret():
    proxies, secrets = splunk_env.build_proxies(
        {"proxy_enabled": "1", "proxy_url": "proxy.corp", "proxy_port": "3128", "proxy_username": "a@b",
         "proxy_password": "p:ss/w@rd"}
    )
    assert proxies["https"] == "http://a%40b:p%3Ass%2Fw%40rd@proxy.corp:3128"
    assert proxies["http"] == proxies["https"]
    assert "p:ss/w@rd" in secrets and "p%3Ass%2Fw%40rd" in secrets


def test_settings_defaults_and_clamping():
    settings = splunk_env.settings_from_stanzas({"api_key": " k "}, None)
    assert (settings.api_key, settings.timeout, settings.max_results, settings.max_lookups, settings.cache_ttl) == (
        "k", 100, 100, 1000, 86400)
    settings = splunk_env.settings_from_stanzas(
        {"api_key": "k", "timeout": "9999", "max_results": "0", "max_lookups": "abc", "cache_ttl": "-5"}, None
    )
    assert (settings.timeout, settings.max_results, settings.max_lookups, settings.cache_ttl) == (300, 1, 1000, 0)


def test_split_uri():
    assert splunk_env._split_uri("https://127.0.0.1:8089") == ("https", "127.0.0.1", 8089)
    assert splunk_env._split_uri("http://sh1") == ("http", "sh1", 8089)
