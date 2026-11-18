"""REST handler for the ViewDNS settings tab: validates the API key with the free Account API before saving."""

import logging

import import_declare_test  # noqa: F401  (UCC-generated: puts ../lib on sys.path)
from splunk import admin
from splunktaucclib.rest_handler.admin_external import AdminExternalHandler

from ta_viewdns import splunk_env
from ta_viewdns.client import AuthError, ConfigurationError, PaidPlanError, QuotaError, ViewDNSClient, ViewDNSError

logger = logging.getLogger("ta_viewdns.settings")


def _masked(value):
    return not value or set(str(value)) == {"*"}


class ViewDNSSettingsHandler(AdminExternalHandler):
    def __init__(self, *args, **kwargs):
        AdminExternalHandler.__init__(self, *args, **kwargs)

    def handleEdit(self, confInfo):
        if self.callerArgs.id == "viewdns":
            self._validate_key()
        AdminExternalHandler.handleEdit(self, confInfo)

    def handleCreate(self, confInfo):
        if self.callerArgs.id == "viewdns":
            self._validate_key()
        AdminExternalHandler.handleCreate(self, confInfo)

    def _arg(self, name, default=None):
        values = self.callerArgs.data.get(name)
        if values:
            return values[0]
        return default

    def _validate_key(self):
        splunk_env.setup_logging()
        api_key = self._arg("api_key")
        if _masked(api_key):
            return  # unchanged key: it was validated when it was saved
        proxies, secrets = None, ()
        try:
            from solnlib import conf_manager

            manager = conf_manager.ConfManager(
                self.getSessionKey(), splunk_env.APP_NAME, realm=splunk_env.CREDENTIAL_REALM
            )
            proxies, secrets = splunk_env.build_proxies(manager.get_conf(splunk_env.SETTINGS_CONF).get("proxy"))
        except Exception:
            pass  # proxy not configured yet
        try:
            timeout = int(self._arg("timeout", "100"))
        except ValueError:
            timeout = 100
        client = ViewDNSClient(
            api_key, base_url=self._arg("base_url"), timeout=min(timeout, 60), proxies=proxies, secrets=secrets
        )
        try:
            client.account_balance()
        except (AuthError, ConfigurationError) as error:
            raise admin.ArgValidationException(error.message)
        except (QuotaError, PaidPlanError):
            return  # the key is valid; usage problems surface at search time
        except ViewDNSError as error:
            logger.warning("API key check failed: %s", error.message)
            raise admin.ArgValidationException(
                "Could not verify the API key: {0} Check the base URL and proxy settings.".format(error.message)
            )
