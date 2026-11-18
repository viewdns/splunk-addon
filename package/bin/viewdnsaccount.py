#!/usr/bin/env python
"""``viewdnsaccount`` generating command: shows the ViewDNS API plan usage and remaining queries.

    | viewdnsaccount

Uses the ViewDNS Account API, which does not consume a query.
"""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from splunklib.searchcommands import Configuration, GeneratingCommand, dispatch  # noqa: E402

from ta_viewdns import remote, splunk_env  # noqa: E402

logger = splunk_env.setup_logging()


@Configuration(distributed=False, type="reporting")
class ViewDNSAccountCommand(GeneratingCommand):
    """
    ##Syntax
    | viewdnsaccount

    ##Description
    Returns one row with the ViewDNS API plan, monthly limit and usage, and the prepaid query balance.
    Does not consume an API query.
    """

    def generate(self):
        info = self._metadata.searchinfo
        try:
            service = remote.connect_user_service(info.session_key, info.splunkd_uri)
            resolver = remote.RemoteResolver(remote.splunk_transport(service))
            row = resolver.balance()
        except Exception as error:  # never show a stack trace
            logger.exception("viewdnsaccount failed")
            self.write_error("ViewDNS: could not read the account balance ({0}).".format(type(error).__name__))
            return
        for _, text in resolver.drain_messages():
            self.write_error(text)
        if row:
            row["_time"] = time.time()
            yield row


if __name__ == "__main__":
    dispatch(ViewDNSAccountCommand, sys.argv, sys.stdin, sys.stdout, __name__)
