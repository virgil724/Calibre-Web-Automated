# -*- coding: utf-8 -*-
# Calibre-Web Automated – fork of Calibre-Web
# Copyright (C) 2018-2026 Calibre-Web contributors
# Copyright (C) 2024-2026 Calibre-Web Automated contributors
# SPDX-License-Identifier: GPL-3.0-or-later
# See CONTRIBUTORS for full list of authors.

from urllib.parse import quote

import requests
from flask_babel import lazy_gettext as N_

from cps import logger
from cps.services.worker import CalibreTask

log = logger.create()

# kobodl downloads and decrypts the whole book before it sends a single byte back, so the
# read timeout has to cover the entire download rather than just network latency.
DOWNLOAD_TIMEOUT = (10, 900)


class TaskKobodlDownload(CalibreTask):
    """Ask kobodl to download one book from a linked Kobo account.

    The response body is deliberately discarded. kobodl writes the decrypted book into its
    own --output-dir -- deployed as the same volume CWA ingests from -- before it starts
    streaming the file back, so by the time we have the response headers the book is already
    on disk and the ingest watcher will pick it up on its own. Pulling the body across would
    only copy a file we already have.
    """

    def __init__(self, task_message, base_url, secret, owner_token, userid, productid):
        super(TaskKobodlDownload, self).__init__(task_message)
        self.base_url = base_url
        self.secret = secret
        self.owner_token = owner_token
        self.userid = userid
        self.productid = productid

    def run(self, worker_thread):
        url = '{0}/user/{1}/book/{2}'.format(
            self.base_url, quote(str(self.userid), safe=''), quote(str(self.productid), safe='')
        )
        headers = {'X-Internal-Secret': self.secret, 'X-Owner-Id': self.owner_token}

        try:
            response = requests.get(url, headers=headers, stream=True, timeout=DOWNLOAD_TIMEOUT)
        except requests.RequestException as ex:
            log.error("kobodl download request failed: %s", ex)
            self._handleError(N_(u"Could not reach the kobodl service"))
            return

        try:
            if response.status_code == 404:
                # kobodl answers 404 for a Kobo account that is not owned by this user
                self._handleError(N_(u"This Kobo account is no longer linked to your CWA account"))
                return
            if response.status_code != 200:
                log.error("kobodl download returned HTTP %s for %s", response.status_code, url)
                self._handleError(N_(u"kobodl could not download this book"))
                return
        finally:
            # Closes the connection without reading the body, see the class docstring
            response.close()

        self._handleSuccess()

    @property
    def name(self):
        return N_(u"Kobo Download")

    @property
    def is_cancellable(self):
        return False
