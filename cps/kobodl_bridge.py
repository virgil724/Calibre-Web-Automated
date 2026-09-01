# -*- coding: utf-8 -*-
# Calibre-Web Automated – fork of Calibre-Web
# Copyright (C) 2018-2026 Calibre-Web contributors
# Copyright (C) 2024-2026 Calibre-Web Automated contributors
# SPDX-License-Identifier: GPL-3.0-or-later
# See CONTRIBUTORS for full list of authors.

"""Bridge between CWA's own user accounts and a kobodl service holding Kobo logins.

kobodl (https://github.com/subdavis/kobo-book-downloader) keeps all of the Kobo specific
logic -- device registration, DRM removal, downloading -- and runs as its own service. It
has no user accounts of its own, so a multi-tenant deployment marks every Kobo account it
stores with an opaque "owner id" and only answers calls that present the matching one.

This blueprint is the trusted caller on the other end of that arrangement: it authenticates
the human with CWA's normal login, looks up the owner token belonging to that CWA user, and
talks to kobodl server-to-server with a shared secret. The owner token is never handed to
the browser and never accepted from it -- it is always derived from current_user -- so a
user cannot reach another user's Kobo accounts by editing a URL or a form field.

Both KOBODL_BASE_URL and KOBODL_INTERNAL_SECRET must be set for any of this to work; when
they are not, every route here answers 503 and CWA is otherwise unaffected.
"""

import os
from binascii import hexlify
from datetime import datetime
from functools import wraps
from os import urandom

import requests
from flask import Blueprint, abort, jsonify, request
from flask_babel import gettext as _

from . import logger, ub
from .cw_login import current_user
from .render_template import render_title_template
from .services.worker import WorkerThread
from .tasks.kobodl_download import TaskKobodlDownload
from .usermanagement import user_login_required

log = logger.create()

kobodl_bridge = Blueprint('kobodl_bridge', __name__, url_prefix='/kobodl')

# Marks a RemoteAuthToken as a kobodl owner token. The table already holds two other kinds:
# 0 for remote-login magic links and 1 for Kobo device sync tokens. Unlike either of those
# this token is never accepted as a credential -- it only ever travels outwards, to tell
# kobodl which of the Kobo accounts it stores belong to this CWA user.
KOBODL_OWNER_TOKEN_TYPE = 2

# Calls made while the user's own request is waiting; the slow one (downloading a book) is
# not made here but on a worker thread, see TaskKobodlDownload.
KOBODL_TIMEOUT = 30


class KobodlUnavailable(Exception):
    """kobodl is not configured, or could not be reached."""


def _kobodl_config():
    """(base_url, secret) as configured, either value empty when unset."""
    return (
        os.environ.get('KOBODL_BASE_URL', '').strip().rstrip('/'),
        os.environ.get('KOBODL_INTERNAL_SECRET', '').strip(),
    )


def kobodl_configured() -> bool:
    """Whether this CWA instance is wired up to a kobodl service at all."""
    base_url, secret = _kobodl_config()
    return bool(base_url and secret)


def get_or_create_kobodl_owner_token(user_id: int) -> str:
    """The opaque owner id identifying this CWA user to kobodl, minted on first use.

    Mirrors kobo_auth.generate_auth_token; datetime.max keeps ub.clean_database from ever
    treating the token as expired.
    """
    token = ub.session.query(ub.RemoteAuthToken).filter(
        ub.RemoteAuthToken.user_id == user_id
    ).filter(ub.RemoteAuthToken.token_type == KOBODL_OWNER_TOKEN_TYPE).first()

    if not token:
        token = ub.RemoteAuthToken()
        token.user_id = user_id
        token.expiration = datetime.max
        token.auth_token = hexlify(urandom(16)).decode('utf-8')
        token.token_type = KOBODL_OWNER_TOKEN_TYPE

        ub.session.add(token)
        ub.session_commit()

    return token.auth_token


def _owner_token() -> str:
    """The owner token of the logged in user. Never read from the request."""
    return get_or_create_kobodl_owner_token(current_user.id)


def _kobodl_request(method: str, path: str, **kwargs):
    """Call kobodl on behalf of the logged in user."""
    base_url, secret = _kobodl_config()
    if not base_url or not secret:
        raise KobodlUnavailable(_("The kobodl service is not configured."))

    headers = {
        'X-Internal-Secret': secret,
        'X-Owner-Id': _owner_token(),
        # Opts into kobodl's JSON responses; without it kobodl renders its own HTML pages
        'Accept': 'application/json',
    }
    kwargs.setdefault('timeout', KOBODL_TIMEOUT)

    try:
        return requests.request(method, base_url + path, headers=headers, **kwargs)
    except requests.RequestException as ex:
        log.error("kobodl request %s %s failed: %s", method, path, ex)
        raise KobodlUnavailable(_("Could not reach the kobodl service."))


def _kobodl_json(method: str, path: str, **kwargs):
    """As _kobodl_request, but insisting on a JSON body."""
    response = _kobodl_request(method, path, **kwargs)
    try:
        return response.json(), response.status_code
    except ValueError:
        log.error("kobodl answered %s %s with non-JSON body (HTTP %s)",
                  method, path, response.status_code)
        raise KobodlUnavailable(_("The kobodl service returned an unexpected response."))


def _json_errors(func):
    """Turn an unreachable/unconfigured kobodl into a JSON 503 rather than an HTML error."""
    @wraps(func)
    def inner(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except KobodlUnavailable as ex:
            return jsonify({'error': str(ex)}), 503
    return inner


@kobodl_bridge.route('/')
@user_login_required
def index():
    """Page listing the Kobo accounts this CWA user has linked."""
    if not kobodl_configured():
        abort(503)

    users, error = [], None
    try:
        payload, status = _kobodl_json('GET', '/user')
        if status == 200:
            users = payload.get('users', [])
        else:
            log.error("kobodl user list returned HTTP %s", status)
            error = _("kobodl could not list your Kobo accounts.")
    except KobodlUnavailable as ex:
        error = str(ex)

    return render_title_template(
        'kobodl_link.html',
        title=_("Kobo Accounts"),
        page="kobodl",
        kobodl_users=users,
        kobodl_error=error,
    )


@kobodl_bridge.route('/link', methods=["POST"])
@user_login_required
@_json_errors
def link_account():
    """Start linking a Kobo account: kobodl answers with a code to enter on kobo.com."""
    email = (request.form.get('email') or '').strip()
    if not email:
        return jsonify({'error': _("Please enter the email address of your Kobo account.")}), 400

    payload, status = _kobodl_json('POST', '/user', data={'email': email})

    # kobodl reports a failed login by re-rendering its account list, so a response without
    # an activation code is a failure however cheerful its status code looks
    if status != 200 or 'activation_code' not in payload:
        log.error("kobodl refused to start activation for a linked account (HTTP %s)", status)
        return jsonify({
            'error': payload.get('error') or _("Kobo would not start the login. Please try again.")
        }), 502

    return jsonify(payload)


@kobodl_bridge.route('/check-activation', methods=["POST"])
@user_login_required
@_json_errors
def check_activation():
    """Poll kobodl to see whether the user has entered the code on kobo.com yet."""
    data = request.get_json(silent=True) or {}
    check_url = data.get('check_url')
    email = data.get('email')
    if not check_url or not email:
        return jsonify({'error': _("Missing activation details. Please start again.")}), 400

    payload, status = _kobodl_json(
        'POST', '/user/check-activation', json={'check_url': check_url, 'email': email}
    )
    return jsonify(payload), status


@kobodl_bridge.route('/<userid>/remove', methods=["POST"])
@user_login_required
@_json_errors
def remove_account(userid):
    """Unlink a Kobo account. kobodl answers 404 when it is not this user's to remove."""
    payload, status = _kobodl_json('POST', '/user/' + userid + '/remove')
    if status == 404:
        return jsonify({'error': _("That Kobo account is not linked to your account.")}), 404
    if status != 200:
        return jsonify({'error': _("kobodl could not remove this Kobo account.")}), 502
    return jsonify(payload)


@kobodl_bridge.route('/<userid>/book')
@user_login_required
@_json_errors
def list_books(userid):
    """The books available in one linked Kobo account."""
    payload, status = _kobodl_json('GET', '/user/' + userid + '/book')
    if status == 404:
        return jsonify({'error': _("That Kobo account is not linked to your account.")}), 404
    if status != 200:
        return jsonify({'error': _("kobodl could not list the books in this Kobo account.")}), 502
    return jsonify(payload)


@kobodl_bridge.route('/<userid>/book/<productid>/download', methods=["POST"])
@user_login_required
def download_book(userid, productid):
    """Queue a download. The book reaches the library through the shared ingest folder.

    Downloading takes long enough that holding the request open would hit reverse proxy
    timeouts, so it runs as a task and shows up under Tasks like any other long job.
    """
    base_url, secret = _kobodl_config()
    if not base_url or not secret:
        return jsonify({'error': _("The kobodl service is not configured.")}), 503

    title = (request.form.get('title') or '').strip()
    task_message = _("Downloading '%(title)s' from Kobo", title=title or _("book"))

    WorkerThread.add(
        current_user.name,
        TaskKobodlDownload(task_message, base_url, secret, _owner_token(), userid, productid),
        hidden=False,
    )
    return jsonify({'success': True})
