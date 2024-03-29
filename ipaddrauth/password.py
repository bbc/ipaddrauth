# Copyright 2022 BBC R&D
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import flask

from keystone.auth.plugins import password
from keystone.common import provider_api

from keystone import exception
from keystone.i18n import _

from oslo_log import log
from oslo_config import cfg
from oslo_serialization import jsonutils

import ipaddress
import re

LOG = log.getLogger(__name__)
CONF = cfg.CONF
PROVIDERS = provider_api.ProviderAPIs

CONF.register_opt(cfg.MultiStrOpt('rule', default=[]), group='ippassword')
CONF.register_opt(cfg.BoolOpt('deny_if_no_forwarded', default=True), group='ippassword')


def _test_user_and_address(rules, ip, user):
    # evaluate each rule in order
    for rule in rules:

        # the username must match the allowed pattern
        if not re.match(rule['regex'], user):
            continue

        # evaulate each network
        for network in rule['networks']:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(network):
                if rule['action'] == 'permit':
                  LOG.info("IP check permitted for user %s from ip %s in network %s", user, ip, network)
                  return True
                else:
                  LOG.info("IP check denied for user %s from ip %s in network %s", user, ip, network)
                  msg = _('Invalid username or password')
                  raise exception.Unauthorized(msg)

    # no rule matched - implicit 'deny'
    LOG.info("IP check implicit deny for user %s from ip %s", user, ip)
    msg = _('Invalid username or password')
    raise exception.Unauthorized(msg)


class IPPassword(password.Password):


    def authenticate(self, auth_payload):

        LOG.debug("IPPassword request headers %s", flask.request.headers)

        # handle the case when a user ID is given instead of a user name
        user_name = auth_payload['user'].get('name')
        user_id = auth_payload['user'].get('id')
        if not user_name:
          user_ref = PROVIDERS.identity_api.get_user(user_id)
          user_name = user_ref['name']

        # load rules from config
        # where can this be done once at startup?
        # needs some error handling for bad input
        rules = []
        for rj in CONF.ippassword.rule:
          r = jsonutils.loads(rj)
          rules.append(r)
        LOG.debug("IPPassword rules parsed %s", rules)

        forwarded_ip = None
        if 'Forwarded' in flask.request.headers:
            h = flask.request.headers.get('Forwarded')
            forwarded_ip = h[h.index('=')+1:h.index(';')]
        elif 'X-Forwarded-For' in flask.request.headers:
            forwarded_ip = flask.request.headers.get('X-Forwarded-For')

        if forwarded_ip == None:
            if CONF.ippassword.deny_if_no_forwarded:
                LOG.debug("IP check denied user %s as no Forwarded or X-Forwarded-For header available to evaluate", user_name)
                msg = _('Invalid username or password')
                raise exception.Unauthorized(msg)
        else:
            _test_user_and_address(rules, forwarded_ip, user_name)

        return super().authenticate(auth_payload)
