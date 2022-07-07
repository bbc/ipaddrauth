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

from keystone import exception
from keystone.i18n import _

from oslo_log import log
from oslo_config import cfg
from oslo_serialization import jsonutils

import ipaddress
import re

LOG = log.getLogger(__name__)
CONF = cfg.CONF

CONF.register_opt(cfg.MultiStrOpt('rule', default=[]), group='ippassword')
CONF.register_opt(cfg.BoolOpt('deny_if_no_forwarded', default=True, group='ippassword')

"""
An example of what is needed in keystone.conf to make this work

[auth]
methods = password,token,application_credential"

# override the password method to use the IPPassword implementation
password = ippassword

[ippassword]
# define an ordered ruleset to permit or deny usernames based on originating IP
# example allows any user on rfc1918 networks
          allows usernames starting "safe_admin_" from rfc1918 and a specified subnet (maybe these use TOTP)
          explicity denies the admin user from all other addresses
          implicity denies all other users who match no previous rules
rule = {"regex": ".*",           "action": "permit", "networks": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] }
rule = {"regex": "^safe_admin_", "action": "permit", "networks": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "1.2.3.0/24"] }
rule = {"regex": "admin",        "action": "deny",   "networks": ["0.0.0.0/0"] }

# set to False to allow login attempts with a missing Forwarded or X-Forwarded-For header
# deny_if_no_forwarded = False
"""

def _test_user_and_address(rules, ip, user):
    for rule in rules:
        # the username must match the allowed pattern

        if not re.match(rule['regex'], user):
            continue

        # evaulate each rule in order
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
                LOG.debug("IP check denied user %s as no Forwarded or X-Forwarded-For header available to evaluate", auth_payload['user']['name'])
                msg = _('Invalid username or password')
                raise exception.Unauthorized(msg)
        else:
            _test_user_and_address(rules, forwarded_ip, auth_payload['user']['name'])

        return super().authenticate(self, auth_payload)
