# -*- encoding: utf-8 -*-
__author__ = "Chmouel Boudjnah <chmouel@enovance.com>"

# Copyright 2013 eNovance.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from swift.common.utils import get_logger, config_true_value
from swift.common.swob import Request, HTTPForbidden
from swift.proxy.controllers.base import get_account_info


class AccountAccessMiddleware(object):
    def __init__(self, app, conf):
        self.app = app
        self.conf = conf
        self.logger = get_logger(self.conf, log_route='quota')
        self.locked_header = conf.get('locked_header', 'locked')
        self.recheck_account_existence = conf.get('recheck_account_existence',
                                                  60)
        denied_methods_conf = conf.get('denied_methods')
        if denied_methods_conf and type(denied_methods_conf) is str:
            self.denied_methods = denied_methods_conf.split(',')
        else:
            self.denied_methods = ("PUT", "DELETE", "POST")

    def deny(self, req):
        return HTTPForbidden(request=req)

    def __call__(self, env, start_response):
        req = Request(env)

        # TOREMOVE: when merged
        # if we are doing a post to update the locked value then alow it.
        if req.method == 'POST':
            for header in req.headers:
                if header.lower() == "x-account-meta-%s" % \
                        self.locked_header.lower():
                    return self.app(env, start_response)

        # check if we are in a method we want to disallow.
        if not req.method in self.denied_methods:
            return self.app(env, start_response)

        account_info = get_account_info(env,
                                        self.app,
                                        swift_source="LCK")
        if not account_info:
            return self.app(env, start_response)

        if 'meta' in account_info and self.locked_header in \
           account_info['meta'] and config_true_value(
               account_info['meta'][self.locked_header]):
            self.logger.debug(
                "[account_access] account locked for %s" %
                (str(req.remote_user)))
            env['swift.authorize'] = self.deny
        return self.app(env, start_response)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    return lambda app: AccountAccessMiddleware(app, conf)
