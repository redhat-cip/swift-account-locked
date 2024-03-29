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
__author__ = "Chmouel Boudjnah <chmouel@enovance.com>"
name = 'swift_account_locked'
entry_point = '%s.middleware:filter_factory' % (name)
version = '0.1'

from setuptools import setup, find_packages

setup(
    name=name,
    version=version,
    description='Swift middleware to allow locking an account.',
    license='Apache License (2.0)',
    author='OpenStack, LLC.',
    author_email='chmouel@enovance.com',
    url='https://github.com/chmouel/%s' % (name),
    packages=find_packages(),
    test_suite='nose.collector',
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 2.6',
        'Environment :: No Input/Output (Daemon)'],
    install_requires=['swift'],  # removed for better compat
    entry_points={
        'paste.filter_factory': ['account_locked=%s' % entry_point]
    }
)
