# Copyright (c) 2016 Tigera, Inc. All rights reserved.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from setuptools import setup, find_packages

setup(
    name='pycalico',

    # Version is required - pycalico can be installed directly from GitHub
    # using pip install.
    version='0.8.0-dev',

    # Don't need a version until we publish to PIP or other forum.
    # version='0.0.0',

    description='A Python API to Calico',

    # The project's main homepage.
    url='https://github.com/projectcalico/libcalico/',

    # Author details
    author='Project Calico',
    author_email='calico-tech@lists.projectcalico.org',

    # Choose your license
    license='Apache 2.0',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Operating System :: POSIX :: Linux',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Topic :: System :: Networking',
    ],

    # What does your project relate to?
    keywords='calico docker etcd mesos kubernetes rkt openstack',

    package_dir={"": "calico_containers"},
    packages=["pycalico"],

    # List run-time dependencies here.  These will be installed by pip when
    # your project is installed. For an analysis of "install_requires" vs pip's
    # requirements files see:
    # https://packaging.python.org/en/latest/requirements.html
    install_requires=['netaddr', 'python-etcd>=0.4.3', 'subprocess32'],
    dependency_links=[
        "https://github.com/jplana/python-etcd.git@0d0145f5e835aa032c97a0a5e09c4c68b7a03f66"
    ]
)
