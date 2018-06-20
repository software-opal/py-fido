#!/usr/bin/env python3
"""The setup script."""

from setuptools import find_packages, setup

requirements = [
    'cryptography~=2.2',
]

packages = find_packages(
    where='./',
    include=['fido_u2f', 'fido_u2f.*'],
)
if not packages:
    raise ValueError('No packages detected.')

setup(
    name='fido-u2f',
    version='0.7.1',
    description='A framework-agnostic implementation of the FIDO U2F '
    'server workflow',
    long_description='',
    author='The Operations Team(Catalyst IT Ltd.)',
    author_email='sysadmins@catalyst.net.nz',
    url='https://gitlab.catalyst.net.nz/sysadmins/hotpotato/',
    packages=packages,
    include_package_data=False,
    install_requires=requirements,
    zip_safe=True,
    package_data={
        'fido_u2f': ['py.typed'],
    },
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: Security',
    ],
)