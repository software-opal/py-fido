#!/usr/bin/env python3
"""The setup script."""

from setuptools import find_packages, setup

requirements = [
    'cryptography>=2.3,<3',
]

flask_sample_requires = [
    'flask',
    'Flask-SQLAlchemy',
]


packages = find_packages(
    where='./',
    include=['fido_u2f', 'fido_u2f.*'],
)
if not packages:
    raise ValueError('No packages detected.')


with open('./README.rst', 'r') as readme_file:
    readme = readme_file.read()


setup(
    name='py-fido',
    version='0.4.0',
    description=(
        'A framework-agnostic implementation of the FIDO U2F server workflow'
    ),
    long_description=readme,
    author='Opal Symes',
    author_email='code@opal.codes',
    url='https://github.com/leesdolphin/py-fido/',
    packages=packages,
    include_package_data=True,
    install_requires=requirements,
    extras_require={
        'sample': flask_sample_requires,
    },
    zip_safe=False,
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
