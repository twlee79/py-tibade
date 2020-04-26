#!/usr/bin/env python
# -*- coding: utf-8 -*-

import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="pytibade",
    version="1.0.0dev1",
    author="Tet Woo Lee",
    author_email="developer@twlee.nz",
    description="Decrypt Titanium Backup for Android backups with Python/pycryptodome",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/twlee79/py-tibade",
    packages=setuptools.find_packages(),
    install_requires=[
        'pycryptodome >= v3.8.2',
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    entry_points={
        'console_scripts': [
            'pytibade = pytibade.pytibade:main',
        ],
    },
    data_files=[("", ["LICENSE"]),
                ("", ["README.md"])
                ],
)
