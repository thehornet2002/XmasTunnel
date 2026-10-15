from setuptools import setup, find_packages

setup(
    name="xmastunnel",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "cryptography>=42.0.0",
        "scapy>=2.5.0",
    ],
    entry_points={
        "console_scripts": [
            "xmastunnel=xmastunnel.cli:main",
        ],
    },
)
