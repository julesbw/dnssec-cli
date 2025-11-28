from setuptools import setup, find_packages

setup(
    name="dnssec-toolkit",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "pyshark",
        "dnspython",
        "rich",
        "click",
    ],
    entry_points={
        "console_scripts": [
            "dnssec = dnssec_tool.cli:main",
        ]
    },
    description="A professional CLI toolkit for DNSSEC scanning and DNS forensic analysis.",
    url="https://github.com/tuusuario/dnssec-toolkit",
)
