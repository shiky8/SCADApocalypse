from setuptools import setup, find_packages

setup(
    name="scadapocalypse",
    version="1.0.0",
    description="SCADApocalypse Toolkit — A SCADA-focused offensive security framework.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Mohamed Shahat",
    url="https://github.com/shiky8/SCADApocalypse",
    packages=find_packages(include=["plugins*", "utils*", "brute_force*", "marketplace*", "tester*"]),
    include_package_data=True,
    install_requires=[
        "requests",
        "pymodbus",
        "websockets",
        "flask",
        "flask-socketio",
        "eventlet",
        "pysnmp",
        "jinja2",
        "paramiko",
        "telnetlib3",
        "pycryptodome"
    ],
    entry_points={
        "console_scripts": [
            "scadapocalypse=__main__:main",
            "scadapocalypse-web=marketplace.app:main"
        ]
    },
    python_requires=">=3.8",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Developers",
    ],
)