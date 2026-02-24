from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="nettrace",
    version="1.0.0",
    author="xytex-s",
    author_email="",  # Add your email if you want
    description="NetTrace is a robust packet sniffer with cross-platform support",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/xytex-s/NetTrace",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: System Administrators",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
        "Operating System :: OS Independent",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Security",
    ],
    # License is defined in pyproject.toml, but keeping install_requires for backward compatibility
    # with tools that read setup.py directly instead of pyproject.toml
    python_requires=">=3.6",
    install_requires=[
        "psutil>=5.9.0",
    ],
    entry_points={
        "console_scripts": [
            "nettrace=sniffer:main",
        ],
    },
)