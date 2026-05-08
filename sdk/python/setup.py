from setuptools import find_packages, setup

setup(
    name="vigil-sdk",
    version="0.1.0",
    description="Public Python SDK for VIGIL — AI-native security operations.",
    author="VIGIL",
    python_requires=">=3.9",
    packages=find_packages(exclude=["tests", "tests.*"]),
    install_requires=["httpx>=0.27.0"],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
