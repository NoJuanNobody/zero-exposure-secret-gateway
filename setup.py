from setuptools import setup, find_packages

setup(
    name="zero-exposure-secret-gateway",
    version="0.1.0",
    description="Conversational wrapper and zero-exposure terminal secret injector for Railway and cloud secret managers.",
    author="Alejandro Londono",
    packages=find_packages(exclude=["tests*"]),
    python_requires=">=3.9",
    install_requires=[],
    extras_require={
        "dev": ["pytest>=7.0"],
    },
    entry_points={
        "console_scripts": [
            "zero-exposure-secret-gateway=zero_exposure_secret_gateway.cli:main",
        ],
    },
)
