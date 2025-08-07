"""
Setup configuration for SSTI Scanner.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_path = Path(__file__).parent / "README.md"
if readme_path.exists():
    with open(readme_path, 'r', encoding='utf-8') as f:
        long_description = f.read()
else:
    long_description = "Advanced Server-Side Template Injection (SSTI) vulnerability scanner"

# Read requirements
requirements_path = Path(__file__).parent / "requirements.txt"
if requirements_path.exists():
    with open(requirements_path, 'r') as f:
        requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]
else:
    requirements = [
        'aiohttp>=3.8.0',
        'beautifulsoup4>=4.11.0',
        'lxml>=4.9.0',
        'pyyaml>=6.0',
        'colorama>=0.4.0',
        'jinja2>=3.1.0',
        'requests>=2.28.0',
        'urllib3>=1.26.0',
    ]

setup(
    name="ssti-scanner",
    version="1.0.0",
    author="Samir Djili",
    author_email="samir.djili@example.com",
    description="Advanced Server-Side Template Injection (SSTI) vulnerability scanner",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/samir-djili/ssti-scanner",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "mypy>=1.0.0",
            "isort>=5.10.0",
        ],
        "browser": [
            "selenium>=4.0.0",
            "playwright>=1.20.0",
        ],
        "advanced": [
            "scrapy>=2.6.0",
            "dnspython>=2.2.0",
            "cryptography>=3.4.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "ssti-scanner=ssti_scanner.cli.main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "ssti_scanner": [
            "data/*.yml",
            "data/*.json",
            "templates/*.html",
        ],
    },
    keywords="security, ssti, template-injection, vulnerability-scanner, penetration-testing",
    project_urls={
        "Bug Reports": "https://github.com/samir-djili/ssti-scanner/issues",
        "Source": "https://github.com/samir-djili/ssti-scanner",
        "Documentation": "https://github.com/samir-djili/ssti-scanner/wiki",
    },
)
