"""Test configuration and fixtures for SSTI Scanner tests."""

import pytest
import asyncio
from pathlib import Path

# Configure asyncio for testing
@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture
def test_data_dir():
    """Return path to test data directory."""
    return Path(__file__).parent / "data"

@pytest.fixture
def sample_config():
    """Sample configuration for testing."""
    from ssti_scanner.core.config import Config
    config = Config()
    config.scanning.threads = 2
    config.scanning.delay = 0.1
    config.crawling.timeout = 5
    config.output.debug = True
    return config
