"""
Unit tests for core configuration management.
"""

import os
import tempfile
import yaml
from pathlib import Path
from unittest.mock import patch

import pytest

from src.core.config import ConfigManager, ScanConfig


class TestConfigManager:
    """Test configuration manager functionality."""
    
    def test_default_configuration(self):
        """Test loading default configuration."""
        config_manager = ConfigManager()
        config = config_manager.get_config()
        
        # Check default values
        assert config.scanning.threads > 0
        assert config.scanning.delay >= 0
        assert config.scanning.timeout > 0
        assert config.scanning.intensity in ['quick', 'normal', 'aggressive']
        
        assert config.crawling.max_depth > 0
        assert config.crawling.max_pages > 0
        
        assert config.detection.min_confidence in ['low', 'medium', 'high']
        
        assert config.output.format in ['console', 'json', 'html', 'csv']
    
    def test_config_file_loading(self):
        """Test loading configuration from file."""
        # Create temporary config file
        config_data = {
            'scanning': {
                'threads': 20,
                'delay': 1.0,
                'timeout': 60,
                'intensity': 'aggressive'
            },
            'detection': {
                'engines': ['jinja2', 'twig'],
                'min_confidence': 'high'
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            yaml.dump(config_data, f)
            config_file = f.name
        
        try:
            config_manager = ConfigManager(config_file=config_file)
            config = config_manager.get_config()
            
            # Check loaded values
            assert config.scanning.threads == 20
            assert config.scanning.delay == 1.0
            assert config.scanning.timeout == 60
            assert config.scanning.intensity == 'aggressive'
            
            assert 'jinja2' in config.detection.engines
            assert 'twig' in config.detection.engines
            assert config.detection.min_confidence == 'high'
        finally:
            Path(config_file).unlink(missing_ok=True)
    
    def test_environment_variable_override(self):
        """Test configuration override via environment variables."""
        with patch.dict(os.environ, {
            'SSTI_THREADS': '25',
            'SSTI_TIMEOUT': '90',
            'SSTI_FORMAT': 'json'
        }):
            config_manager = ConfigManager()
            config = config_manager.get_config()
            
            assert config.scanning.threads == 25
            assert config.scanning.timeout == 90
            assert config.output.format == 'json'
    
    def test_config_validation(self):
        """Test configuration validation."""
        # Invalid configuration should raise error
        invalid_config = {
            'scanning': {
                'threads': -1,  # Invalid
                'delay': -0.5,  # Invalid
                'intensity': 'invalid'  # Invalid
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            yaml.dump(invalid_config, f)
            config_file = f.name
        
        try:
            with pytest.raises(ValueError):
                ConfigManager(config_file=config_file)
        finally:
            Path(config_file).unlink(missing_ok=True)
    
    def test_config_merge(self):
        """Test configuration merging from multiple sources."""
        # Base config file
        base_config = {
            'scanning': {
                'threads': 15,
                'delay': 0.8
            },
            'detection': {
                'engines': ['jinja2']
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            yaml.dump(base_config, f)
            config_file = f.name
        
        try:
            # Override with environment variables
            with patch.dict(os.environ, {
                'SSTI_THREADS': '20',
                'SSTI_ENGINES': 'jinja2,twig,freemarker'
            }):
                config_manager = ConfigManager(config_file=config_file)
                config = config_manager.get_config()
                
                # Environment should override file
                assert config.scanning.threads == 20
                # File value should remain if not overridden
                assert config.scanning.delay == 0.8
                # List override should work
                assert 'jinja2' in config.detection.engines
                assert 'twig' in config.detection.engines
                assert 'freemarker' in config.detection.engines
        finally:
            Path(config_file).unlink(missing_ok=True)
    
    def test_config_profiles(self):
        """Test configuration profiles."""
        config_manager = ConfigManager()
        
        # Test quick profile
        quick_config = config_manager.get_profile_config('quick')
        assert quick_config.scanning.intensity == 'quick'
        assert quick_config.scanning.threads <= 10
        assert quick_config.crawling.max_depth <= 2
        
        # Test aggressive profile
        aggressive_config = config_manager.get_profile_config('aggressive')
        assert aggressive_config.scanning.intensity == 'aggressive'
        assert aggressive_config.scanning.threads >= 15
        assert aggressive_config.crawling.max_depth >= 5
        assert aggressive_config.detection.blind_injection is True
    
    def test_config_update(self):
        """Test runtime configuration updates."""
        config_manager = ConfigManager()
        
        # Update single value
        config_manager.update_config('scanning.threads', 25)
        config = config_manager.get_config()
        assert config.scanning.threads == 25
        
        # Update nested section
        config_manager.update_config('output', {
            'format': 'json',
            'colors': False
        })
        config = config_manager.get_config()
        assert config.output.format == 'json'
        assert config.output.colors is False


class TestScanConfig:
    """Test scan configuration data class."""
    
    def test_scan_config_creation(self):
        """Test scan configuration creation."""
        config = ScanConfig()
        
        # Check required attributes exist
        assert hasattr(config, 'scanning')
        assert hasattr(config, 'crawling')
        assert hasattr(config, 'detection')
        assert hasattr(config, 'output')
        assert hasattr(config, 'authentication')
        assert hasattr(config, 'proxy')
    
    def test_scan_config_serialization(self):
        """Test configuration serialization."""
        config = ScanConfig()
        
        # Test to_dict
        config_dict = config.to_dict()
        assert isinstance(config_dict, dict)
        assert 'scanning' in config_dict
        assert 'crawling' in config_dict
        
        # Test from_dict
        new_config = ScanConfig.from_dict(config_dict)
        assert new_config.scanning.threads == config.scanning.threads
        assert new_config.output.format == config.output.format
    
    def test_config_validation_methods(self):
        """Test configuration validation methods."""
        config = ScanConfig()
        
        # Valid configuration should pass
        assert config.validate() is True
        
        # Invalid values should fail validation
        config.scanning.threads = -1
        with pytest.raises(ValueError):
            config.validate()
    
    def test_config_inheritance(self):
        """Test configuration inheritance and overrides."""
        base_config = ScanConfig()
        
        # Create override configuration
        override_dict = {
            'scanning': {
                'threads': 25,
                'intensity': 'aggressive'
            },
            'output': {
                'format': 'json'
            }
        }
        
        # Apply overrides
        new_config = base_config.override(override_dict)
        
        # Check that overrides were applied
        assert new_config.scanning.threads == 25
        assert new_config.scanning.intensity == 'aggressive'
        assert new_config.output.format == 'json'
        
        # Check that non-overridden values remain
        assert new_config.scanning.delay == base_config.scanning.delay
        assert new_config.crawling.max_depth == base_config.crawling.max_depth


class TestConfigProfiles:
    """Test predefined configuration profiles."""
    
    def test_quick_profile(self):
        """Test quick scan profile."""
        config_manager = ConfigManager()
        config = config_manager.get_profile_config('quick')
        
        assert config.scanning.intensity == 'quick'
        assert config.scanning.threads <= 10
        assert config.crawling.max_depth <= 2
        assert config.crawling.max_pages <= 100
        assert config.detection.blind_injection is False
    
    def test_normal_profile(self):
        """Test normal scan profile."""
        config_manager = ConfigManager()
        config = config_manager.get_profile_config('normal')
        
        assert config.scanning.intensity == 'normal'
        assert 5 <= config.scanning.threads <= 15
        assert 2 <= config.crawling.max_depth <= 5
        assert 100 <= config.crawling.max_pages <= 1000
    
    def test_aggressive_profile(self):
        """Test aggressive scan profile."""
        config_manager = ConfigManager()
        config = config_manager.get_profile_config('aggressive')
        
        assert config.scanning.intensity == 'aggressive'
        assert config.scanning.threads >= 15
        assert config.crawling.max_depth >= 5
        assert config.crawling.max_pages >= 1000
        assert config.detection.blind_injection is True
    
    def test_stealth_profile(self):
        """Test stealth scan profile."""
        config_manager = ConfigManager()
        config = config_manager.get_profile_config('stealth')
        
        assert config.scanning.threads <= 5
        assert config.scanning.delay >= 2.0
        assert config.crawling.respect_robots is True
        assert config.crawling.enable_javascript is False
    
    def test_custom_profile_creation(self):
        """Test creating custom profiles."""
        config_manager = ConfigManager()
        
        # Define custom profile
        custom_profile = {
            'scanning': {
                'threads': 8,
                'delay': 1.5,
                'intensity': 'normal'
            },
            'detection': {
                'engines': ['jinja2', 'twig'],
                'min_confidence': 'medium'
            }
        }
        
        # Register custom profile
        config_manager.add_profile('custom', custom_profile)
        
        # Test custom profile
        config = config_manager.get_profile_config('custom')
        assert config.scanning.threads == 8
        assert config.scanning.delay == 1.5
        assert 'jinja2' in config.detection.engines
        assert 'twig' in config.detection.engines


class TestConfigPersistence:
    """Test configuration persistence and management."""
    
    def test_save_config(self):
        """Test saving configuration to file."""
        config_manager = ConfigManager()
        
        # Modify configuration
        config_manager.update_config('scanning.threads', 30)
        config_manager.update_config('output.format', 'json')
        
        # Save to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            config_file = f.name
        
        try:
            config_manager.save_config(config_file)
            
            # Load saved configuration
            new_config_manager = ConfigManager(config_file=config_file)
            new_config = new_config_manager.get_config()
            
            # Verify saved values
            assert new_config.scanning.threads == 30
            assert new_config.output.format == 'json'
        finally:
            Path(config_file).unlink(missing_ok=True)
    
    def test_config_backup_restore(self):
        """Test configuration backup and restore."""
        config_manager = ConfigManager()
        
        # Create backup
        backup = config_manager.backup_config()
        
        # Modify configuration
        config_manager.update_config('scanning.threads', 50)
        modified_config = config_manager.get_config()
        assert modified_config.scanning.threads == 50
        
        # Restore from backup
        config_manager.restore_config(backup)
        restored_config = config_manager.get_config()
        
        # Should match original
        assert restored_config.scanning.threads != 50
    
    def test_config_history(self):
        """Test configuration change history."""
        config_manager = ConfigManager()
        
        # Make several changes
        config_manager.update_config('scanning.threads', 15)
        config_manager.update_config('scanning.delay', 1.0)
        config_manager.update_config('output.format', 'json')
        
        # Check history
        history = config_manager.get_config_history()
        assert len(history) >= 3
        
        # Should contain recent changes
        changes = [change['key'] for change in history]
        assert 'scanning.threads' in changes
        assert 'scanning.delay' in changes
        assert 'output.format' in changes
