#!/usr/bin/env python3
"""
File Input Example for SSTI Scanner

This example demonstrates how to scan URLs from various file formats:
- Simple text files with URLs
- Extended format with HTTP methods and data
- Burp Suite exports
- OWASP ZAP exports
- JSON format files

Author: SSTI Scanner Team
License: MIT
"""

import asyncio
import logging
import json
import tempfile
from pathlib import Path

# Import SSTI scanner components
from src.core.scanner import SSTIScanner
from src.core.config import ConfigManager
from src.input.url_list_processor import URLListProcessor
from src.reporters.console import ConsoleReporter

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def create_sample_url_files():
    """
    Create sample URL files in different formats for demonstration.
    
    Returns:
        dict: Mapping of format names to file paths
    """
    
    sample_files = {}
    
    # 1. Simple URL list
    simple_urls = [
        "http://testphp.vulnweb.com/search.php?test=query",
        "http://testphp.vulnweb.com/userinfo.php?user=test",
        "http://httpbin.org/get?param=value",
        "http://httpbin.org/post",
        "http://httpbin.org/put"
    ]
    
    simple_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
    simple_file.write('\n'.join(simple_urls))
    simple_file.close()
    sample_files['simple'] = simple_file.name
    
    # 2. Extended format with methods and data
    extended_content = """# Extended format URL list
# Comments are supported

# GET requests (default)
http://testphp.vulnweb.com/search.php?test=query
http://httpbin.org/get?param=value

# POST requests with form data
POST http://httpbin.org/post data=param1=value1&param2=value2
POST http://testphp.vulnweb.com/login.php username=admin&password=test

# POST with JSON data
POST http://httpbin.org/post [data={"key":"value","test":"data"}]

# Requests with custom headers
GET http://httpbin.org/headers [headers={"X-Custom":"test","Authorization":"Bearer token"}]

# Complex request with multiple options
POST http://api.example.com/endpoint [data={"query":"{{test}}"},headers={"Content-Type":"application/json","X-API-Key":"secret"}]
"""
    
    extended_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
    extended_file.write(extended_content)
    extended_file.close()
    sample_files['extended'] = extended_file.name
    
    # 3. JSON format
    json_data = {
        "targets": [
            {
                "url": "http://httpbin.org/get",
                "method": "GET",
                "params": {"q": "test"}
            },
            {
                "url": "http://httpbin.org/post",
                "method": "POST",
                "data": {"field": "value"},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"}
            },
            {
                "url": "http://api.example.com/search",
                "method": "POST",
                "data": {"query": "search term"},
                "headers": {"Content-Type": "application/json"}
            }
        ]
    }
    
    json_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
    json.dump(json_data, json_file, indent=2)
    json_file.close()
    sample_files['json'] = json_file.name
    
    return sample_files


async def simple_file_scan_example():
    """
    Example of scanning URLs from a simple text file.
    """
    
    logger.info("Example 1: Simple URL file scanning")
    
    # Create sample file
    sample_files = create_sample_url_files()
    simple_file = sample_files['simple']
    
    try:
        # Step 1: Process URL file
        processor = URLListProcessor()
        
        logger.info(f"Loading URLs from: {simple_file}")
        urls = processor.load_from_file(simple_file)
        
        logger.info(f"Loaded {len(urls)} URLs from file")
        
        # Display loaded URLs
        print("\n📄 Loaded URLs:")
        for i, url_entry in enumerate(urls, 1):
            print(f"  {i}. {url_entry.url} ({url_entry.method})")
        
        # Step 2: Configure scanner
        config_manager = ConfigManager()
        config = config_manager.get_config()
        
        # Optimize for file-based scanning
        config.scanning.threads = 3
        config.scanning.delay = 0.5
        
        # Step 3: Scan URLs
        scanner = SSTIScanner(config)
        reporter = ConsoleReporter(config)
        
        all_results = []
        
        for url_entry in urls:
            logger.info(f"Scanning: {url_entry.url}")
            
            try:
                # Convert URLEntry to scan parameters
                if url_entry.method == 'GET':
                    results = await scanner.scan_url(url_entry.url)
                else:
                    results = await scanner.scan_url(
                        url_entry.url,
                        method=url_entry.method,
                        data=url_entry.data,
                        headers=url_entry.headers
                    )
                
                all_results.extend(results)
                
            except Exception as e:
                logger.error(f"Error scanning {url_entry.url}: {e}")
                continue
        
        # Step 4: Generate report
        if all_results:
            await reporter.generate_report(all_results)
        
        # Step 5: Summary
        vuln_count = sum(1 for r in all_results if r.is_vulnerable)
        print(f"\n📊 Simple File Scan Summary:")
        print(f"   URLs processed: {len(urls)}")
        print(f"   Tests performed: {len(all_results)}")
        print(f"   Vulnerabilities found: {vuln_count}")
        
        return all_results
        
    finally:
        await scanner.close()
        # Cleanup temp file
        Path(simple_file).unlink(missing_ok=True)


async def extended_file_scan_example():
    """
    Example of scanning URLs from extended format file.
    """
    
    logger.info("Example 2: Extended format file scanning")
    
    # Create sample file
    sample_files = create_sample_url_files()
    extended_file = sample_files['extended']
    
    try:
        # Step 1: Process extended format file
        processor = URLListProcessor()
        
        logger.info(f"Loading URLs from extended format: {extended_file}")
        urls = processor.load_from_file(extended_file, format='extended')
        
        logger.info(f"Loaded {len(urls)} URL entries from extended format")
        
        # Display loaded URLs with details
        print("\n📄 Loaded URL entries:")
        for i, url_entry in enumerate(urls, 1):
            print(f"  {i}. {url_entry.method} {url_entry.url}")
            if url_entry.data:
                print(f"      Data: {url_entry.data}")
            if url_entry.headers:
                print(f"      Headers: {url_entry.headers}")
        
        # Step 2: Configure scanner for more thorough testing
        config_manager = ConfigManager()
        config = config_manager.get_config()
        
        config.scanning.threads = 5
        config.scanning.delay = 1.0
        config.scanning.intensity = 'normal'
        
        # Step 3: Scan with extended parameters
        scanner = SSTIScanner(config)
        reporter = ConsoleReporter(config)
        
        all_results = []
        
        for url_entry in urls:
            logger.info(f"Scanning: {url_entry.method} {url_entry.url}")
            
            try:
                results = await scanner.scan_url(
                    url_entry.url,
                    method=url_entry.method,
                    data=url_entry.data,
                    headers=url_entry.headers
                )
                
                all_results.extend(results)
                
            except Exception as e:
                logger.error(f"Error scanning {url_entry.url}: {e}")
                continue
        
        # Step 4: Generate detailed report
        if all_results:
            await reporter.generate_report(all_results)
        
        # Step 5: Summary with statistics
        vuln_count = sum(1 for r in all_results if r.is_vulnerable)
        methods_used = set(url.method for url in urls)
        
        print(f"\n📊 Extended File Scan Summary:")
        print(f"   URL entries processed: {len(urls)}")
        print(f"   HTTP methods used: {', '.join(sorted(methods_used))}")
        print(f"   Tests performed: {len(all_results)}")
        print(f"   Vulnerabilities found: {vuln_count}")
        
        return all_results
        
    finally:
        await scanner.close()
        # Cleanup temp file
        Path(extended_file).unlink(missing_ok=True)


async def json_file_scan_example():
    """
    Example of scanning URLs from JSON format file.
    """
    
    logger.info("Example 3: JSON format file scanning")
    
    # Create sample file
    sample_files = create_sample_url_files()
    json_file = sample_files['json']
    
    try:
        # Step 1: Process JSON format file
        processor = URLListProcessor()
        
        logger.info(f"Loading URLs from JSON format: {json_file}")
        urls = processor.load_from_file(json_file, format='json')
        
        logger.info(f"Loaded {len(urls)} URL entries from JSON format")
        
        # Display loaded URLs
        print("\n📄 Loaded JSON entries:")
        for i, url_entry in enumerate(urls, 1):
            print(f"  {i}. {url_entry.method} {url_entry.url}")
            if url_entry.data:
                print(f"      Data: {url_entry.data}")
            if url_entry.headers:
                print(f"      Headers: {list(url_entry.headers.keys()) if url_entry.headers else 'None'}")
        
        # Step 2: Configure scanner
        config_manager = ConfigManager()
        config = config_manager.get_config()
        
        config.scanning.threads = 4
        config.scanning.delay = 0.8
        
        # Step 3: Scan JSON entries
        scanner = SSTIScanner(config)
        reporter = ConsoleReporter(config)
        
        all_results = []
        
        for url_entry in urls:
            logger.info(f"Scanning JSON entry: {url_entry.method} {url_entry.url}")
            
            try:
                results = await scanner.scan_url(
                    url_entry.url,
                    method=url_entry.method,
                    data=url_entry.data,
                    headers=url_entry.headers
                )
                
                all_results.extend(results)
                
            except Exception as e:
                logger.error(f"Error scanning {url_entry.url}: {e}")
                continue
        
        # Step 4: Generate report
        if all_results:
            await reporter.generate_report(all_results)
        
        # Step 5: Summary
        vuln_count = sum(1 for r in all_results if r.is_vulnerable)
        
        print(f"\n📊 JSON File Scan Summary:")
        print(f"   JSON entries processed: {len(urls)}")
        print(f"   Tests performed: {len(all_results)}")
        print(f"   Vulnerabilities found: {vuln_count}")
        
        return all_results
        
    finally:
        await scanner.close()
        # Cleanup temp file
        Path(json_file).unlink(missing_ok=True)


def url_list_filtering_example():
    """
    Example of URL list filtering and processing capabilities.
    """
    
    logger.info("Example 4: URL list filtering and processing")
    
    # Create sample file with mixed URLs
    mixed_urls = [
        "http://example.com/test",
        "https://secure.example.com/api",
        "http://different.com/endpoint",
        "https://api.example.com/v1/search",
        "ftp://files.example.com/data",  # Non-HTTP
        "http://example.com/duplicate",
        "http://example.com/duplicate",  # Duplicate
    ]
    
    temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
    temp_file.write('\n'.join(mixed_urls))
    temp_file.close()
    
    try:
        processor = URLListProcessor()
        
        # Load all URLs
        all_urls = processor.load_from_file(temp_file.name)
        print(f"\n📄 Original URLs loaded: {len(all_urls)}")
        
        # Filter by domain
        example_urls = processor.filter_by_domain(all_urls, "example.com")
        print(f"📄 URLs from example.com: {len(example_urls)}")
        
        # Filter by scheme
        https_urls = processor.filter_by_scheme(all_urls, "https")
        print(f"📄 HTTPS URLs: {len(https_urls)}")
        
        # Remove duplicates
        unique_urls = processor.deduplicate(all_urls)
        print(f"📄 Unique URLs: {len(unique_urls)}")
        
        # Get statistics
        stats = processor.get_statistics(all_urls)
        print(f"\n📊 URL Statistics:")
        print(f"   Total URLs: {stats['total_urls']}")
        print(f"   Unique URLs: {stats['unique_urls']}")
        print(f"   Domains: {stats['unique_domains']}")
        print(f"   HTTP methods: {', '.join(stats['methods'])}")
        
        # Export filtered results
        output_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
        processor.export_simple(unique_urls, output_file.name)
        print(f"📁 Filtered URLs exported to: {output_file.name}")
        
        return unique_urls
        
    finally:
        # Cleanup temp files
        Path(temp_file.name).unlink(missing_ok=True)
        Path(output_file.name).unlink(missing_ok=True)


async def batch_processing_example():
    """
    Example of batch processing multiple URL files.
    """
    
    logger.info("Example 5: Batch processing multiple files")
    
    # Create multiple sample files
    sample_files = create_sample_url_files()
    
    try:
        # Configure scanner for batch processing
        config_manager = ConfigManager()
        config = config_manager.get_config()
        
        config.scanning.threads = 6
        config.scanning.delay = 0.3
        config.output.format = 'json'
        
        scanner = SSTIScanner(config)
        processor = URLListProcessor()
        
        all_batch_results = []
        total_urls = 0
        
        # Process each file type
        for file_type, file_path in sample_files.items():
            logger.info(f"Processing {file_type} format file: {file_path}")
            
            try:
                # Determine format
                if file_type == 'json':
                    urls = processor.load_from_file(file_path, format='json')
                elif file_type == 'extended':
                    urls = processor.load_from_file(file_path, format='extended')
                else:
                    urls = processor.load_from_file(file_path, format='simple')
                
                print(f"  📄 Loaded {len(urls)} URLs from {file_type} file")
                total_urls += len(urls)
                
                # Scan URLs from this file
                file_results = []
                for url_entry in urls:
                    try:
                        results = await scanner.scan_url(
                            url_entry.url,
                            method=url_entry.method,
                            data=url_entry.data,
                            headers=url_entry.headers
                        )
                        file_results.extend(results)
                        
                    except Exception as e:
                        logger.error(f"Error scanning {url_entry.url}: {e}")
                        continue
                
                all_batch_results.extend(file_results)
                
                vuln_count = sum(1 for r in file_results if r.is_vulnerable)
                print(f"  ✅ {file_type}: {len(file_results)} tests, {vuln_count} vulnerabilities")
                
            except Exception as e:
                logger.error(f"Error processing {file_type} file: {e}")
                continue
        
        # Final summary
        total_vulns = sum(1 for r in all_batch_results if r.is_vulnerable)
        
        print(f"\n📊 Batch Processing Summary:")
        print(f"   Files processed: {len(sample_files)}")
        print(f"   Total URLs: {total_urls}")
        print(f"   Total tests: {len(all_batch_results)}")
        print(f"   Total vulnerabilities: {total_vulns}")
        
        return all_batch_results
        
    finally:
        await scanner.close()
        # Cleanup all temp files
        for file_path in sample_files.values():
            Path(file_path).unlink(missing_ok=True)


async def main():
    """
    Main function demonstrating various file input methods.
    """
    
    print("📁 SSTI Scanner - File Input Examples")
    print("="*50)
    
    try:
        # Example 1: Simple file scanning
        print("\n1️⃣ Simple URL File Scanning")
        print("-" * 35)
        await simple_file_scan_example()
        
        print("\n" + "="*50)
        
        # Example 2: Extended format scanning
        print("\n2️⃣ Extended Format File Scanning")
        print("-" * 40)
        await extended_file_scan_example()
        
        print("\n" + "="*50)
        
        # Example 3: JSON format scanning
        print("\n3️⃣ JSON Format File Scanning")
        print("-" * 35)
        await json_file_scan_example()
        
        print("\n" + "="*50)
        
        # Example 4: URL filtering
        print("\n4️⃣ URL List Filtering and Processing")
        print("-" * 45)
        url_list_filtering_example()
        
        print("\n" + "="*50)
        
        # Example 5: Batch processing
        print("\n5️⃣ Batch Processing Multiple Files")
        print("-" * 42)
        await batch_processing_example()
        
        print("\n" + "="*50)
        print("✅ All file input examples completed successfully!")
        
    except KeyboardInterrupt:
        logger.info("Examples interrupted by user.")
        print("\n⏹️ Examples interrupted by user.")
        
    except Exception as e:
        logger.error(f"Example execution failed: {e}")
        print(f"\n❌ Error: {e}")
        raise


if __name__ == "__main__":
    """
    Run the file input examples when script is executed directly.
    
    Usage:
        python file_input.py
    """
    
    # Check Python version
    import sys
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 or higher is required.")
        sys.exit(1)
    
    # Run examples
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    except Exception as e:
        print(f"\n💥 Fatal error: {e}")
        sys.exit(1)
