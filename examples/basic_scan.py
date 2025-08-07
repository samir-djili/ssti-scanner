#!/usr/bin/env python3
"""
Basic SSTI Scanner Usage Example

This example demonstrates the most basic usage of the SSTI scanner:
- Scanning a single URL
- Using default configuration
- Simple output handling

Author: SSTI Scanner Team
License: MIT
"""

import asyncio
import logging
from pathlib import Path

# Import SSTI scanner components
from src.core.scanner import SSTIScanner
from src.core.config import ConfigManager
from src.reporters.console import ConsoleReporter

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def basic_scan_example():
    """
    Perform a basic scan of a single URL.
    
    This example shows:
    1. Creating a scanner with default configuration
    2. Scanning a single URL
    3. Handling results
    """
    
    # Target URL for scanning
    # NOTE: Only scan URLs you own or have permission to test!
    target_url = "http://testphp.vulnweb.com/search.php?test=query"
    
    logger.info(f"Starting basic scan of: {target_url}")
    
    try:
        # Step 1: Create configuration manager with defaults
        config_manager = ConfigManager()
        config = config_manager.get_config()
        
        # Optional: Customize basic settings
        config.scanning.threads = 5  # Use fewer threads for basic scan
        config.scanning.delay = 1.0  # Add delay between requests
        config.output.format = 'console'  # Use console output
        
        # Step 2: Create scanner instance
        scanner = SSTIScanner(config)
        
        # Step 3: Create reporter for output
        reporter = ConsoleReporter(config)
        
        # Step 4: Perform the scan
        logger.info("Starting SSTI vulnerability scan...")
        
        # Scan the single URL
        results = await scanner.scan_url(target_url)
        
        # Step 5: Process and display results
        logger.info(f"Scan completed. Found {len(results)} results.")
        
        if results:
            logger.info("Generating report...")
            await reporter.generate_report(results)
        else:
            logger.info("No vulnerabilities detected.")
        
        # Step 6: Display summary
        vulnerability_count = sum(1 for result in results if result.is_vulnerable)
        
        print(f"\n{'='*50}")
        print(f"SCAN SUMMARY")
        print(f"{'='*50}")
        print(f"Target URL: {target_url}")
        print(f"Total Tests: {len(results)}")
        print(f"Vulnerabilities Found: {vulnerability_count}")
        
        if vulnerability_count > 0:
            print(f"\n⚠️  VULNERABILITIES DETECTED!")
            print(f"Please review the detailed results above.")
        else:
            print(f"\n✅ No vulnerabilities found.")
        
        return results
        
    except Exception as e:
        logger.error(f"Error during scan: {e}")
        raise
    
    finally:
        # Step 7: Cleanup
        await scanner.close()
        logger.info("Scanner cleanup completed.")


async def multiple_urls_example():
    """
    Scan multiple URLs with basic configuration.
    
    This example shows how to scan multiple targets
    in sequence with the same scanner instance.
    """
    
    # List of URLs to scan
    # NOTE: Only include URLs you own or have permission to test!
    target_urls = [
        "http://testphp.vulnweb.com/search.php?test=query",
        "http://testphp.vulnweb.com/userinfo.php?user=test",
        "http://httpbin.org/get?param=value"  # Safe testing endpoint
    ]
    
    logger.info(f"Starting scan of {len(target_urls)} URLs")
    
    try:
        # Create scanner with default configuration
        config_manager = ConfigManager()
        config = config_manager.get_config()
        
        # Optimize for multiple URL scanning
        config.scanning.threads = 3  # Conservative threading
        config.scanning.delay = 0.5  # Reasonable delay
        
        scanner = SSTIScanner(config)
        reporter = ConsoleReporter(config)
        
        all_results = []
        
        # Scan each URL
        for i, url in enumerate(target_urls, 1):
            logger.info(f"Scanning URL {i}/{len(target_urls)}: {url}")
            
            try:
                results = await scanner.scan_url(url)
                all_results.extend(results)
                
                vuln_count = sum(1 for r in results if r.is_vulnerable)
                logger.info(f"URL {i} completed: {vuln_count} vulnerabilities found")
                
            except Exception as e:
                logger.error(f"Error scanning {url}: {e}")
                continue
        
        # Generate combined report
        if all_results:
            logger.info("Generating combined report...")
            await reporter.generate_report(all_results)
        
        # Summary
        total_vulns = sum(1 for r in all_results if r.is_vulnerable)
        print(f"\n{'='*60}")
        print(f"MULTI-URL SCAN SUMMARY")
        print(f"{'='*60}")
        print(f"URLs Scanned: {len(target_urls)}")
        print(f"Total Tests: {len(all_results)}")
        print(f"Total Vulnerabilities: {total_vulns}")
        
        return all_results
        
    except Exception as e:
        logger.error(f"Error during multi-URL scan: {e}")
        raise
    
    finally:
        await scanner.close()


def save_results_example(results, output_file="scan_results.json"):
    """
    Save scan results to a file for later analysis.
    
    Args:
        results: List of scan results
        output_file: Path to save results
    """
    
    import json
    from datetime import datetime
    
    if not results:
        logger.info("No results to save.")
        return
    
    # Prepare results for JSON serialization
    serializable_results = []
    
    for result in results:
        result_dict = {
            'timestamp': datetime.now().isoformat(),
            'url': result.url,
            'is_vulnerable': result.is_vulnerable,
            'confidence': result.confidence.value if hasattr(result.confidence, 'value') else str(result.confidence),
            'engine': result.engine,
            'payload': result.payload,
            'response_snippet': result.response[:200] if result.response else None,
            'evidence': result.evidence
        }
        serializable_results.append(result_dict)
    
    # Save to file
    output_path = Path(output_file)
    
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(serializable_results, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Results saved to: {output_path.absolute()}")
        print(f"\n📁 Results saved to: {output_path.absolute()}")
        
    except Exception as e:
        logger.error(f"Error saving results: {e}")


async def main():
    """
    Main function demonstrating different basic usage patterns.
    """
    
    print("🔍 SSTI Scanner - Basic Usage Examples")
    print("="*50)
    
    try:
        # Example 1: Single URL scan
        print("\n1️⃣ Single URL Scan Example")
        print("-" * 30)
        results1 = await basic_scan_example()
        
        # Save results from first example
        if results1:
            save_results_example(results1, "basic_scan_results.json")
        
        print("\n" + "="*50)
        
        # Example 2: Multiple URLs scan
        print("\n2️⃣ Multiple URLs Scan Example")
        print("-" * 35)
        results2 = await multiple_urls_example()
        
        # Save results from second example
        if results2:
            save_results_example(results2, "multi_url_results.json")
        
        print("\n" + "="*50)
        print("✅ All examples completed successfully!")
        
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user.")
        print("\n⏹️ Scan interrupted by user.")
        
    except Exception as e:
        logger.error(f"Example execution failed: {e}")
        print(f"\n❌ Error: {e}")
        raise


if __name__ == "__main__":
    """
    Run the basic examples when script is executed directly.
    
    Usage:
        python basic_scan.py
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
