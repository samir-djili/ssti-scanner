"""
Main CLI entry point for SSTI Scanner.

This module provides the main command-line interface using argparse
with subcommands for different scanner operations.
"""

import argparse
import sys
import asyncio
from typing import List, Optional

from ssti_scanner.core.config import Config
from ssti_scanner.core.scanner import SSTIScanner
from ssti_scanner.reporters.console_reporter import ConsoleReporter
from ssti_scanner.utils.logger import setup_logging
from .commands import ScanCommand, CrawlCommand, AnalyzeCommand, PayloadCommand, ReportCommand, ConfigCommand


def create_parser() -> argparse.ArgumentParser:
    """Create the main argument parser with subcommands."""
    
    parser = argparse.ArgumentParser(
        prog='ssti-scanner',
        description='Advanced Server-Side Template Injection (SSTI) vulnerability scanner',
        epilog='For detailed help on subcommands, use: ssti-scanner <command> --help'
    )
    
    # Global options
    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s 1.0.0'
    )
    
    parser.add_argument(
        '--config',
        type=str,
        help='Configuration file path (YAML or JSON)'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )
    
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Suppress non-essential output'
    )
    
    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )
    
    # Create subparsers
    subparsers = parser.add_subparsers(
        dest='command',
        help='Available commands',
        metavar='COMMAND'
    )
    
    # Add subcommands
    ScanCommand.add_parser(subparsers)
    CrawlCommand.add_parser(subparsers)
    AnalyzeCommand.add_parser(subparsers)
    PayloadCommand.add_parser(subparsers)
    ReportCommand.add_parser(subparsers)
    ConfigCommand.add_parser(subparsers)
    
    return parser


async def run_scan_command(args: argparse.Namespace, config: Config) -> int:
    """Execute the scan command."""
    try:
        scanner = SSTIScanner(config)
        console_reporter = ConsoleReporter(use_colors=not args.no_color)
        
        # Determine targets
        targets = []
        if args.url:
            targets.append(args.url)
        elif args.file:
            with open(args.file, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        else:
            console_reporter.print_progress("No targets specified", "error")
            return 1
        
        # Configure scan options
        scan_options = {
            'intensity': args.intensity,
            'engines': args.engines.split(',') if args.engines else None,
            'crawl_depth': args.crawl_depth,
            'follow_redirects': args.follow_redirects,
            'include_blind': args.blind,
        }
        
        console_reporter.print_progress(f"Starting scan of {len(targets)} target(s)", "info")
        
        # Execute scan
        for target in targets:
            console_reporter.print_progress(f"Scanning: {target}", "info")
            
            result = await scanner.scan_target(target, **scan_options)
            
            # Print results
            if not args.quiet:
                report = console_reporter.generate_report(result)
                print(report)
            
            # Save results if output specified
            if args.output:
                from ssti_scanner.reporters.json_reporter import JSONReporter
                json_reporter = JSONReporter(args.output)
                output_path = json_reporter.save_report(result)
                console_reporter.print_progress(f"Results saved to: {output_path}", "success")
        
        return 0
        
    except KeyboardInterrupt:
        console_reporter.print_progress("Scan interrupted by user", "warning")
        return 1
    except Exception as e:
        console_reporter.print_progress(f"Scan failed: {e}", "error")
        if args.debug:
            import traceback
            traceback.print_exc()
        return 1


def main(argv: Optional[List[str]] = None) -> int:
    """
    Main entry point for the CLI.
    
    Args:
        argv: Command line arguments, uses sys.argv if None
        
    Returns:
        Exit code (0 for success, non-zero for error)
    """
    parser = create_parser()
    args = parser.parse_args(argv)
    
    # Handle no command specified
    if not args.command:
        parser.print_help()
        return 1
    
    # Setup logging
    log_level = 'DEBUG' if args.debug else 'INFO'
    if args.quiet:
        log_level = 'WARNING'
    
    setup_logging(level=log_level)
    
    try:
        # Load configuration
        config = Config()
        if args.config:
            config.load_from_file(args.config)
        
        # Override config with CLI args
        if hasattr(args, 'threads') and args.threads:
            config.scanning.threads = args.threads
        if hasattr(args, 'timeout') and args.timeout:
            config.crawling.timeout = args.timeout
        if hasattr(args, 'delay') and args.delay:
            config.scanning.delay = args.delay
        
        # Execute command
        if args.command == 'scan':
            return asyncio.run(run_scan_command(args, config))
        elif args.command == 'crawl':
            return CrawlCommand.execute(args, config)
        elif args.command == 'analyze':
            return AnalyzeCommand.execute(args, config)
        elif args.command == 'payloads':
            return PayloadCommand.execute(args, config)
        elif args.command == 'report':
            return ReportCommand.execute(args, config)
        elif args.command == 'config':
            return ConfigCommand.execute(args, config)
        else:
            parser.print_help()
            return 1
            
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
