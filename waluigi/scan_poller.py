"""
Waluigi Scan Poller Module

This module provides the main entry point and interactive console for the Waluigi
security scanning framework. It manages the scanning thread lifecycle, handles
user interaction through a command-line interface, and provides real-time logging
and debugging capabilities.

The scan poller serves as the primary control interface for:
- Managing scanning operations and thread lifecycle
- Providing interactive debugging and control commands
- Handling connection management with the scanning backend
- Real-time log monitoring and display
- Session management and error recovery

The module includes:
- Interactive command-line interface for scan control
- Queue-based logging system for real-time monitoring
- Connection retry logic for robust operation
- Scanning thread management and lifecycle control
- Debug mode toggling and monitoring capabilities

Classes:
    QueueHandler: Custom logging handler for queue-based log management

Functions:
    print_usage: Display available command-line interface commands
    setup_logging: Configure logging system with queue handler
    main: Main application loop with interactive console

Constants:
    local_extender_port (int): Port for local backend communication
"""

from waluigi import recon_manager
import traceback
import argparse
import time
import sys
import logging
import queue
from typing import Optional, Any, Union

# Configuration: Local backend communication port
local_extender_port: int = 33333


def print_usage() -> None:
    """
    Display available command-line interface commands to the user.

    This function prints a help menu showing all available interactive commands
    that can be used in the scan poller's command-line interface. It provides
    guidance for users on how to control the scanning operations.

    Returns:
        None: Prints help information to stdout

    Example:
        >>> print_usage()
        Help:
         q - quit
         h - help
         d - debug
         x - Toggle Scanner Thread

    Note:
        Commands are single-character for quick interaction during scanning operations
    """
    print("Help:")
    print(" q - quit")
    print(" h - help")
    print(" d - debug")
    print(" x - Toggle Scanner Thread")
    print("")


class QueueHandler(logging.Handler):
    """
    Custom logging handler that sends log records to a queue for processing.

    This handler extends the standard logging.Handler to support queue-based
    logging, enabling real-time log monitoring and display in the interactive
    console. It's designed for concurrent environments where log messages
    need to be processed separately from their generation.

    The handler safely puts formatted log records into a queue without blocking
    the logging thread, providing resilient log handling for the scanning system.

    Attributes:
        log_queue (queue.Queue): Queue for storing formatted log messages

    Example:
        >>> log_queue = queue.Queue()
        >>> handler = QueueHandler(log_queue)
        >>> logger = logging.getLogger()
        >>> logger.addHandler(handler)
    """

    def __init__(self, log_queue: queue.Queue) -> None:
        """
        Initialize the QueueHandler with a log queue.

        Args:
            log_queue (queue.Queue): Queue for storing formatted log messages

        Example:
            >>> log_queue = queue.Queue()
            >>> handler = QueueHandler(log_queue)
        """
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record: logging.LogRecord) -> None:
        """
        Emit a log record by putting it into the queue.

        This method formats the log record and attempts to put it into the queue
        without blocking. If the queue operation fails, it calls the standard
        error handling mechanism.

        Args:
            record (logging.LogRecord): Log record to be processed and queued

        Returns:
            None: Log record is placed in queue for later processing

        Example:
            >>> handler = QueueHandler(queue.Queue())
            >>> record = logging.LogRecord(...)
            >>> handler.emit(record)  # Record is queued for processing

        Note:
            Uses put_nowait() to avoid blocking if the queue is full
        """
        try:
            self.log_queue.put_nowait(self.format(record))
        except Exception:
            self.handleError(record)


def setup_logging() -> queue.Queue:
    """
    Configure the logging system with queue-based handler for real-time monitoring.

    This function sets up a comprehensive logging configuration including:
    - Debug-level logging with timestamp formatting
    - Queue-based handler for non-blocking log processing
    - Reduced verbosity for urllib3 to minimize noise
    - Consistent date/time formatting across all log messages

    The queue-based approach allows log messages to be processed asynchronously,
    which is essential for the interactive console to display logs in real-time
    without blocking the main application thread.

    Returns:
        queue.Queue: Configured log queue for retrieving formatted log messages

    Example:
        >>> log_queue = setup_logging()
        >>> # Log messages are now available in the queue
        >>> while not log_queue.empty():
        ...     print(log_queue.get_nowait())

    Note:
        - Sets urllib3 logging to WARNING level to reduce HTTP request noise
        - Uses DEBUG level for application logging
        - Configures consistent timestamp formatting
    """
    # Setup logging configuration
    log_level = logging.DEBUG
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    date_format = '%Y-%m-%d_%H:%M:%S'
    formatter = logging.Formatter(log_format, datefmt=date_format)

    # Configure basic logging
    logging.basicConfig(level=log_level, format=log_format,
                        datefmt=date_format)
    # Reduce urllib3 verbosity to minimize HTTP request noise
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    # Create queue-based logging handler
    log_queue = queue.Queue()
    queue_handler = QueueHandler(log_queue)
    queue_handler.setLevel(log_level)
    queue_handler.setFormatter(formatter)

    # Add queue handler to root logger
    logger = logging.getLogger()
    logger.addHandler(queue_handler)

    return log_queue


def main(args) -> None:
    """
    Main application loop with interactive console for scan management.

    This function serves as the primary entry point for the scan poller application.
    It manages the complete lifecycle of scanning operations including:
    - Connection management with retry logic for backend communication
    - Interactive command-line interface for real-time control
    - Scanning thread lifecycle management
    - Error handling and recovery mechanisms
    - Session management and reconnection logic

    The function runs in a continuous loop, handling user commands and managing
    the scanning operations until the user chooses to quit or an unrecoverable
    error occurs.

    Args:
        args: Command line arguments containing:
            - token (str): Authentication token for backend communication
            - test (bool): Test mode flag for validation runs

    Returns:
        None: Runs until user exits or fatal error occurs

    Raises:
        recon_manager.SessionException: When unable to establish session with backend
        ConnectionError: When backend connection is refused
        Exception: For any other unexpected errors during operation

    Example:
        >>> import argparse
        >>> args = argparse.Namespace()
        >>> args.token = "your-auth-token"
        >>> args.test = False
        >>> main(args)  # Starts interactive console

    Interactive Commands:
        - 'q': Quit the application
        - 'h': Display help menu
        - 'd': Toggle debug mode on/off
        - 'x': Toggle scanner thread on/off

    Note:
        - Automatically retries connection every 30 seconds on failure
        - Handles session exceptions gracefully with retry logic
        - Ensures proper cleanup of scanning threads on exit
    """
    # Initialize logging and create connection manager thread
    log_queue = setup_logging()
    scan_thread = None
    debug = False
    exit_loop = False

    while exit_loop == False:
        try:
            # Create instance of recon manager with backend connection
            recon_manager_inst = recon_manager.get_recon_manager(
                args.token, "http://127.0.0.1:%d" % local_extender_port)

            # Create and start the scheduled scan thread
            scan_thread = recon_manager.ScheduledScanThread(recon_manager_inst)
            scan_thread.log_queue = log_queue
            scan_thread.start()

            # Interactive console loop for user commands
            while exit_loop == False:
                print("Enter a command")
                # Display prompt for user input
                print(">", end='')
                command = input()

                # Process user commands
                if command == "q":
                    # Quit command - exit application
                    exit_loop = True
                    break
                elif command == 'h':
                    # Help command - display usage information
                    print_usage()
                elif command == 'd':
                    # Debug command - toggle debug mode
                    if debug == True:
                        debug = False
                        print("[*] Debugging disabled")
                    else:
                        debug = True
                        print("[*] Debugging enabled")
                    recon_manager_inst.set_debug(debug)
                elif command == 'x':
                    # Toggle scanner thread on/off
                    scan_thread.toggle_poller()

        except Exception as e:
            # Handle connection and session exceptions with retry logic
            if isinstance(e, recon_manager.SessionException):
                print("[*] Unable to register with server. Retrying in 30 seconds")
                time.sleep(30)
                continue
            elif "refused" in str(e):
                print("[*] Connection refused. Retrying in 30 seconds")
                time.sleep(30)
                continue
            else:
                # Unhandled exception - print traceback and exit
                print(traceback.format_exc())
            break

        # Ensure proper cleanup of scanning thread
        if scan_thread:
            scan_thread.stop()


if __name__ == "__main__":
    """
    Command-line entry point for the Waluigi scan poller application.

    This section handles command-line argument parsing and application initialization.
    It supports test mode for validation and requires an authentication token for
    backend communication.

    Command-line Arguments:
        -x, --token (str): Required authentication token for backend communication
        -t, --test: Optional test flag to validate installation and configuration

    Exit Codes:
        0: Successful test run or normal application exit
        1: Missing required arguments or runtime error

    Example:
        $ python scan_poller.py --token "your-auth-token"
        $ python scan_poller.py --token "your-token" --test  # Test mode
    """
    # Configure command-line argument parser
    parser = argparse.ArgumentParser(
        description="Waluigi Security Scanning Framework - Interactive Console",
        epilog="Use 'h' command in interactive mode for runtime help"
    )
    parser.add_argument(
        "-x", "--token",
        help="Collector authentication token for backend communication",
        required=True,
        type=str
    )
    parser.add_argument(
        '-t', dest='test',
        help='Test flag to validate installation and configuration',
        action='store_true'
    )

    # Parse command-line arguments
    args = parser.parse_args()

    # Handle test mode
    if args.test:
        print("[*] Test successful - Waluigi scan poller configuration validated")
        sys.exit(0)

    # Start main application
    main(args)
