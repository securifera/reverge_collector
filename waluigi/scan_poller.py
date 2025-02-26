import recon_manager
import traceback
import argparse
import time
import sys
import logging

local_extender_port = 33333

logger = logging.getLogger(__name__)


def print_usage():
    print("Help:")
    print(" q - quit")
    print(" h - help")
    print(" d - debug")
    print(" x - Toggle Scanner Thread")
    print("")


def setup_logging():

    # Setup logging
    log_level = logging.DEBUG
    logging.basicConfig(level=log_level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                        datefmt='%Y-%m-%d_%H:%M:%S')

    # Setting up file handler
    file_handler = logging.FileHandler('waluigi.log')

    # Add handlers
    logger.addHandler(file_handler)


def main(args):

    # Create connection manager thread
    scan_thread = None
    debug = False
    exit_loop = False
    while exit_loop == False:
        try:
            # Create instance of recon manager
            recon_manager_inst = recon_manager.get_recon_manager(
                args.token, "http://127.0.0.1:%d" % local_extender_port)

            # Create the scheduled scan thread
            scan_thread = recon_manager.ScheduledScanThread(recon_manager_inst)
            scan_thread.start()

            # interactive console
            while exit_loop == False:
                print("Enter a command")
                # Only works in Python3
                print(">", end='')
                # For Python 2.7 - notice the space between print
                # print (">", end = '')
                command = input()
                if command == "q":
                    exit_loop = True
                    break
                elif command == 'h':
                    print_usage()
                elif command == 'd':
                    if debug == True:
                        debug = False
                        print("[*] Debugging disabled")
                    else:
                        debug = True
                        print("[*] Debugging enabled")
                    recon_manager_inst.set_debug(debug)

                elif command == 'x':
                    # Toggle the scan poller
                    scan_thread.toggle_poller()

        except Exception as e:
            if isinstance(e, recon_manager.SessionException):
                print("[*] Unable to get session key. Retrying in 30 seconds")
                time.sleep(30)
                continue
            elif "refused" in str(e):
                print("[*] Connection refused. Retrying in 30 seconds")
                time.sleep(30)
                continue
            else:
                print(traceback.format_exc())

            break

        if scan_thread:
            scan_thread.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-x", "--token", help="Collector Token", required=True)
    parser.add_argument('-t', dest='test',
                        help='Test flag', action='store_true')
    args = parser.parse_args()

    setup_logging()

    if args.test:
        print("[*] Test successful")
        sys.exit(0)

    main(args)
