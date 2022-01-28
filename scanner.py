''' Scanner.py  submitted by Robert Blanchett 100639184
    v0.7        for Holmesglen CertIV in cybesecurity 22334VIC
                Programming Assessment Task 2.

                A command line reporter from the Virus Total API

                find __main__ for notes on TODO to expand this script. 

Developed on    Windows 10 Enterprise (Build 1904) 
                Developer Evaluation Virtual Box VM (linux host)
                Python 3.9.6 (64 bit) from python.org
                VScode 1.59 with pylance installed

                All My own work. RDB

                Requires vt-py and validators from pypi

                ONLY urls are reported on at this stage to keep script within ~150 loc

                provided test datafiles IPs, URLs and domains from: 
                spamhaus.de, URLhaus.de, iplists.FireHol.org and scumware.org

                Please refer to the README for information development and the distrubuted files.
                and the one known BUG with double usage printing from configparser.
'''
import sys          # Python Runtime, exception tamer and basename extraction
import os           # path and file operations
import datetime     # stamping reports and filenames
import configparser # state persistence across executions
import argparse     # CLI from stdlib
import socket       # check the network
import time         # delay API calls
import vt           # virus Total API Python client Library (install with pip)
import validators   # validators library (install with pip)

## validators, vt-py modules from from pypi, 

## Keys and Essential Constants  (Reserved from Configparser to aid readability)
## Establish Configparser

VTAPIKEY = ''
install_directory = sys.argv[0][:-10]   # windows sets argv[0] to path to path *and* filename
now = datetime.datetime.now().strftime("-%Y-%m-%d-%H-%M-%S") # .scanrc backup
scanrc = '.scanrc'                      # Config File
config = configparser.ConfigParser()
supplied =[]                            # processing buckets for validation and scan
valid_ip = []                           #
valid_url = []                          #
valid_domain = []                       #

def init(args):
    ''' Reset the configuration file backing up an existing one, if found. '''

    if  os.path.isfile(install_directory+scanrc):
        print(f"\nBacking up Config File {install_directory+scanrc} to {install_directory+scanrc+now}")
        os.rename(install_directory+scanrc, install_directory+scanrc+now)       

    else:
       print(f"\nConfig File {install_directory+scanrc} not found, Resetting Configuration.")

    config['DEFAULT'] = {'Runs': 0, 'URLScanCount': '0', 'Malicious': 0}
    config['State'] = {'Runs': 0, 'UrlScanCount': 0, 'Malicious': 0}
    config['LastRun'] = {}
    config.write(open(install_directory+scanrc, 'w'))

def check_network():
    '''Internet availability check. Cloudflare is always there.'''
    try:
        socket.create_connection(("1.1.1.1", 53))
        return True
    except OSError:
        return False
    

def scan(args):
    ''' Validate and submit to VirusTotal API for reports the contents of submitted files'''
    if check_network():
        print("\nInternet available. Continuing.")

    else:
        print("\nInternet unavailable. Exiting.")
        sys.exit()

    print("\nprocessing supplied files.") 
    for n in range(len(args.files)):
        print(args.files[n].name)
    print("\nplease wait. VirusTotal limits requests to 4/minute.")
    print("and so does this script!\n")
    
    for l in range(len(args.files)):
        for line in args.files[l]:
            supplied.append(line.rstrip())

    print((len(supplied)), "items to be validated before scanning.\n")

    print(supplied)

    # validate items
    to_validate = supplied.copy()
    valid_ip = [x for x in to_validate if validators.ip_address.ipv4(x)]
    valid_url = [x for x in to_validate if validators.url(x)]
    valid_domain = [x for x in to_validate if validators.domain(x)]

    # only scanning the URLs to keep the script  within ~150 loc
    # each returned object type has a different set of API endpoints 
    # and object members I'd have to code uniquely for

    vtGet = vt.Client(VTAPIKEY)
    urlResults = dict.fromkeys(valid_url)
    scanRuns =  config.getint('State', 'Runs')
    print("\nPrevious Runs", scanRuns)
    
    for i in range(len(valid_url)):

        print("\nSubmitting Url: ", valid_url[i])
        url_id = vt.url_id(valid_url[i])
        response = vtGet.get_object("/urls/{}", url_id)
        urlResults[valid_url[i]] = response.last_analysis_stats
        config.write(open(install_directory+scanrc, 'w'))
        # config  to store results and increment of scan run as subkeys in config file. future/excised work.
        time.sleep(13)

    vtGet.close()       # Cleanup http connection

    config.set('State', 'Runs', str(scanRuns +1))

    print("\nScanner run {} Report {}".format(config.getint('State', 'Runs'), datetime.datetime.now().strftime("%A, %d %b %H:%M")))
    print("The number of virus products and how the URL was reported by them.")
    print("Results from The VirusTotal.com Public API")
    for url, results in urlResults.items():
        print("\nURL: {}".format(url))
        for type in results:
            print("{0:<11} : {1:<}".format(type, results[type]))

    config.write(open(install_directory+scanrc, 'w'))
    
def main(args):
    '''  Framework logic and function dispatcher'''

# Read config.
    if  os.path.isfile(install_directory+scanrc):
        config.read(install_directory+scanrc)
    
    else:
        init(args)

# Command Dispatcher
    action = {'init': init, 'scan': scan}
    action[args.subcommand](args)

if __name__ == "__main__":
    '''File handle collection and CLI parsing by argparse'''
    # TODO: work removed to get minimum working code ~150 loc
    # 
    # include submission of IP addresses, domains and filehashes.
    # functionality removed for LOC limitations
    # add subparsers for unimplemented subcommands: list (previous runs etc),
    # shutdown (handle KeyboardInterrupt Ctrl-C interrupt during scan)
    # import hashlib  to submit file hashes for checking
    # import subprocess to do in-script installation of pypi on ModuleNotFoundError
    # record detailed run information in .scanrc with configparser
    parser=argparse.ArgumentParser(description="scanner Registry and Malicious Item Scanner", usage='''
    scanner.py <command> [filenames ..]

    The currently implemented subcommands are:
    init                                Reset the Configuration
    scan  [filename1 filename2 ..]      Submit one or more plaintext files with either:
                                        ONE IP address or ONE Web URL or ONE Domain per line''')
    
    subparser = parser.add_subparsers(dest='subcommand', title='subcommands',help='scanner subcommand help')
    subparser.required=True
    parser_init = subparser.add_parser('init', help='reset the configuration file.')
    parser_init.set_defaults(func=init)
    parser_scan = subparser.add_parser('scan', help='supply text files with items to be scanned.')
    parser_scan.add_argument('files', type=argparse.FileType('r'), nargs='+')
    parser_scan.set_defaults(func=scan)
    
    args=parser.parse_args()
    
    main(args)