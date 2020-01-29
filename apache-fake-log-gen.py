#!/usr/bin/python
import time
import datetime
import pytz
import numpy
import random
import gzip
import zipfile
import sys
import argparse
from faker import Faker
from random import randrange
from tzlocal import get_localzone
import socket
import struct
import gzip as gz
import numpy as np

# Script Parameters
ASN_FILE = "ip2asn-v4-u32.tsv.gz"
# p_travel hyperparamters
P_TRAVEL_ALPHA = 1
P_TRAVEL_BETA = 30
# p_home hyperparamters
P_HOME_ALPHA = 3
P_HOME_BETA = 5
# Num events per user
NUM_EVENTS_PARETO_A = 1
NUM_EVENTS_PARETO_LOC = 1
NUM_EVENTS_PARETO_SCALE = 50
MAX_NUM_OF_EVENTS = 10000
# Home work proximity
HOME_WORK_DISTANCE_UNIFORM_WINDOW = 50000
# Not just pick IP from home/work network, but perhaps few others around them
HOME_WORK_LOCALITY_WINDOW_SIGMA = 10


def ip2int(ip):
    """Convert an IP string to long"""
    packed_ip = socket.inet_aton(ip)
    return struct.unpack("!I", packed_ip)[0]


def load_asn_list(file_name=ASN_FILE):
    """Load and return Autonomous Systems and corresponding IP Ranges."""
    asn_list = []
    with gz.open(file_name, 'r') as f:
        for ln in f:
            tks = ln.strip().split()
            cur_asn = {
                "begin": int(tks[0]),
                "end": int(tks[1]),
                "asn": tks[2],
                "country": tks[3]
            }
            asn_list.append(cur_asn)

    return asn_list


# Load ASN list into memory
global asn_list
asn_list = load_asn_list()
print("Loaded ASN List: {} ASNs.".format(len(asn_list)))


def int2ip(n):
    """Convert an long to IP string."""
    packet_ip = struct.pack("!I", n)
    return socket.inet_ntoa(packet_ip)


def draw_ip_from_asn(asn):
    """Draw an IP address from given ASN uniform at random."""
    ip_address_int = np.random.randint(low=asn["begin"], high=asn["end"] + 1)
    return int2ip(ip_address_int)


def draw_ip():
    """Draw a random IP address from random ASN all uniform at random."""
    asn = np.random.randint(len(asn_list))
    return draw_ip_from_asn(asn_list[asn])


def draw_user_ip(home_asn, work_asn, p_travel, p_home):
    """Draw IP address from user's distributed defined by input parameters.

    When drawing an IP address for a login event, we first draw whether a user
        is 'traveling' or not. If they are traveling, we assign them a
        random ASN to connect to.

    If they are not traveling, we then draw whether or not the user is at home
        or at work that day. We assume the user travels within a viscinity of
        their home/work. Thus, we draw an IP address from within a radius around
        their home/work radius.

    Once we have the ASN a user is using for this access, we uniformly sample
        from the ASN's IP range for the assigned IP address.

    :param home_asn: (int) the ASN idx corresponding to the user's home.
    :param work_asn: (int) the ASN idx corresponding to the user's work.
    :param p_travel: (float) the probability that the user is traveling.
    :param p_home: (float) the probability that the user is at home versus work.
    :return (string) an IPv4 address in dot-notation.
    """
    # If user is traveling, pick a random ASN
    if np.random.rand() < p_travel:
        cur_asn = np.random.randint(len(asn_list))
    else:
        # User is at home or at work
        home_or_work = home_asn if np.random.rand() < p_home else work_asn

        # Assume user travels locally around work or home
        cur_asn = np.random.normal(
            loc=home_or_work,
            scale=HOME_WORK_LOCALITY_WINDOW_SIGMA)
        cur_asn = int(cur_asn) % len(asn_list)

    cur_ip = draw_ip_from_asn(asn_list[cur_asn])
    return cur_ip


def generate_user_asns(num_asn, home_work_distance_uniform_window=HOME_WORK_DISTANCE_UNIFORM_WINDOW):
    """Generate home and work ASN ids for a user.

    We assume each user to be associated with two different ASNs:
        - one associated with their 'home' network and
        - one associated with their 'work' network.

    :param num_asn: (int) the number of ASNs to draw from
    :param home_work_distance_uniform_window: (int) the max distance between
        an individual's home and work
    :return (tuple[int]) the user's home and work ASN idx
    """
    home = np.random.randint(num_asn)

    work = home
    while work == home:
        work_low = home - home_work_distance_uniform_window
        work_high = home + home_work_distance_uniform_window
        work = np.random.randint(low=work_low, high=work_high)
        work = work % num_asn

    return home, work


local = get_localzone()


class switch(object):
    def __init__(self, value):
        self.value = value
        self.fall = False

    def __iter__(self):
        """Return the match method once, then stop"""
        yield self.match
        raise StopIteration

    def match(self, *args):
        """Indicate whether or not to enter a case suite"""
        if self.fall or not args:
            return True
        elif self.value in args:  # changed for v1.5, see below
            self.fall = True
            return True
        else:
            return False


parser = argparse.ArgumentParser(__file__, description="Fake Apache Log Generator")
parser.add_argument("--output", "-o", dest='output_type', help="Write to a Log file, a gzip file or to STDOUT",
                    choices=['LOG', 'GZ', 'CONSOLE'])
parser.add_argument("--log-format", "-l", dest='log_format', help="Log format, Common or Extended Log Format",
                    choices=['CLF', 'ELF'], default="ELF")
parser.add_argument("--num", "-n", dest='num_lines', help="Number of lines to generate (0 for infinite)", type=int,
                    default=1)
parser.add_argument("--prefix", "-p", dest='file_prefix', help="Prefix the output file name", type=str)
parser.add_argument("--sleep", "-s", help="Sleep this long between lines (in seconds)", default=0.0, type=float)
parser.add_argument("--include-login", "-i", dest='include_login', help="Choose whether to include user names",
                    choices=['TRUE', 'FALSE'], default="FALSE")

args = parser.parse_args()

log_lines = args.num_lines
file_prefix = args.file_prefix
output_type = args.output_type
log_format = args.log_format
include_login = args.include_login

faker = Faker()

timestr = time.strftime("%Y%m%d-%H%M%S")
otime = datetime.datetime.now()

outFileName = 'access_log_' + timestr + '.log' if not file_prefix else file_prefix + '_access_log_' + timestr + '.log'

for case in switch(output_type):
    if case('LOG'):
        f = open(outFileName, 'w')
        break
    if case('GZ'):
        f = gzip.open(outFileName + '.gz', 'w')
        break
    if case('CONSOLE'): pass
    if case():
        f = sys.stdout

response = ["200", "404", "500", "301"]

verb = ["GET", "POST", "DELETE", "PUT"]

resourcesWL = ["/list", "/wp-content", "/wp-admin", "/explore", "/search/tag/list", "/app/main/posts",
               "/posts/posts/explore", "/apps/cart.jsp?appID=", "/about-us", "/support", "/catalyst", "/dashboard",
               "/contact-us"]

resourcesL = ["/list", "/wp-content", "/wp-admin", "/explore", "/search/tag/list", "/app/main/posts",
              "/posts/posts/explore", "/apps/cart.jsp?appID=", "/about-us", "/support", "/catalyst", "/dashboard",
              "/contact-us", "/login_success"]

users = ["Elise", "Matthew", "Milton", "Samantha", "Kate", "Natalie", "Crystal", "Thea", "Keith", "Ian", "Lance",
         "Marcus"]

ualist = [faker.firefox, faker.chrome, faker.safari, faker.internet_explorer, faker.opera]

# Select an ASN for the user's home and work network
home, work = generate_user_asns(len(asn_list))

# Sample how active the user is based on a Pareto distribution
num_events = int(
    NUM_EVENTS_PARETO_SCALE *
    (np.random.pareto(NUM_EVENTS_PARETO_A) + NUM_EVENTS_PARETO_LOC)
)
num_events = min(log_lines, num_events)

# Sample traveling probability for this user
p_travel = np.random.beta(P_TRAVEL_ALPHA, P_TRAVEL_BETA)

# Sample staying home probability for this user.
# If not travelling, user is either at home or work
p_home = np.random.beta(P_HOME_ALPHA, P_HOME_BETA)

flag = True
while (flag):
    if args.sleep:
        increment = datetime.timedelta(seconds=args.sleep)
    else:
        increment = datetime.timedelta(seconds=random.randint(30, 300))
    otime += increment

    ip = draw_user_ip(home, work, p_travel, p_home)
    dt = otime.strftime('%d/%b/%Y:%H:%M:%S')
    tz = datetime.datetime.now(local).strftime('%z')

    if include_login == "FALSE":
        uri = random.choice(resourcesWL)
        if uri.find("apps") > 0:
            uri += str(random.randint(1000, 10000))
        vrb = numpy.random.choice(verb, p=[0.6, 0.1, 0.1, 0.2])
    elif include_login == "TRUE":
        user = random.choice(users)
        uri = random.choice(resourcesL)
        if uri.find("apps") > 0:
            uri += str(random.randint(1000, 10000))
        if uri == "/login_success":
            vrb = "GET"
        else:
            vrb = numpy.random.choice(verb, p=[0.6, 0.1, 0.1, 0.2])

    resp = numpy.random.choice(response, p=[0.9, 0.04, 0.02, 0.04])
    byt = int(random.gauss(5000, 50))
    referer = faker.uri()
    useragent = numpy.random.choice(ualist, p=[0.5, 0.3, 0.1, 0.05, 0.05])()
    if log_format == "CLF" and include_login == "FALSE":
        f.write('%s - - [%s %s] "%s %s HTTP/1.0" %s %s\n' % (ip, dt, tz, vrb, uri, resp, byt))
    elif log_format == "ELF" and include_login == "FALSE":
        f.write(
            '%s - - [%s %s] "%s %s HTTP/1.0" %s %s "%s" "%s"\n' % (ip, dt, tz, vrb, uri, resp, byt, referer, useragent))
    elif log_format == "CLF" and include_login == "TRUE":
        f.write('%s - %s [%s %s] "%s %s HTTP/1.0" %s %s\n' % (ip, user, dt, tz, vrb, uri, resp, byt))
    elif log_format == "ELF" and include_login == "TRUE":
        f.write('%s - %s [%s %s] "%s %s HTTP/1.0" %s %s "%s" "%s"\n' % (
            ip, user, dt, tz, vrb, uri, resp, byt, referer, useragent))
    f.flush()

    log_lines = log_lines - 1
    flag = False if log_lines == 0 else True
    if args.sleep:
        time.sleep(args.sleep)
