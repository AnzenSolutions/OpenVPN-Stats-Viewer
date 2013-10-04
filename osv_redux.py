#!/usr/bin/env python

"""
Similar to openvpn_stats_viewer.py but does not even bother with 
SQLite, uses a flatfile database storage.
"""
import sys

# We need the stats file in order to make this happen, otherwise exit out
try:
    openvpn_stats = sys.argv[1]
except IndexError:
    print "Usage: %s <path to OpenVPN stats file> [display pretty]" % (sys.argv[0])
    sys.exit(1)
    
import os

# Improved file reading
import linecache

"""
Layout:
stats/
 -- global (global stats)
 -- cn_1/ (cn_1 replaced by CN of OpenVPN user)
 -- -- <epoch> (filename is unix timestamp/epoch, inside is CSV format of session data)
"""
STATS_DIR = os.path.join(os.path.abspath("."), "stats")

# Simple check to see if path (folder) exists, if not then create it (optional)
def exists(path, make_if_not=True):
    if os.path.exists("%s/%s" % (STATS_DIR, path)) == False:
        if make_if_not:
            os.mkdir("%s/%s" % (STATS_DIR, path))
            return True
        else:
            return False
    else:
        return True

# Simple method that takes bytes and converts it to human-readable format
def bytesfmt(bt):
    tag = ["B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"]
    counter = 0
    
    # So we don't manipulate the data itself, only a copy of it
    amt = float(bt)
    
    # Should be 1000 but 1024 is more accurate
    while amt > 1024:
        # To ensure we get a decimal number in the end we divide by a decimal
        amt /= 1024.0
        counter += 1
    
    # Returns string formatted as <amount> <type> i.e.: 32.0 MB or 184.89 GB
    return "%s %s" % (str(round(amt, 2)), tag[counter])

# Essentially convert a time difference from seconds to human-readable format
def secsfmt(diff):
    # How many seconds are in each time measurement
    intervals = [1, 60, 3600, 86400, 604800, 2419200, 29030400]
    
    # Human-readable form of time measurement
    names = [
                ('second', 'seconds'),
                ('minute', 'minutes'),
                ('hour', 'hours'),
                ('day', 'days'),
                ('week', 'weeks'),
                ('month', 'months'),
                ('year', 'years')
            ]
    
    result = []
    
    # One-liner trick to get the index of our interval based on the name of the unit we want broken down into
    unit = map(lambda a: a[1], names).index('seconds')
    
    # Multiply the difference by what type of measurement we want (diff < current epoch after all)
    diff = diff * intervals[unit]
    
    # Loop through each of the stages of time in reverse order
    for i in range(len(names)-1, -1, -1):
        # Divide our difference time by the interval of time (i.e.: 3600 / 86400)
        a = diff / intervals[i]
        
        # If a is 0 > a < 1 then a = 0, this means we aren't in the correct measurement yet
        if a > 0:
            # 1 % a = modulo math; if remainder of 1/a = 0 then use singular form, otherwise 1/a = 1 so use plural
            result.append((a, names[i][1 % a]))
            
            # Modify the difference after we know that its valid
            diff -= a * intervals[i]
            
    return result

# These two are needed for date2epoch to convert a text date to epoch
import datetime
import time

# Convert text date (i.e.: Thu Oct  3 15:31:08 2013) to epoch (i.e.: 1380828668)
# since looking up data in a database is quicker with numbers than text itself
def date2epoch(date):
    # OpenVPN displays times in locale format (i.e.: Thu Oct  3 15:31:08 2013)
    # We need to convert that to a workable time object in Python
    date = datetime.datetime.strptime(date, "%c").timetuple()
    
    # Luckily Python has an easy conversion from its datetime format to epoch
    # However, Python also adds milliseconds to it (<seconds>.<ms>).  We want whole numbers.
    return int(time.mktime(date))

# Returns filename to manipulate
def cnfn(cn, date):
    return os.path.join(STATS_DIR, cn, str(date))
    
import re

# Used to pull stats from the stats file
stats = re.compile('^([a-zA-Z0-9_-]+),(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d{1,5},(\d{1,}),(\d{1,}),(.*)$', re.I)

# Manages the virtual IP routing table (mainly used to fetch the virtual IP of the user)
ipr = re.compile('^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),([a-zA-Z0-9_-]+),[^,]+,(.*)$')

def stats_parser():
    total_in = 0.0
    total_out = 0.0
    user_count = 0
    
    """
    Layout:
    "cn name" : {
        "real_ip" : ip,
        "bytes_rx" : bytes in,
        "bytes_tx" : bytes out,
        "conn_since" : last connection date,
        "virt_ip" : ip from openvpn,
        "last_vip" : last date issued virtual ip
    }
    """
    results = {}
    
    # Stores each whitestripped line from the OpenVPN stats file into a list
    try:
        lines = [line.strip() for line in open(openvpn_stats)]
    except IOError:
        print "%s does not exist or is unreadable by this script.  Aborting" % openvpn_stats
        sys.exit(1)
    
    # Place holders so we aren't redeclaring them each time
    d = None
    g = None
    
    # Loop through each line
    for line in lines:
        # Check if we're at a stats line of the user
        d = stats.match(line)
        
        # If so...
        if d:
            # Get the matches found for the line
            g = d.groups()
            
            # The CN should never be found twice, but error checking in case
            if g[0] not in results:
                results[g[0]] = {
                    'real_ip' : g[1], 
                    'bytes_rx' : int(g[2]), 
                    'bytes_tx' : int(g[3]), 
                    'conn_since' : date2epoch(g[4]),
                    'conn_since_str' : g[4]
                }
                
                total_in += int(g[2])
                total_out += int(g[3])
                user_count += 1
        else:
            # Check to see if we're at a IP pool line instead
            d = ipr.match(line)
            
            if d:
                g = d.groups()
                
                # Store the virtual IP information
                results[g[1]]["virt_ip"] = g[0]
                results[g[1]]["last_vip"] = date2epoch(g[2])
                results[g[1]]["last_vip_str"] = g[2]
    
    update_global_record(time.strftime('%c', time.gmtime(time.time()) ), total_in, total_out, user_count)
    
    return results

# Converts time difference into human readable format string
def diff2hr(since):
    now = int(time.time())
    diff = since - now
    
    return ", ".join(["%d %s" % (x[0], x[1]) for x in secsfmt(diff)])
    
"""
Displays the current statistic record.
"""
def display_record(cn, btx, brx, vip, vip_time, rip, conn):
    # Check to see if we want pretty output, default to no
    try:
        pretty = True if sys.argv[2] == "1" else False
    except IndexError:
        pretty = False
    
    # We want the time of now as well as when the connection started
    now = int(time.time())
    then = date2epoch(conn)
    
    # Get the difference between them
    diff = then - now
    
    # Pretty output the total session length regardless of 'pretty' option
    conn_life = ", ".join(["%d %s" % (x[0], x[1]) for x in secsfmt(diff)])
    
    # No pretty, display single-line text
    if pretty == False:
        print "%s: %s bytes sent, %s received (%s total) on VPN IP %s (assigned on %s) while connecting from %s (connected since %s [total session length: %s])." % (
            cn, bytesfmt(btx), bytesfmt(brx), bytesfmt(btx+brx), vip, vip_time, rip, conn, conn_life
        )
    else:
        # Tree-outline of record
        print "+ %s" % cn
        print "|+ -- Data:"
        print "|     -- In:\t\t\t%s" % bytesfmt(brx)
        print "|     -- Out:\t\t\t%s" % bytesfmt(btx)
        print "|     -- Total:\t\t\t%s" % bytesfmt(brx+btx)
        print "|+ -- VPN:"
        print "|     -- IP:\t\t\t%s" % vip
        print "|     -- Date Given:\t\t%s" % vip_time
        print "|+ -- Network:"
        print "|     -- Real IP:\t\t%s" % rip
        print "|     -- Date Connected:\t%s" % conn
        print "|     -- Total Session Time:\t%s" % conn_life

def update_records(report):
    # Loop through each CN/connected account found
    for cn,data in report.iteritems():
        # Make sure CN has a folder available, otherwise create it
        exists(cn)
        
        with open(cnfn(cn, data["conn_since"]), "wt") as fp:
            fp.write("virtual ip,virtual ip given,remote ip,bytes in,bytes out,bytes total,session time,session length\n")
            fp.write("%s,%s,%s,%d,%d,%d,%s,%s" % (
                                                    data["virt_ip"],
                                                    data["last_vip_str"],
                                                    data["real_ip"],
                                                    data["bytes_rx"],
                                                    data["bytes_tx"],
                                                    data["bytes_rx"] + data["bytes_tx"],
                                                    data["conn_since_str"],
                                                    diff2hr(data["conn_since"])
                                                ))
                                                
        # Prints out the data for each user
        display_record(cn, data["bytes_tx"], data["bytes_rx"], data["virt_ip"], data["last_vip_str"], data["real_ip"], data["conn_since_str"])

def parse_global_record():
    record = linecache.getline("%s/global" % (STATS_DIR), 2).strip().split(",")
    
    return record

"""
Displays the global records for OpenVPN
"""
def display_global_record(date, bi, bit, bo, bot, bt, btt, users, users_dict={}):
    # Check to see if we want pretty output, default to no
    try:
        pretty = True if sys.argv[2] == "1" else False
    except IndexError:
        pretty = False
    
    # No pretty, display single-line text
    if pretty == False:
        print "%s: %s bytes sent (%s), %s bytes received (%s), total of %s bytes (%s).  Total users connected: %s" % (
                                                                                                                        date,
                                                                                                                        bo,
                                                                                                                        bot,
                                                                                                                        bi,
                                                                                                                        bit,
                                                                                                                        bt,
                                                                                                                        btt,
                                                                                                                        users)
                                                                                                                        
    else:
        # Tree-outline of record
        print "+ %s" % date
        print "|+ -- Data:"
        print "|     -- In:\t\t\t%s bytes (%s)" % (bi, bit)
        print "|     -- Out:\t\t\t%s bytes (%s)" % (bo, bot)
        print "|     -- Total:\t\t\t%s bytes (%s)" % (bt, btt)
        print "|+ -- Users:"
        print "|     -- Total:\t\t\t%s" % (users)
        
        for _,name in users_dict.iteritems():
            print "|     -- User (CN):\t\t%s" % (name)
        
def update_global_record(date, bytesin, bytesout, users):
    with open("%s/global" % STATS_DIR, "wt") as fp:
        fp.write("date,bytes in,bytes in human,bytes out, bytes out human,bytes total,bytes total human,users\n")
        fp.write("%s,%d,%s,%d,%s,%d,%s,%d" % (
                                                date,
                                                bytesin,
                                                bytesfmt(bytesin),
                                                bytesout,
                                                bytesfmt(bytesout),
                                                bytesin+bytesout,
                                                bytesfmt(bytesin+bytesout),
                                                users
                                            ))

def parse_record(cn, date):
    record = linecache.getline("%s/%s/%s" % (STATS_DIR, cn, date), 2).strip().split(",")
    
    return (cn, record[4], record[3], record[0], record[1], record[2], record[6])

# Proper but in theory not required
if __name__ == "__main__":
    # If the stats directory doesn't exist, make it
    if os.path.exists(STATS_DIR) == False:
        os.mkdir(STATS_DIR)
    
    # Browse through the records
    if openvpn_stats == "!":
        users = {}
        index = 1
        
        for user in os.walk(STATS_DIR).next()[1]:
            if os.path.isdir("%s/%s" % (STATS_DIR, user)):
                users["%d" % index] = os.path.join(user)
                print "[%d] %s" % (index, os.path.join(user))
                index += 1
        
        if not users:
            print "Could not find any profiles in %s.  Aborting." % STATS_DIR
            sys.exit(1)
        
        users["0"] = "G"
        print "\n[0] Global Statistics"
        
        uid = None
        
        while users.get(uid) == None:
            uid = raw_input("> Enter the ID for the user you would like to view statistics for: ")
        
        dates = {}
        index = 1
        
        if uid != "0":
            for date in os.walk("%s/%s" % (STATS_DIR, users[uid])).next()[2]:
                dates["%d" % index] = date
                print "[%d] %s" % (index, time.strftime('%c', time.gmtime( float(date) )))
                index += 1
            
            if not dates:
                print "Could not find any data to parse in %s/%s.  Aborting." % (STATS_DIR, users[uid])
                sys.exit(1)
            
            date = None
            
            while dates.get(date) == None:
                date = raw_input("> Enter the ID for the date you would like to view: ")
            
            display_record(*parse_record(users[uid], dates[date]))
        else:
            users.pop("0")
            display_global_record(*parse_global_record(), users_dict=users)
    else:
        print "Stats Last Updated:",linecache.getline(openvpn_stats, 2).strip().split(",")[1],"\n"
        
        report = stats_parser()
        update_records(report)
    
    sys.exit(0)
