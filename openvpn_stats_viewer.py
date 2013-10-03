#!/usr/bin/env python

"""
This file parses the OpenVPN stats file (make sure "stats <file>" is 
set in the OpenVPN server config) and displays the results.

You can also search through records by passing "!" as the argument 
instead of the filename.

Data is stored in SQLite for historical purposes.

If SQLite 3 or 2 is not found, no data is logged into the database, 
which also means records are not kept.

It is advisable to have this run via cron every minute, which is the 
same frequency that the stats file is updated.

Usage: ./openvpn_stats_viewer.py <OpenVPN stats file> [display pretty]
:: OpenVPN stats file - The file specified in OpenVPN that logs 
                        connection statistics every minute
:: display pretty - By default 0.  Pass 1 for this argument to display 
                    results in a pretty tree format, otherwise plain
                    single-line text string.
"""

import sys

# We need the stats file in order to make this happen, otherwise exit out
try:
    openvpn_stats = sys.argv[1]
except IndexError:
    print "Usage: %s <path to OpenVPN stats file> [display pretty]" % (sys.argv[0])
    sys.exit(1)

# We assume SQLite is available by this point (some still use a very old version)
sqlite = True

# If its Python 2.6+ SQLite3 should be included
try:
    import sqlite3 as dbdriver
except ImportError:
    try:
        import sqlite2 as dbdriver
    except ImportError:
        sqlite = False

if sqlite:
    db = dbdriver.connect("osv.db")
else:
    db = None
    
# Simple method that takes bytes and converts it to human-readable format
def bytesfmt(bt):
    tag = ["B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"]
    counter = 0
    
    # So we don't manipulate the data itself, only a copy of it
    amt = bt
    
    # Should be 1000 but 1024 is more accurate
    while amt > 1024:
        # To ensure we get a decimal number in the end we divide by a decimal
        amt /= 1024.0
        counter += 1
    
    # Returns string formatted as <amount> <type> i.e.: 32.0 MB or 184.89 GB
    return "%s %s" % (str(round(amt, 2)), tag[counter])

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

# Wrapper function to select data from a query, as SQLite is a pain in the ass for such things
def select(cursor, query, kwargs):
    try:
        return cursor.execute(query, kwargs).fetchone()
    except TypeError:
        return None
    
import re

# Used to pull stats from the stats file
stats = re.compile('^([a-zA-Z0-9_-]+),(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d{1,5},(\d{1,}),(\d{1,}),(.*)$', re.I)

# Manages the virtual IP routing table (mainly used to fetch the virtual IP of the user)
ipr = re.compile('^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),([a-zA-Z0-9_-]+),[^,]+,(.*)$')
    
def stats_parser():
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
    lines = [line.strip() for line in open(openvpn_stats)]
    
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
        else:
            # Check to see if we're at a IP pool line instead
            d = ipr.match(line)
            
            if d:
                g = d.groups()
                
                # Store the virtual IP information
                results[g[1]]["virt_ip"] = g[0]
                results[g[1]]["last_vip"] = date2epoch(g[2])
                results[g[1]]["last_vip_str"] = g[2]
        
    return results

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
    
def update_records(cur, report):
    # Loop through each CN/connected account found
    for cn,data in report.iteritems():
        if db != None:
            # Check if the CN is already known in our system
            uid = select(cur, "select id from users where cn=:cn", {"cn" : cn})[0]
            
            # If not, make it happen
            if uid == None:
                uid = cur.execute("insert into users(cn) values(?);", (cn,)).lastrowid
                
                # Required after every modification to the database
                db.commit()
            
            # Similar to getting the UID
            vipid = select(cur, "select id from vip where ip=:ip and last_ref=:lr and uid=:uid", {"ip" : data['virt_ip'], "lr" : data['last_vip'], "uid" : uid})[0]
            
            if vipid == None:
                vipid = cur.execute("insert into vip(ip,last_ref,uid) values(?,?,?)", (data['virt_ip'], data['last_vip'], uid,)).lastrowid
                db.commit()
                
            ripid = select(cur, "select id from rip where ip=:ip and connsince=:conn and uid=:uid", {"ip" : data['real_ip'], "conn" : data['conn_since'], "uid" : uid})[0]
            
            if ripid == None:
                ripid = cur.execute("insert into rip(ip,connsince,uid) values(?,?,?)", (data["real_ip"], data["conn_since"], uid,)).lastrowid
                db.commit()
            
            # There's two ways to handle the stats query:
            # Assume you can update, and if an exception is thrown do an insert
            # Check for a stats ID, if it don't exist insert it otherwise update it
            #
            # The 2nd route seemed more logical?  Plus, less annoying to me.
            sid = select(cur, "select id from stats where uid=:uid and vipid=:vip and ripid=:rip", {"uid" : uid, "vip" : vipid, "rip" : ripid})[0]
            
            if sid == None:
                sid = cur.execute("insert into stats(uid,vipid,ripid,brx,btx) values(?,?,?,?,?)", (uid, vipid, ripid, data["bytes_rx"], data["bytes_tx"],)).lastrowid
            else:
                cur.execute("update stats set brx=?,btx=? where id=?", (data["bytes_rx"], data["bytes_tx"], sid,))
            
        # Prints out the data for each user
        display_record(cn, data["bytes_tx"], data["bytes_rx"], data["virt_ip"], data["last_vip_str"], data["real_ip"], data["conn_since_str"])
    
    if db != None:
        cur.close()
        db.close()
        
# Proper but in theory not required
if __name__ == "__main__":
    cur = None
    
    if db != None:
        # Get a reference to the db's cursor (i.e.: handle to perform tasks)
        cur = db.cursor()
        
    if openvpn_stats == "!":
        if db != None:
            c = ""
            
            users = {}
            
            cns = cur.execute("select * from users").fetchall()
            
            for entry in cns:
                users["%d" % entry[0]] = entry[1]
                
                print "[%d] %s" % (entry[0], entry[1])
            
            uid = None
            
            while users.get(uid) == None:
                uid = raw_input("> Enter the user you would like to view statistics for: ")
            
            for stat in cur.execute("select vipid,ripid,brx,btx from stats where uid=?", (uid,)):
                vip = select(cur, "select ip,last_ref from vip where id=:id", {'id' : stat[0]})
                rip = select(cur, "select ip,connsince from rip where id=:id", {'id' : stat[1]})
                
                display_record(
                    users[uid], 
                    stat[3], 
                    stat[2], 
                    vip[0], 
                    time.strftime("%c", time.gmtime(vip[1])), 
                    rip[0], 
                    time.strftime("%c", time.gmtime(rip[1]))
                )
    else:
        report = stats_parser()
        update_records(cur, report)
