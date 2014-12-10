#This is a script used to communicate with nearby firechat devices over bluetooth
#The end result is a manner to interact with blucat to generage the necessary
#   command to connect to the firechat device on the terminal

#The hope is that the code is moduar enough that it could be modified such to produce
#   the connection command for any desired application running on a specific port

#Command structure taken from http://blucat.sourceforge.net/blucat/firechat-analysis/
#This script assumes that blucat is installed (brew install blucat) 
#   and that it is on an OS X system < 10.9
#Futhermore it assumes that all bluetooth services using port 15 are firechat
#   servers. The application will allow you to select which is the desired
#   device to connect with.

import os
DEBUG = False

#input a desired port and protocol to search for
#Returns a dictionary all devices
#key => Device bluetooth address
#value => (Device name, Boolean of port present)
def scan(port,protocol):
    print "Running Scan"
    fi, fo, fe = os.popen3("blucat services")
    output = fo.read()
    devices = output.split("+")
    if len(devices) == 1:
        print "No Devices Found"
        return {}
    header = devices[0]
    devices = devices[1:]
    scan_results = {}
    for device in devices:
        info = parse_device(device, port, protocol)
        scan_results[info[0]] = (info[1], info[2])
    return scan_results


#Prints debuging statments in a standard format only if
#   The global DEBUG variable is true
def debug_print(name, statment, breaker=""):
    if DEBUG:
        print breaker
        print "{}: {}".format(name,statment)
        print breaker

#Takes in a device string from the scan function, the search port and protocol
#Returns a tuple (id (string),name (string),port present (boolean))
def parse_device(device_string, port, protocol):
    debug_print("String", device_string)
    lines = device_string.split('\n')
    header = lines[0]
    services = lines[1:]
    header_info = header.split(',')
    device_id = header_info[1]
    device_name = header_info[2]
    port15 = False
    for service in services:
        if "{}://{}:{}".format(protocol,device_id,port) in service:
            port15 = True
            break
    return (device_id,device_name,port15)

#Scans with firechat port and protocol
def scan_firechat():
    return scan(15,"btspp")

#Input -- expects devices from a scan and 
#   optionally a boolean if it should filter based on port presence
#Returns the desired device id or -1 if an exit is desired
def connect(devices, filterDisplay=True):
    if filterDisplay:
        keys = filter(lambda k: devices[k][1],devices.keys())
    else:
        keys = devices.keys()
    if len(keys) == 0:
        print "No devices present -- exiting"
        return -1
    print "Select a device from below or 0 to exit"
    print "0: Exit"
    for i,k in enumerate(keys):
        print "{}: {}".format(i + 1, devices[k][0])
    selection = raw_input("Selection: ").strip()
    try:
        number = int(selection)
        if number == 0:
            return -1
        if number < len(devices) + 1:
            return keys[number - 1]
    except:
        print
        print "Invalid input"
        print
        connect(devices,filterDisplay)
    print
    print "Invalid input"
    print
    connect(devices,filterDisplay)


#returns the connection string required 
def connect_firechat():
    bid = connect(scan_firechat())
    if not bid or bid == -1:
        print "No connection made, exiting"
        return
    constring = "blucat -url btspp://{}:15".format(bid)
    print constring
    return constring

connect_firechat()