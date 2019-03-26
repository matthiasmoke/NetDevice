import socket
import subprocess
import multiprocessing
import getopt
import sys
import platform

PING_COMM_UNIX = ["ping", "-b", "-c 1"]
PING_COMM_WIN = ["ping", "-n 1"]
HOST_UNREACHABLE_GER = "Zielhost nicht erreichbar"
HOST_UNREACHABLE_ENG = "Destination Host Unreachable"
start_addr = 1
end_addr = 255
reachable_hosts = []


def print_banner():
    print("<=================== NetDevice ===================>")


def usage():
    print("List all hosts connected to your network")
    print("Usage: NetDevice.py [flags]")
    print("-s start_address")
    print("-e end_address")
    print("")


# gets ip address of executing host
def own_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()

    return ip


# Returns os specific ping command with address inserted
def get_ping_command(address):
    global PING_COMM_UNIX
    global PING_COMM_WIN
    os = platform.system()

    command = []

    if "Linux" in os:
        command += PING_COMM_UNIX
    else:
        command += PING_COMM_WIN

    command.append(str(address))
    return command


# pings a host
def ping_host(address):
    command = get_ping_command(address)
    resp = subprocess.Popen(command, stdout=subprocess.PIPE)
    out = resp.communicate()[0]

    if HOST_UNREACHABLE_ENG not in str(out):
        return address


# gets the hostname of a host
def get_host_name(host):
    try:
        name = socket.gethostbyaddr(host)[0]
        return name
    except socket.error as err:
        return str(err)


# generates ip addresses for the given range
def generate_ips_to_ping(start_index, end_index):
    ips = []

    if (start_index > -1) and (end_index > start_index):
        ip_parts = str(own_ip()).split('.')

        for i in range(start_index, end_index):
            curr_add = "%s.%s.%s.%d" % (ip_parts[0], ip_parts[1], ip_parts[2], i)
            ips.append(curr_add)

    return ips


# pings a range of ip addresses
def ping_ip_range(start, end):
    ips = generate_ips_to_ping(int(start), int(end))

    if len(ips) > 0:
        num_threads = 2 * multiprocessing.cpu_count()
        pool = multiprocessing.Pool(num_threads)

        print("processing...")
        pinged_hosts = pool.map(ping_host, ips)
        pool.close()
        pool.join()
        print("Processing Finished")
        check_device_names(pinged_hosts)

    else:
        print("Error no addresses to ping!")


def check_device_names(pinged_ips):
    for ip in pinged_ips:
        if ip is not None:
            reachable_hosts.append(ip)

    print("IPv4 Address \t\t\t Status \t\t\t\t Hostname")
    if len(reachable_hosts) > 0:
        for a in reachable_hosts:
            device_name = get_host_name(a)
            print("%s \t\t\t Host reachable \t\t\t %s" % (a, device_name))
            print("")


def main():
    global start_addr
    global end_addr

    if not len(sys.argv[1:]):
        usage()

    try:
        opts, args = getopt.getopt(sys.argv[1:], "s:e:")
    except getopt.GetoptError as err:
        print(err)
        usage()

    for o, a in opts:
        if o in "-s":
            start_addr = a
        elif o in "-e":
            end_addr = a
        else:
            print("Error invalid input!")
            usage()

    ping_ip_range(start_addr, end_addr)


if __name__ == '__main__':
    print_banner()
    main()


