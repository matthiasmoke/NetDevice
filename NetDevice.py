import socket
import subprocess
import multiprocessing

HOST_UNREACHABLE_GER = "Zielhost nicht erreichbar"


def own_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()

    return ip


def ping_host(address):

    resp = subprocess.Popen(("ping -n 1 %s" % address), stdout=subprocess.PIPE)
    out = resp.communicate()[0]

    if HOST_UNREACHABLE_GER not in str(out):
        return address


def ping_ip_range(start, end):
    ip_parts = str(own_ip()).split('.')
    ips = []

    for i in range(start, end):
        curr_add = "%s.%s.%s.%d" % (ip_parts[0], ip_parts[1], ip_parts[2], i)
        ips.append(curr_add)

    num_threads = 2 * multiprocessing.cpu_count()
    pool = multiprocessing.Pool(num_threads)

    print("processing...")
    reachable_hosts = pool.map(ping_host, ips)
    pool.close()
    pool.join()
    print("Pool closed")

    for a in reachable_hosts:
        print("%s : Host reachable" % a)


if __name__ == '__main__':
    ping_ip_range(0, 150)


