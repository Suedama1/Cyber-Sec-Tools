# Imports
from tabulate import tabulate
import nmap
import threading

# NMAP Scan Function
def nmap_scan():
    """Uses TCP Syn and UDP scan for the top 10 ports of localhost and scanme.nmap.org with OS detection, version detection, script scanning and traceroute. Prints the results in a table using tabulate.

    Returns:
        dict: Returns a dictionary of the scan results
    """

    # Create a PortScanner
    nm = nmap.PortScanner()

    # Create a list of headers for the table
    headers = ["Host", "Hostname", "Protocol", "Port ID",
               "State", "Product", "Extra Info", "Reason", "CPE"]

    # Create a list of hosts to scan
    hosts = ["localhost", "scanme.nmap.org"]

    # Create a list to store the scan results
    scan_results = []

    # Create a dictionary to store the scan results
    result = {}

    # Scan the hosts
    def scan_host(host):
        result = nm.scan(hosts=host, arguments="--top-ports 10 -A -sT -sU")
        for host in nm.all_hosts():
            for protocol in ["tcp", "udp"]:
                for port in nm[host][protocol].keys():
                    scan_results.append([host, nm[host].hostname(), protocol, port, nm[host][protocol][port]["state"], nm[host][protocol][port]
                                        ["product"], nm[host][protocol][port]["extrainfo"], nm[host][protocol][port]["reason"], nm[host][protocol][port]["cpe"]])
        # Return the scan results
        return result

    # Create two threads to scan the hosts
    thread1 = threading.Thread(target=scan_host, args=(hosts[0],))
    thread2 = threading.Thread(target=scan_host, args=(hosts[1],))
    # Start the threads
    thread1.start()
    thread2.start()
    # Wait for the threads to finish before continuing
    thread1.join()
    thread2.join()

    print(f"Type of nmScan: {type(nm)}")
    print(f"Scanning Ports: {', '.join(hosts)}")
    print(f"Type of results: {type(result)}")

    # Sort the scan results
    scan_results = sorted(scan_results, key=lambda x: x[1])

    # Print the scan results in a table using tabulate
    print(tabulate(scan_results, headers, tablefmt="simple_grid"))
    print("NMAP Scan Completed in", nm.scanstats()["elapsed"], "seconds\n")


# Testing Script

# nmap_scan()
