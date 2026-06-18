import socket
def scan_port(host, port_number):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(1)
        s.connect((host, port_number))
        response = s.recv(1024)
        return "open: " + response.decode('utf-8', errors='ignore')
    except ConnectionRefusedError:
        return "closed"
    except socket.timeout:
        return "filtered"
    finally:
        s.close()

for i in range (1, 101):
    c = scan_port("scanme.nmap.org", i)
    print(c)