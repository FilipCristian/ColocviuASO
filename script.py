from scapy.all import ARP, Ether, srp


def scan_network(ip_range):
    """
    Scanează rețeaua pentru dispozitive active.

    Args:
        ip_range (str): Intervalul de adrese IP, ex: "192.168.1.0/24".

    Returns:
        list: O listă cu IP-urile dispozitivelor active.
    """
    # Creăm un pachet ARP pentru a identifica dispozitivele din rețea
    arp_request = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request

    # Trimitem pachetul și primim răspunsurile
    result = srp(packet, timeout=2, verbose=0)[0]

    # Extragem IP-urile dispozitivelor active
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices


if __name__ == "__main__":
    # Setează intervalul de scanare, de exemplu "192.168.1.0/24"
    ip_range = input("Introdu intervalul IP al VLAN-ului (ex: 192.168.1.0/24): ")
    print(f"Scanare în curs pentru {ip_range}...")

    # Scanează rețeaua
    active_devices = scan_network(ip_range)

    # Afișează rezultatele
    if active_devices:
        print("\nDispozitive active găsite:")
        for device in active_devices:
            print(f"IP: {device['ip']}, MAC: {device['mac']}")
    else:
        print("\nNu au fost găsite dispozitive active.")
