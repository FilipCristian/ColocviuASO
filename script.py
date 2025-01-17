from scapy.all import ARP, Ether, srp
import socket
import struct
import fcntl
import os

def get_local_network():
    """
    Detectează automat intervalul IP al rețelei locale (LAN).

    Returns:
        str: Intervalul IP, ex: "192.168.1.0/24".
    """
    # Deschide un socket pentru a obține informații despre rețea
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        interfaces = os.listdir('/sys/class/net/')  # Listăm interfețele de rețea
        for iface in interfaces:
            try:
                # Obține adresa IP a interfeței
                iface_ip = socket.inet_ntoa(
                    fcntl.ioctl(
                        s.fileno(),
                        0x8915,  # SIOCGIFADDR
                        struct.pack('256s', iface[:15].encode('utf-8'))
                    )[20:24]
                )

                # Obține masca de rețea
                iface_mask = socket.inet_ntoa(
                    fcntl.ioctl(
                        s.fileno(),
                        0x891b,  # SIOCGIFNETMASK
                        struct.pack('256s', iface[:15].encode('utf-8'))
                    )[20:24]
                )

                # Calculează prefixul rețelei
                ip_as_int = struct.unpack('!I', socket.inet_aton(iface_ip))[0]
                mask_as_int = struct.unpack('!I', socket.inet_aton(iface_mask))[0]
                network_as_int = ip_as_int & mask_as_int

                # Transformă în format CIDR
                network_ip = socket.inet_ntoa(struct.pack('!I', network_as_int))
                prefix_length = bin(mask_as_int).count('1')
                return f"{network_ip}/{prefix_length}"
            except Exception:
                # Ignoră interfețele fără IP (ex: lo, interfețe neconfigurate)
                continue
    return None

def scan_network(ip_range):
    """
    Scanează rețeaua pentru dispozitive active.

    Args:
        ip_range (str): Intervalul de adrese IP, ex: "192.168.1.0/24".

    Returns:
        list: O listă cu IP-urile și MAC-urile dispozitivelor active.
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
    # Detectăm intervalul IP al rețelei locale
    ip_range = get_local_network()

    if not ip_range:
        print("Nu s-a putut detecta rețeaua locală. Asigură-te că interfața de rețea este configurată corect.")
    else:
        print(f"Scanare în curs pentru rețeaua {ip_range}...")

        # Scanează rețeaua
        active_devices = scan_network(ip_range)

        # Afișează rezultatele
        if active_devices:
            print("\nDispozitive active găsite:")
            for device in active_devices:
                print(f"IP: {device['ip']}, MAC: {device['mac']}")
        else:
            print("\nNu au fost găsite dispozitive active.")