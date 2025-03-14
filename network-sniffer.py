import socket
import struct
import sys

def parse_ipv4_header(data):
    """Gelen ham paketin IPv4 başlığını ayrıştırır."""
    #ilk 20 bayt alındı
    ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
    
    version_ihl = ip_header[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0xF) * 4
    ttl = ip_header[5]
    protocol = ip_header[6]
    
    # format değiştirilidi
    src_ip = socket.inet_ntoa(ip_header[8])
    dst_ip = socket.inet_ntoa(ip_header[9])
    
    return version, ihl, ttl, protocol, src_ip, dst_ip, data[ihl:]

def main():
    # Hem Windows ve hem de linux için raw soket oluşturuldu 
    try:
        if sys.platform == "win32":
           
            conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            hostname = socket.gethostname()
            target_ip = socket.gethostbyname(hostname)
            conn.bind((target_ip, 0))
            conn.setsockopt(socket.IPPROTO_IP, socket.RCVALL, socket.RCVALL_ON)
        else:
            
            conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except PermissionError:
        print("[!] Hata: Bu betiği çalıştırmak için YÖNETİCİ (Admin/Sudo) yetkisi gerekiyor!")
        sys.exit()

    print("[+] Ağ Trafiği Dinleniyor... (Durdurmak için Ctrl+C)\n")
    print(f"{'Protokol':<10} | {'Kaynak IP':<15} -> {'Hedef IP':<15} | TTL")
    print("-" * 60)

    try:
        while True:
            
            raw_data, addr = conn.recvfrom(65535)
            
            # Paketi ayrıştır
            version, ihl, ttl, protocol, src_ip, dst_ip, payload = parse_ipv4_header(raw_data)
            
            # Protokol ismini belirle (6: TCP, 17: UDP, 1: ICMP)
            proto_name = "Diğer"
            if protocol == 6:
                proto_name = "TCP"
            elif protocol == 17:
                proto_name = "UDP"
            elif protocol == 1:
                proto_name = "ICMP"
                
          
            print(f"{proto_name:<10} | {src_ip:<15} -> {dst_ip:<15} | {ttl}")
            
    except KeyboardInterrupt:
        print("\n[-] Sniffer kullanıcı tarafından durduruldu.")
        if sys.platform == "win32":
            conn.setsockopt(socket.IPPROTO_IP, socket.RCVALL, socket.RCVALL_OFF)

if __name__ == "__main__":
    main()