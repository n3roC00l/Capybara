import argparse
import os
from scapy.all import *
import socket
import ipaddress


# Função para validar IPs
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False



#logo do programa
def show_logo():
    capybara_art = """

⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣶⠛⢻⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣄⣼⡦⠴⠒⠒⠶⣤⣀⠀⣾⢧⡋⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣀⡤⠶⠚⠉⠁⠀⠀⠀⠀⠀⠀⠀⠈⣿⣷⣋⡿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⡤⠖⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣶⣶⣦⠈⠻⠻⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢀⡠⠞⠃⠀⠀⠀⠀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⡇⠀⡀⠙⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⡞⠁⠀⠀⠀⠀⢀⡴⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠛⠛⠟⠀⠀⠙⠀⠸⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⡿⣤⡀⠀⢀⡴⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠘⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⡇⠀⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠳⣄⠀⠀⡀⠀⠈⢳⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢹⡀⠀⢸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢈⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠙⢦⡀⠀⠙⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠘⣇⠀⠘⣆⠀⠀⠀⠀⠀⠀⠀⢀⣴⠞⠀⠹⠆⠀⠀⠈⢳⠀⠀⠀⠀⠀⠁⠀⠀⠀⠉⠳⠤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠘⢦⣤⣹⣄⣀⣀⣀⣠⣤⠴⠊⠀⠀⠀⠀⠀⠀⠀⠀⠈⠃⠀⠀⠀⠀⠲⣤⡀⠀⠀⠀⠀⠈⠙⠲⢤⡀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠙⠲⢤⡀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⢰⡄⠀⠀⠀⠀⠁⠀⠀⠀⠀⠈⠑⠢⣄⡙⠷⣄⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠈⡇⠀⠀⡀⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠈⠀⠀⠈⠳⣄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣻⠀⠀⢳⠀⠀⠀⠘⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠢⡀⠀⠑⢄⠙⢆⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠈⠂⠀⠀⠀⠀⢠⣿⠀⠀⠀⠀⠀⠀⢀⣤⠴⠚⠃⠀⠀⠘⢢⡀⠀⠀⠉⠀⠀⠈⠧⠘⢧⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢈⡇⠀⠀⠀⠀⠀⠀⠀⠘⠋⠀⠀⠀⠀⠀⣴⠋⠀⠀⠀⠀⠀⠀⠀⠀⠙⢦⡀⠀⢦⠀⠀⠀⠀⠈⣇⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢹⠀⢰⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠈⢳⡀⠀⠀⠀⠸⡆
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠘⠷⠀⠀⠀⠀⠀⢠⠀⠀⠀⠠⡏⠀⠀⢠⠀⠀⠀⠀⠀⢠⡀⠀⠀⠀⡀⠀⠀⠷⠀⢸⡄⠀⢳
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⡇⠀⠀⠀⠀⡄⠀⠀⢸⡇⠀⠀⢸⣧⠀⠀⠈⢣⠀⠀⠀⠀⢀⣳⠀⠀⠀⢹⡄⠀⠀⠀⠈⠁⠀⢸
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⡄⠀⠀⠀⣷⠀⠀⠘⠃⠀⠀⢀⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠁⠀⠀⠸⢳⡀⢀⡀⠀⢠⠀⢸
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣄⠀⠀⢻⡇⠀⠀⠀⠀⠀⣸⠉⢧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠀⠐⣧⠀⠸⠀⡼
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣦⡀⣸⣷⠀⠀⠀⠀⠀⡇⠀⠈⠳⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⢸⠇
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣖⡿⣿⡟⣻⣿⣷⡄⠀⠀⢾⣁⡀⠀⠀⣨⡷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠏⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠿⠷⠿⣿⣥⠟⠀⣹⣾⠦⡿⡾⠇⠉⢻⣟⣀⣀⡬⠟⠲⢤⣀⣀⣀⣀⠀⠀⠀⠀⢀⣀⡴⠋⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠋⠁⢰⣿⡽⢛⡧⢠⡇⠀⠀⠀⠉⠉⠙⠓⠒⠒⠚⠉⠁⠀⠉⠑⠒⠒⠉⠉⠁⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠛⠒⣿⣤⠞⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀

    """
    print(capybara_art)
    print("Script de Redes - Spoofing, Port Scan e TCP")
    print("-" * 50)



# Função para spoofing
def spoofing():

    ip_falso = input("[*] Informe o IP falso (spoofed IP): ")
    ip_destino = input("[*] Informe o IP de destino para spoofing: ")


    # Validar IPs
    if not (is_valid_ip(ip_falso) and is_valid_ip(ip_destino)):
        print("[!] Um ou mais endereços IP fornecidos são inválidos.")
        return

    print(f"[*] Iniciando Spoofing com o IP falso {ip_falso} para o IP de destino {ip_destino}...")

    # Envio de pacotes ICMP (ping) com o IP falso
    packet = IP(src=ip_falso, dst=ip_destino) / ICMP()
    send(packet)
    print(f"[*] Pacote ICMP spoofado enviado de {ip_falso} para {ip_destino}")



# Função para port scan
def port_scan(ip_destino):
    print(f"[*] Iniciando Port Scan para o IP {ip_destino}...")
    open_ports = []

    # Defina uma lista de portas comuns
    common_ports = [21, 22, 23, 25, 53, 80, 443, 110, 143, 3389, 8080]

    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip_destino, port))
        if result == 0:  # Porta aberta
            open_ports.append(port)
        sock.close()

    if open_ports:
        print(f"[*] Portas abertas em {ip_destino}: {', '.join(map(str, open_ports))}")
    else:
        print("[*] Nenhuma porta aberta encontrada.")



# Função para envio de pacotes TCP
def send_tcp_packets():
    ip_destino = input("[*] Informe o IP de destino para envio de pacotes TCP: ")
    port_scan(ip_destino)



# Função principal
def main():
    parser = argparse.ArgumentParser(
        description="Script Capybara - Ferramenta de Redes com Spoofing, Port Scan e Envio de Pacotes TCP"
    )
    parser.add_argument("-s", "--spoofing", action="store_true", help="Executar spoofing")
    parser.add_argument("-p", "--portscan", action="store_true", help="Executar port scan")
    parser.add_argument("-t", "--tcp", action="store_true", help="Enviar pacotes TCP")

    args = parser.parse_args()

    # Exibe a logo ao iniciar o script
    show_logo()

    # Chama as funções baseadas nos argumentos
    if args.spoofing:
        spoofing()
    if args.portscan:
        ip_destino = input("[*] Informe o IP de destino para o Port Scan: ")
        if not is_valid_ip(ip_destino):
            print("[!] Endereço IP fornecido é inválido.")
            return
        port_scan(ip_destino)
    if args.tcp:
        send_tcp_packets()

    # Caso nenhum argumento seja fornecido
    if not (args.spoofing or args.portscan or args.tcp):
        parser.print_help()


if __name__ == "__main__":
    main()





# By:
#       ::::    :::  ::::::::  :::::::::   ::::::::             ::::::::   :::::::   :::::::  ::
#      :+:+:   :+: :+:    :+: :+:    :+: :+:    :+:           :+:    :+: :+:   :+: :+:   :+: :+:
#     :+:+:+  +:+        +:+ +:+    +:+ +:+    +:+           +:+        +:+   +:+ +:+   +:+ +:+
#    +#+ +:+ +#+     +#++:  +#++:++#:  +#+    +:+           +#+        +#+   +:+ +#+   +:+ +#+
#   +#+  +#+#+#        +#+ +#+    +#+ +#+    +#+           +#+        +#+   +#+ +#+   +#+ +#+
#   #+#   #+#+# #+#    #+# #+#    #+# #+#    #+#           #+#    #+# #+#   #+# #+#   #+# #+#
#  ###    ####  ########  ###    ###  ########  ########## ########   #######   #######  ##########
