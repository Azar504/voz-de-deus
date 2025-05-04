import os
import sys
import time
import socket
import hashlib
import threading
import random
import requests
import pyfiglet
from colorama import init, Fore, Back, Style
from termcolor import colored

init(autoreset=True)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def typing_effect(text, speed=0.03):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(speed)
    print()

def loading_effect(message="CARREGANDO", duration=2):
    chars = "▓░▒"
    for _ in range(duration * 10):
        for char in chars:
            sys.stdout.write(f"\r{Fore.RED}{message} {char * 20}")
            sys.stdout.flush()
            time.sleep(0.05)
    print()

def display_banner():
    clear_screen()
    banner = pyfiglet.figlet_format("VOZ DE DEUS", font="slant")
    glitch_banner = ""
    for line in banner.split("\n"):
        if random.random() < 0.2:
            glitch_line = ""
            for char in line:
                if random.random() < 0.1:
                    glitch_line += random.choice("!@#$%^&*()_+-=")
                else:
                    glitch_line += char
            glitch_banner += glitch_line + "\n"
        else:
            glitch_banner += line + "\n"
    
    print(Fore.RED + glitch_banner)
    typing_effect(f"{Fore.CYAN}[SISTEMA INICIADO]{Style.RESET_ALL} {Fore.GREEN}[ONLINE]{Style.RESET_ALL} {Fore.YELLOW}[FIREWALL BYPASSED]")
    print(f"{Fore.RED}{'=' * 60}")
    typing_effect(f"{Fore.WHITE}SISTEMA DE RASTREAMENTO E COLETA DE DADOS v2.5")
    print(f"{Fore.RED}{'=' * 60}")
    time.sleep(1)

def display_menu():
    print(f"\n{Fore.CYAN}SELECIONE UMA OPERAÇÃO:")
    print(f"{Fore.RED}{'=' * 60}")
    print(f"{Fore.YELLOW}[1] {Fore.WHITE}CONSULTAR CNPJ")
    print(f"{Fore.YELLOW}[2] {Fore.WHITE}CONSULTAR IP")
    print(f"{Fore.YELLOW}[3] {Fore.WHITE}CONSULTAR BIN (CARTÃO)")
    print(f"{Fore.YELLOW}[4] {Fore.WHITE}CONSULTAR CEP")
    print(f"{Fore.YELLOW}[5] {Fore.WHITE}ESCANEAR PORTAS TCP")
    print(f"{Fore.YELLOW}[6] {Fore.WHITE}PING/TRACEROUTE")
    print(f"{Fore.YELLOW}[7] {Fore.WHITE}CONSULTAR SENHA VAZADA")
    print(f"{Fore.YELLOW}[8] {Fore.WHITE}MALWARES - GUIA")
    print(f"{Fore.YELLOW}[0] {Fore.WHITE}SAIR DO SISTEMA")
    print(f"{Fore.RED}{'=' * 60}")

def consultar_cnpj():
    clear_screen()
    banner = pyfiglet.figlet_format("CNPJ SCAN", font="doom")
    print(Fore.RED + banner)
    print(f"{Fore.RED}{'=' * 60}")
    typing_effect(f"{Fore.CYAN}[RASTREAMENTO DE ENTIDADES]{Style.RESET_ALL}")

    while True:
        cnpj = input(f"\n{Fore.YELLOW}>>> DIGITE O CNPJ (APENAS NÚMEROS): {Fore.WHITE}")
        cnpj = ''.join(filter(str.isdigit, cnpj))
        
        if len(cnpj) != 14:
            print(f"{Fore.RED}[ERRO] CNPJ DEVE CONTER 14 DÍGITOS.")
            continue
            
        loading_effect("CONSULTANDO SERVIDOR", 2)
        
        try:
            url = f"https://receitaws.com.br/v1/cnpj/{cnpj}"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                if "ERROR" in data or data.get("status") == "ERROR":
                    print(f"{Fore.RED}[ERRO] {data.get('message', 'CNPJ NÃO ENCONTRADO OU SERVIDOR INDISPONÍVEL.')}")
                else:
                    print(f"\n{Fore.GREEN}[ALVO LOCALIZADO]{Style.RESET_ALL}")
                    print(f"{Fore.RED}{'=' * 60}")
                    print(f"{Fore.CYAN}RAZÃO SOCIAL: {Fore.WHITE}{data.get('nome', 'N/A')}")
                    print(f"{Fore.CYAN}NOME FANTASIA: {Fore.WHITE}{data.get('fantasia', 'N/A')}")
                    print(f"{Fore.CYAN}SITUAÇÃO: {Fore.WHITE}{data.get('situacao', 'N/A')}")
                    print(f"{Fore.CYAN}TIPO: {Fore.WHITE}{data.get('tipo', 'N/A')}")
                    print(f"{Fore.CYAN}ATIVIDADE PRINCIPAL: {Fore.WHITE}{data.get('atividade_principal', [{}])[0].get('text', 'N/A') if data.get('atividade_principal') else 'N/A'}")
                    print(f"{Fore.CYAN}CEP: {Fore.WHITE}{data.get('cep', 'N/A')}")
                    print(f"{Fore.CYAN}ENDEREÇO: {Fore.WHITE}{data.get('logradouro', 'N/A')}, {data.get('numero', 'N/A')}")
                    print(f"{Fore.CYAN}BAIRRO: {Fore.WHITE}{data.get('bairro', 'N/A')}")
                    print(f"{Fore.CYAN}CIDADE/UF: {Fore.WHITE}{data.get('municipio', 'N/A')}/{data.get('uf', 'N/A')}")
                    print(f"{Fore.CYAN}CAPITAL SOCIAL: {Fore.WHITE}R$ {data.get('capital_social', 'N/A')}")
                    print(f"{Fore.CYAN}ABERTURA: {Fore.WHITE}{data.get('abertura', 'N/A')}")
                    
                    dados_cnpj = data
            else:
                print(f"{Fore.RED}[ERRO] STATUS CODE: {response.status_code}")
                print(f"{Fore.RED}[ERRO] SERVIDOR RECUSOU A CONEXÃO OU LIMITE DE CONSULTAS ATINGIDO.")
                print(f"{Fore.YELLOW}Tente novamente em alguns minutos.")
                
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[ERRO DE CONEXÃO] {e}")
        
        opcao = input(f"\n{Fore.YELLOW}CONSULTAR OUTRO CNPJ? (S/N): {Fore.WHITE}").upper()
        if opcao != "S":
            break

def consultar_ip():
    clear_screen()
    banner = pyfiglet.figlet_format("IP TRACER", font="poison")
    print(Fore.CYAN + banner)
    print(f"{Fore.RED}{'=' * 60}")
    typing_effect(f"{Fore.CYAN}[RASTREAMENTO DE LOCALIZAÇÃO]{Style.RESET_ALL}")

    while True:
        ip = input(f"\n{Fore.YELLOW}>>> DIGITE O IP ALVO (VAZIO PARA SEU IP): {Fore.WHITE}")
        
        loading_effect("TRIANGULANDO SINAL", 2)
        
        try:
            url = f"https://ipinfo.io/{ip}/json" if ip else "https://ipinfo.io/json"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                print(f"\n{Fore.GREEN}[ALVO LOCALIZADO]{Style.RESET_ALL}")
                print(f"{Fore.RED}{'=' * 60}")
                print(f"{Fore.CYAN}IP: {Fore.WHITE}{data.get('ip', 'N/A')}")
                print(f"{Fore.CYAN}HOSTNAME: {Fore.WHITE}{data.get('hostname', 'N/A')}")
                print(f"{Fore.CYAN}CIDADE: {Fore.WHITE}{data.get('city', 'N/A')}")
                print(f"{Fore.CYAN}REGIÃO: {Fore.WHITE}{data.get('region', 'N/A')}")
                print(f"{Fore.CYAN}PAÍS: {Fore.WHITE}{data.get('country', 'N/A')}")
                print(f"{Fore.CYAN}LOCALIZAÇÃO: {Fore.WHITE}{data.get('loc', 'N/A')}")
                print(f"{Fore.CYAN}ORGANIZAÇÃO: {Fore.WHITE}{data.get('org', 'N/A')}")
                print(f"{Fore.CYAN}TIMEZONE: {Fore.WHITE}{data.get('timezone', 'N/A')}")
                
                resultado_ip = data
                
                if data.get('loc'):
                    lat, lon = data.get('loc').split(',')
                    print(f"{Fore.YELLOW}[INFO] COORDENADAS PARA MAPA: https://www.google.com/maps?q={lat},{lon}")
            else:
                print(f"{Fore.RED}[ERRO] STATUS CODE: {response.status_code}")
                print(f"{Fore.RED}[ERRO] IP INVÁLIDO OU SERVIDOR INDISPONÍVEL.")
                
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[ERRO DE CONEXÃO] {e}")
        
        opcao = input(f"\n{Fore.YELLOW}CONSULTAR OUTRO IP? (S/N): {Fore.WHITE}").upper()
        if opcao != "S":
            break

def consultar_bin():
    clear_screen()
    banner = pyfiglet.figlet_format("BIN LOOKUP", font="ansi_shadow")
    print(Fore.GREEN + banner)
    print(f"{Fore.RED}{'=' * 60}")
    typing_effect(f"{Fore.CYAN}[RASTREAMENTO DE CARTÕES]{Style.RESET_ALL}")

    while True:
        bin_number = input(f"\n{Fore.YELLOW}>>> DIGITE OS 6 PRIMEIROS DÍGITOS DO CARTÃO: {Fore.WHITE}")
        bin_number = ''.join(filter(str.isdigit, bin_number))
        
        if len(bin_number) < 6:
            print(f"{Fore.RED}[ERRO] BIN DEVE CONTER PELO MENOS 6 DÍGITOS.")
            continue
            
        bin_number = bin_number[:6]  
        loading_effect("CONSULTANDO BASE DE DADOS", 2)
        
        try:
            url = f"https://lookup.binlist.net/{bin_number}"
            headers = {'Accept-Version': '3'}
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                print(f"\n{Fore.GREEN}[DADOS ENCONTRADOS]{Style.RESET_ALL}")
                print(f"{Fore.RED}{'=' * 60}")
                print(f"{Fore.CYAN}BIN: {Fore.WHITE}{bin_number}")
                print(f"{Fore.CYAN}BANDEIRA: {Fore.WHITE}{data.get('scheme', 'N/A').upper()}")
                print(f"{Fore.CYAN}TIPO: {Fore.WHITE}{data.get('type', 'N/A').upper()}")
                print(f"{Fore.CYAN}CATEGORIA: {Fore.WHITE}{data.get('category', 'N/A').upper()}")
                
                if data.get('bank'):
                    print(f"{Fore.CYAN}BANCO: {Fore.WHITE}{data.get('bank', {}).get('name', 'N/A')}")
                    print(f"{Fore.CYAN}SITE: {Fore.WHITE}{data.get('bank', {}).get('url', 'N/A')}")
                    print(f"{Fore.CYAN}TELEFONE: {Fore.WHITE}{data.get('bank', {}).get('phone', 'N/A')}")
                
                if data.get('country'):
                    print(f"{Fore.CYAN}PAÍS: {Fore.WHITE}{data.get('country', {}).get('name', 'N/A')} ({data.get('country', {}).get('alpha2', 'N/A')})")
                    print(f"{Fore.CYAN}MOEDA: {Fore.WHITE}{data.get('country', {}).get('currency', 'N/A')}")
                
                resultado_bin = data
            elif response.status_code == 404:
                print(f"{Fore.RED}[ERRO] BIN NÃO ENCONTRADA NA BASE DE DADOS.")
            else:
                print(f"{Fore.RED}[ERRO] STATUS CODE: {response.status_code}")
                print(f"{Fore.RED}[ERRO] SERVIDOR INDISPONÍVEL OU LIMITE DE CONSULTAS ATINGIDO.")
                
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[ERRO DE CONEXÃO] {e}")
        
        opcao = input(f"\n{Fore.YELLOW}CONSULTAR OUTRA BIN? (S/N): {Fore.WHITE}").upper()
        if opcao != "S":
            break

def consultar_cep():
    clear_screen()
    banner = pyfiglet.figlet_format("CEP SCAN", font="slant")
    print(Fore.YELLOW + banner)
    print(f"{Fore.RED}{'=' * 60}")
    typing_effect(f"{Fore.CYAN}[RASTREAMENTO DE ENDEREÇO]{Style.RESET_ALL}")

    while True:
        cep = input(f"\n{Fore.YELLOW}>>> DIGITE O CEP (APENAS NÚMEROS): {Fore.WHITE}")
        cep = ''.join(filter(str.isdigit, cep))
        
        if len(cep) != 8:
            print(f"{Fore.RED}[ERRO] CEP DEVE CONTER 8 DÍGITOS.")
            continue
            
        loading_effect("ACESSANDO SERVIDORES", 2)
        
        try:
            url = f"https://viacep.com.br/ws/{cep}/json/"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                if "erro" in data:
                    print(f"{Fore.RED}[ERRO] CEP NÃO ENCONTRADO.")
                else:
                    print(f"\n{Fore.GREEN}[LOCALIZAÇÃO ENCONTRADA]{Style.RESET_ALL}")
                    print(f"{Fore.RED}{'=' * 60}")
                    print(f"{Fore.CYAN}CEP: {Fore.WHITE}{data.get('cep', 'N/A')}")
                    print(f"{Fore.CYAN}LOGRADOURO: {Fore.WHITE}{data.get('logradouro', 'N/A')}")
                    print(f"{Fore.CYAN}COMPLEMENTO: {Fore.WHITE}{data.get('complemento', 'N/A') or 'Não informado'}")
                    print(f"{Fore.CYAN}BAIRRO: {Fore.WHITE}{data.get('bairro', 'N/A')}")
                    print(f"{Fore.CYAN}CIDADE: {Fore.WHITE}{data.get('localidade', 'N/A')}")
                    print(f"{Fore.CYAN}UF: {Fore.WHITE}{data.get('uf', 'N/A')}")
                    print(f"{Fore.CYAN}IBGE: {Fore.WHITE}{data.get('ibge', 'N/A')}")
                    print(f"{Fore.CYAN}GIA: {Fore.WHITE}{data.get('gia', 'N/A') or 'Não disponível'}")
                    print(f"{Fore.CYAN}DDD: {Fore.WHITE}{data.get('ddd', 'N/A')}")
                    print(f"{Fore.CYAN}SIAFI: {Fore.WHITE}{data.get('siafi', 'N/A')}")
                    
                    resultado_cep = data
            else:
                print(f"{Fore.RED}[ERRO] STATUS CODE: {response.status_code}")
                print(f"{Fore.RED}[ERRO] SERVIDOR INDISPONÍVEL.")
                
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[ERRO DE CONEXÃO] {e}")
            
        except ValueError:
            print(f"{Fore.RED}[ERRO] FORMATO DE RESPOSTA INVÁLIDO.")
        
        opcao = input(f"\n{Fore.YELLOW}CONSULTAR OUTRO CEP? (S/N): {Fore.WHITE}").upper()
        if opcao != "S":
            break

def escanear_portas():
    clear_screen()
    banner = pyfiglet.figlet_format("PORT SCAN", font="doom")
    print(Fore.RED + banner)
    print(f"{Fore.RED}{'=' * 60}")
    typing_effect(f"{Fore.CYAN}[ESCANEAMENTO DE PORTAS]{Style.RESET_ALL}")

    host = input(f"\n{Fore.YELLOW}>>> DIGITE O IP/DOMÍNIO ALVO: {Fore.WHITE}")
    
    try:
        ip = socket.gethostbyname(host)
        print(f"\n{Fore.GREEN}[+] HOSTNAME {host} RESOLVIDO PARA {ip}")
        print(f"{Fore.RED}{'=' * 60}")
        
        print(f"\n{Fore.YELLOW}[+] INICIANDO SCAN NAS PORTAS 1-1024...")
        print(f"{Fore.RED}{'=' * 60}")
        
        open_ports = []
        start_time = time.time()
        
        def scan_port(port):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((ip, port))
            if result == 0:
                service = "Desconhecido"
                try:
                    service = socket.getservbyport(port)
                except:
                    pass
                print(f"{Fore.GREEN}[ABERTA] Porta {port}: {service}")
                open_ports.append((port, service))
            s.close()
        
        threads = []
        for port in range(1, 1025):
            sys.stdout.write(f"\r{Fore.YELLOW}[SCAN] Verificando porta {port}/1024")
            sys.stdout.flush()
            t = threading.Thread(target=scan_port, args=(port,))
            threads.append(t)
            t.start()
            
            if len(threads) >= 100:
                for t in threads:
                    t.join()
                threads = []
        
        for t in threads:
            t.join()
        
        scan_time = time.time() - start_time
        
        print(f"\n\n{Fore.GREEN}[COMPLETO] Scan finalizado em {scan_time:.2f} segundos")
        print(f"{Fore.RED}{'=' * 60}")
        print(f"{Fore.CYAN}PORTAS ABERTAS EM {host} ({ip}):")
        
        if not open_ports:
            print(f"{Fore.RED}Nenhuma porta aberta encontrada.")
        else:
            for port, service in open_ports:
                print(f"{Fore.GREEN}Porta {port}: {service}")
                
        resultado_scan = {
            "host": host,
            "ip": ip,
            "open_ports": open_ports,
            "scan_time": scan_time
        }
                
    except socket.gaierror:
        print(f"{Fore.RED}[ERRO] Não foi possível resolver o hostname.")
    except socket.error:
        print(f"{Fore.RED}[ERRO] Não foi possível conectar ao servidor.")
    except Exception as e:
        print(f"{Fore.RED}[ERRO] {e}")
    
    input(f"\n{Fore.YELLOW}Pressione ENTER para voltar ao menu...")

def ping_traceroute():
    clear_screen()
    banner = pyfiglet.figlet_format("NET TRACER", font="slant")
    print(Fore.CYAN + banner)
    print(f"{Fore.RED}{'=' * 60}")
    typing_effect(f"{Fore.CYAN}[RASTREAMENTO DE REDE]{Style.RESET_ALL}")

    host = input(f"\n{Fore.YELLOW}>>> DIGITE O IP/DOMÍNIO ALVO: {Fore.WHITE}")
    
    print(f"\n{Fore.GREEN}[1] {Fore.WHITE}PING")
    print(f"{Fore.GREEN}[2] {Fore.WHITE}TRACEROUTE")
    option = input(f"\n{Fore.YELLOW}>>> ESCOLHA UMA OPÇÃO: {Fore.WHITE}")
    
    loading_effect("INICIANDO RASTREAMENTO", 1)
    
    try:
        if option == "1":
            print(f"\n{Fore.YELLOW}[+] EXECUTANDO PING EM {host}...")
            print(f"{Fore.RED}{'=' * 60}")
            
            if os.name == 'nt':
                os.system(f"ping -n 4 {host}")
            else:
                os.system(f"ping -c 4 {host}")
                
        elif option == "2":
            print(f"\n{Fore.YELLOW}[+] EXECUTANDO TRACEROUTE EM {host}...")
            print(f"{Fore.RED}{'=' * 60}")
            
            if os.name == 'nt':
                os.system(f"tracert {host}")
            else:
                os.system(f"traceroute {host}")
        else:
            print(f"{Fore.RED}[ERRO] Opção inválida.")
    except Exception as e:
        print(f"{Fore.RED}[ERRO] {e}")
    
    input(f"\n{Fore.YELLOW}Pressione ENTER para voltar ao menu...")

def verificar_senha_vazada():
    clear_screen()
    banner = pyfiglet.figlet_format("LEAK CHECK", font="doom")
    print(Fore.RED + banner)
    print(f"{Fore.RED}{'=' * 60}")
    typing_effect(f"{Fore.CYAN}[VERIFICAÇÃO DE VAZAMENTOS]{Style.RESET_ALL}")

    senha = input(f"\n{Fore.YELLOW}>>> DIGITE A SENHA PARA VERIFICAR (NÃO ARMAZENAMOS): {Fore.WHITE}")
    
    if not senha:
        print(f"{Fore.RED}[ERRO] SENHA VAZIA.")
        input(f"\n{Fore.YELLOW}Pressione ENTER para voltar ao menu...")
        return
    
    loading_effect("VERIFICANDO VAZAMENTOS", 2)
    
    try:
        sha1_hash = hashlib.sha1(senha.encode()).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]
        
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            hashes = (line.split(':') for line in response.text.splitlines())
            count = next((int(count) for hash_suffix, count in hashes if hash_suffix == suffix), 0)
            
            print(f"\n{Fore.RED}{'=' * 60}")
            
            if count:
                print(f"{Fore.RED}[ALERTA DE SEGURANÇA] Senha encontrada em {count} vazamentos!")
                print(f"{Fore.RED}Esta senha é comprometida e NÃO deve ser usada!")
                print(f"{Fore.YELLOW}Recomendação: Troque esta senha em todos os serviços onde ela é utilizada.")
            else:
                print(f"{Fore.GREEN}[SEGURO] Esta senha não foi encontrada em vazamentos conhecidos.")
                print(f"{Fore.YELLOW}Isso não garante segurança absoluta. Use sempre senhas fortes e autenticação em dois fatores.")
                
            resultado_senha = {
                "hash": sha1_hash,
                "vazamentos": count
            }
        else:
            print(f"{Fore.RED}[ERRO] STATUS CODE: {response.status_code}")
            print(f"{Fore.RED}[ERRO] Não foi possível verificar a senha.")
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[ERRO DE CONEXÃO] {e}")
    except Exception as e:
        print(f"{Fore.RED}[ERRO] {e}")
    
    input(f"\n{Fore.YELLOW}Pressione ENTER para voltar ao menu...")

def mostrar_malwares():
    clear_screen()
    
    glitch_text = """
    ▓▓▓ ERROR 0x8007007E ▓▓▓
    
    ▒▒▒▒▒▒▒ SYSTEM FAILURE ▒▒▒▒▒▒▒
    
    █▓▒░MÓDULO DESATIVADO░▒▓█
    
    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
    
    [██] ACESSO NEGADO [██]
    
    █▄█▄█▄ MANUTENÇÃO EM ANDAMENTO █▄█▄█▄
    """
    
    error_banner = pyfiglet.figlet_format("FORA DO AR", font="doom")
    print(Fore.RED + error_banner)
    
    for line in glitch_text.split('\n'):
        typing_effect(Fore.RED + line, 0.01)
    
    print(f"\n{Fore.RED}{'=' * 60}")
    print(f"{Fore.RED}[AVISO] Este módulo está temporariamente indisponível.")
    print(f"{Fore.RED}[AVISO] Motivo: Manutenção de segurança.")
    print(f"{Fore.RED}{'=' * 60}")
    
    input(f"\n{Fore.YELLOW}Pressione ENTER para voltar ao menu...")

def exit_program():
    clear_screen()
    banner = pyfiglet.figlet_format("DESCONECTANDO", font="poison")
    print(Fore.RED + banner)
    print(f"{Fore.RED}{'=' * 60}")
    
    messages = [
        "ENCERRANDO CONEXÃO COM O HOST...",
        "APAGANDO REGISTROS DE ACESSO...",
        "REMOVENDO TRAÇOS DIGITAIS...",
        "LIMPANDO MEMÓRIA CACHE...",
        "SAINDO DO SISTEMA..."
    ]
    
    for msg in messages:
        typing_effect(f"{Fore.CYAN}{msg}", 0.05)
        time.sleep(0.5)
    
    final_msg = pyfiglet.figlet_format("CONEXAO ENCERRADA", font="slant")
    print(Fore.RED + final_msg)
    
    sys.exit(0)

def main():
    while True:
        display_banner()
        display_menu()
        
        try:
            choice = input(f"\n{Fore.YELLOW}>>> DIGITE SUA ESCOLHA: {Fore.WHITE}")
            
            options = {
                "1": consultar_cnpj,
                "2": consultar_ip,
                "3": consultar_bin,
                "4": consultar_cep,
                "5": escanear_portas,
                "6": ping_traceroute,
                "7": verificar_senha_vazada,
                "8": mostrar_malwares,
                "0": exit_program
            }
            
            if choice in options:
                options[choice]()
            else:
                print(f"{Fore.RED}[ERRO] Opção inválida!")
                time.sleep(1)
        except KeyboardInterrupt:
            exit_program()
        except Exception as e:
            print(f"{Fore.RED}[ERRO CRÍTICO] {e}")
            time.sleep(2)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        exit_program()