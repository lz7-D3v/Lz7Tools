
"""
Lz7 Tools - Copyright
import os
import time
import requests
import socket
from colorama import init, Fore, Style

init(autoreset=True)

banner_ascii = f"""
{Fore.RED} __                  ________ 
{Fore.RED}/  |                /        |
{Fore.RED}$$ |       ________ $$$$$$$$/ 
{Fore.RED}$$ |      /        |    /$$/  
{Fore.RED}$$ |      $$$$$$$$/    /$$/   
{Fore.RED}$$ |        /  $$/    /$$/    
{Fore.RED}$$ |_____  /$$$$/__  /$$/     
{Fore.RED}$$       |/$$      |/$$/      
{Fore.RED}$$$$$$$$/ $$$$$$$$/ $$/       

{Fore.WHITE}             Lz7 Tools by @Lz7.D3v
{Fore.RED}───────────────────────────────────────────────
"""

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def pause():
    input(Fore.WHITE + "\nPressione Enter para voltar...")

def menu_page(title, options, next_page=None, prev_page=None):
    clear()
    print(banner_ascii)
    print(Fore.WHITE + Style.BRIGHT + title + "\n")

    for i, option in enumerate(options, start=1):
        print(f"{Fore.WHITE}[{i}] {option}")

    if next_page:
        print(f"\n{Fore.RED}[N] Próxima Página", end='  ')
    if prev_page:
        print(f"{Fore.RED}[B] Página Anterior", end='  ')
    print(f"{Fore.RED}[I] Info  [Q] Sair\n")

def ip_scanner():
    clear()
    print(banner_ascii)
    print(Fore.CYAN + "[IP Scanner] Informe o IP para escanear.\n")

    ip = input(Fore.WHITE + "Digite o IP: ").strip()
    if not ip:
        print(Fore.RED + "\n[!] IP inválido.")
        pause()
        return

    print(Fore.YELLOW + "\n[~] Buscando informações...\n")
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()

        if data['status'] == 'success':
            print(Fore.GREEN + f"IP: {data['query']}")
            print(Fore.GREEN + f"País: {data['country']}")
            print(Fore.GREEN + f"Região: {data['regionName']}")
            print(Fore.GREEN + f"Cidade: {data['city']}")
            print(Fore.GREEN + f"Latitude: {data['lat']}")
            print(Fore.GREEN + f"Longitude: {data['lon']}")
            print(Fore.GREEN + f"ISP: {data['isp']}")
            print(Fore.GREEN + f"Organização: {data['org']}")
            print(Fore.GREEN + f"ZIP: {data.get('zip', 'N/A')}")
            print(Fore.GREEN + f"Timezone: {data.get('timezone', 'N/A')}")
        else:
            print(Fore.RED + f"[!] Erro: {data.get('message', 'IP inválido ou não encontrado.')}")
    except Exception as e:
        print(Fore.RED + f"\n[!] Erro na requisição: {str(e)}")

    pause()

def port_scanner():
    clear()
    print(banner_ascii)
    print(Fore.CYAN + "[Port Scanner] Informe o IP ou domínio para escanear.\n")

    target = input(Fore.WHITE + "Digite o IP ou domínio: ").strip()
    if not target:
        print(Fore.RED + "\n[!] Alvo inválido.")
        pause()
        return

    print(Fore.YELLOW + f"\n[~] Escaneando portas de {target} (1 a 1024)...\n")
    open_ports = []

    try:
        for port in range(1, 1025):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
                print(Fore.GREEN + f"[+] Porta {port} aberta")
            sock.close()
    except Exception as e:
        print(Fore.RED + f"[!] Erro: {e}")

    if not open_ports:
        print(Fore.RED + "\nNenhuma porta comum foi encontrada aberta.")
    else:
        print(Fore.CYAN + f"\nPortas abertas: {open_ports}")

    pause()


def username_tracker():
    clear()
    print(banner_ascii)
    print(Fore.CYAN + "[Username Tracker] Verificando presença global de um nome de usuário.\n")

    username = input(Fore.WHITE + "Digite o nome de usuário: ").strip()
    if not username:
        print(Fore.RED + "\n[!] Nome de usuário inválido.")
        pause()
        return

    print(Fore.YELLOW + f"\n[~] Procurando por '{username}' em mais de 25 plataformas...\n")

    platforms = {
        "GitHub": f"https://github.com/{username}",
        "Twitter": f"https://twitter.com/{username}",
        "Instagram": f"https://instagram.com/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "TikTok": f"https://www.tiktok.com/@{username}",
        "Pinterest": f"https://www.pinterest.com/{username}",
        "SoundCloud": f"https://soundcloud.com/{username}",
        "Medium": f"https://medium.com/@{username}",
        "YouTube": f"https://www.youtube.com/@{username}",
        "DeviantArt": f"https://www.deviantart.com/{username}",
        "About.me": f"https://about.me/{username}",
        "Twitch": f"https://www.twitch.tv/{username}",
        "VK": f"https://vk.com/{username}",
        "GitLab": f"https://gitlab.com/{username}",
        "Flickr": f"https://www.flickr.com/people/{username}",
        "Replit": f"https://replit.com/@{username}",
        "Keybase": f"https://keybase.io/{username}",
        "Blogger": f"https://{username}.blogspot.com",
        "Steam": f"https://steamcommunity.com/id/{username}",
        "Roblox": f"https://www.roblox.com/user.aspx?username={username}",
        "Patreon": f"https://www.patreon.com/{username}",
        "ProductHunt": f"https://www.producthunt.com/@{username}",
        "OK.ru": f"https://ok.ru/{username}",
        "500px": f"https://500px.com/{username}",
        "Behance": f"https://www.behance.net/{username}",
        "Tripadvisor": f"https://www.tripadvisor.com/Profile/{username}",
        "Goodreads": f"https://www.goodreads.com/user/show/{username}",
        "Wattpad": f"https://www.wattpad.com/user/{username}",
        "Last.fm": f"https://www.last.fm/user/{username}"
    }

    for site, url in platforms.items():
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                print(Fore.GREEN + f"[+] {site}: Encontrado → {url}")
            elif r.status_code == 404:
                print(Fore.RED + f"[-] {site}: Não encontrado")
            else:
                print(Fore.YELLOW + f"[?] {site}: Código {r.status_code}")
        except Exception as e:
            print(Fore.RED + f"[!] {site}: Erro → {e}")

    pause()


def website_vuln_scanner():
    import time
    from urllib.parse import urljoin

    def get_wordlist():
        clear()
        print("""Escolha a wordlist a ser utilizada:

[1] Usar wordlist padrão do Lz7 Tools
[2] Usar sua própria wordlist (.txt)

""")
        choice = input("Escolha uma opção: ").strip()

        if choice == '1':
            return 'wordlist.txt'
        elif choice == '2':
            print("\nExemplo de caminho no Android:")
            print("/storage/emulated/0/DCIM/minha-wordlist.txt\n")
            path = input("Digite o caminho da sua wordlist: ").strip()
            if os.path.exists(path):
                return path
            else:
                print("\n[ERRO] Caminho inválido.")
                pause()
                return get_wordlist()
        else:
            print("\n[!] Opção inválida.")
            pause()
            return get_wordlist()

    def get_target():
        clear()
        print("Digite o site alvo corretamente. Exemplo:")
        print("https://example.com\n")
        url = input("URL do site: ").strip()
        if not url.startswith("http"):
            print("\n[!] URL inválida. Deve começar com http:// ou https://")
            pause()
            return get_target()
        return url

    def scan_endpoints(base_url, wordlist_path):
        print("\n[+] Iniciando varredura com wordlist...")
        time.sleep(1)
        try:
            with open(wordlist_path, 'r') as file:
                paths = [line.strip() for line in file if line.strip()]
        except Exception as e:
            print(f"\n[ERRO] Falha ao ler wordlist: {e}")
            return

        for endpoint in paths:
            full_url = urljoin(base_url, endpoint)
            try:
                response = requests.get(full_url, timeout=5)
                if response.status_code in [200, 301, 302]:
                    print(f"[✔] Encontrado: {full_url} ({response.status_code})")
            except requests.RequestException:
                continue

    def check_xss(url):
        xss_payloads = ["<script>alert(1)</script>", '"><svg/onload=alert(1)>', "<img src=x onerror=alert(1)>"]
        for payload in xss_payloads:
            test_url = f"{url}?q={payload}"
            try:
                r = requests.get(test_url, timeout=5)
                if payload in r.text:
                    print(f"\033[91m[XSS] Possível XSS detectada: {test_url}\033[0m")
            except:
                continue

    def check_sql_injection(url):
        sqli_payloads = ["' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL, NULL--", "' AND sleep(5)--"]
        for payload in sqli_payloads:
            test_url = f"{url}?id={payload}"
            try:
                r = requests.get(test_url, timeout=5)
                if "sql" in r.text.lower() or r.status_code == 500:
                    print(f"\033[91m[SQLi] Possível SQL Injection: {test_url}\033[0m")
            except:
                continue

    def check_lfi(url):
        lfi_payloads = ["../../etc/passwd", "../../../../../../etc/passwd", "../windows/win.ini"]
        for payload in lfi_payloads:
            test_url = f"{url}?file={payload}"
            try:
                r = requests.get(test_url, timeout=5)
                if "root:" in r.text or "[extensions]" in r.text:
                    print(f"\033[91m[LFI] Possível LFI: {test_url}\033[0m")
            except:
                continue

    def check_cmd_injection(url):
        cmd_payloads = ["test;whoami", "1|whoami", "`whoami`"]
        for payload in cmd_payloads:
            test_url = f"{url}?cmd={payload}"
            try:
                r = requests.get(test_url, timeout=5)
                if "root" in r.text or "admin" in r.text:
                    print(f"\033[91m[CMD] Possível Command Injection: {test_url}\033[0m")
            except:
                continue

    clear()
    print(banner_ascii)
    print(Fore.CYAN + "[Website Vulnerability Scanner]\n")
    wordlist = get_wordlist()
    target = get_target()
    scan_endpoints(target, wordlist)
    check_xss(target)
    check_sql_injection(target)
    check_lfi(target)
    check_cmd_injection(target)
    print("\n[✓] Varredura finalizada.")
    pause()


def email_lookup():
    import hashlib
    clear()
    print(banner_ascii)
    print(Fore.CYAN + "[Email Lookup] Investigação de endereço de e-mail\n")

    email = input(Fore.WHITE + "Digite o e-mail para análise: ").strip()
    if not email or "@" not in email:
        print(Fore.RED + "\n[!] E-mail inválido.")
        pause()
        return

    print(Fore.YELLOW + f"\n[~] Coletando informações sobre: {email}\n")

    # Gravatar (público)
    gravatar_hash = hashlib.md5(email.lower().encode()).hexdigest()
    gravatar_url = f"https://www.gravatar.com/avatar/{gravatar_hash}?d=404"

    try:
        resp = requests.get(gravatar_url)
        if resp.status_code == 200:
            print(Fore.GREEN + "[+] Gravatar: Imagem encontrada")
            print(Fore.GREEN + f"URL: {gravatar_url}")
        else:
            print(Fore.RED + "[-] Gravatar: Nenhuma imagem encontrada")
    except:
        print(Fore.RED + "[!] Erro ao consultar o Gravatar.")

    # HaveIBeenPwned (checagem básica de exposição pública)
    hibp_url = f"https://haveibeenpwned.com/unifiedsearch/{email}"
    print(Fore.YELLOW + "\n[~] Verifique manualmente se houve vazamentos:")
    print(Fore.CYAN + f"=> {hibp_url}")

    # Busca simples por presença em sites
    common_sites = {
        "Twitter": f"https://twitter.com/search?q={email}",
        "Facebook": f"https://www.facebook.com/search/top/?q={email}",
        "LinkedIn": f"https://www.linkedin.com/search/results/all/?keywords={email}",
        "Pastebin": f"https://pastebin.com/search?q={email}",
        "Google": f"https://www.google.com/search?q={email}",
        "Hunter.io": f"https://hunter.io/email-finder/{email.split('@')[0]}"
    }

    print(Fore.YELLOW + "\n[~] Presença em plataformas:")
    for name, url in common_sites.items():
        print(Fore.CYAN + f"=> {name}: {url}")

    pause()


def phone_lookup():
    clear()
    print(banner_ascii)
    print(Fore.CYAN + "[Phone Number Lookup] Investigação básica de número telefônico\n")

    number = input(Fore.WHITE + "Digite o número com código do país (ex: +5511988887777): ").strip()
    if not number.startswith('+') or len(number) < 8:
        print(Fore.RED + "\n[!] Número inválido. Deve começar com '+' e conter código do país.")
        pause()
        return

    print(Fore.YELLOW + f"\n[~] Coletando dados públicos sobre: {number}\n")

    print(Fore.CYAN + "[Links úteis para investigação manual:]")
    lookup_links = {
        "Google Search": f"https://www.google.com/search?q={number}",
        "Truecaller (consulta)": f"https://www.truecaller.com/search/global/{number}",
        "Sync.me": f"https://sync.me/search/?number={number}",
        "Facebook": f"https://www.facebook.com/search/top/?q={number}",
        "Instagram (via busca)": f"https://www.instagram.com/{number}",
        "WhoCallsMe": f"https://whocallsme.com/Phone-Number.aspx/{number}",
        "WhatsApp Web": "https://web.whatsapp.com"  # observação: usado manualmente no app
    }

    for name, url in lookup_links.items():
        print(Fore.GREEN + f"=> {name}: {url}")

    print(Fore.YELLOW + "\n[~] Dica: Use o Truecaller pelo navegador ou app para tentar ver o nome cadastrado.")
    pause()


def exif_reader():
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS

    def get_exif_data(img_path):
        try:
            image = Image.open(img_path)
            exif_data = image._getexif()
            if not exif_data:
                print(Fore.RED + "\n[!] Nenhum dado EXIF encontrado.")
                return

            print(Fore.YELLOW + "\n[~] Metadados encontrados:\n")
            for tag_id, value in exif_data.items():
                tag = TAGS.get(tag_id, tag_id)
                print(Fore.GREEN + f"{tag}: {value}")

                # Localização (GPS)
                if tag == "GPSInfo":
                    gps_data = {}
                    for t in value:
                        sub_tag = GPSTAGS.get(t, t)
                        gps_data[sub_tag] = value[t]
                    print(Fore.CYAN + "\n[+] Dados GPS:")
                    for g in gps_data:
                        print(f"  {g}: {gps_data[g]}")
        except Exception as e:
            print(Fore.RED + f"\n[!] Erro ao ler EXIF: {e}")

    clear()
    print(banner_ascii)
    print(Fore.CYAN + "[Exif Image Reader] Leitor de metadados de imagem\n")
    path = input(Fore.WHITE + "Digite o caminho da imagem (ex: /sdcard/DCIM/img.jpg): ").strip()

    if not path or not os.path.exists(path):
        print(Fore.RED + "\n[!] Caminho inválido ou arquivo não encontrado.")
    else:
        get_exif_data(path)

    pause()


def google_dorking():
    clear()
    print(banner_ascii)
    print(Fore.CYAN + "[Google Dorking] Gerador avançado de buscas com operadores Google\n")

    target = input(Fore.WHITE + "Digite um domínio, palavra-chave ou nome: ").strip()
    if not target:
        print(Fore.RED + "\n[!] Entrada inválida.")
        pause()
        return

    print(Fore.YELLOW + "\n[~] Dorks gerados para: " + target + "\n")

    dorks = {
        "Arquivos PDF": f'site:{target} filetype:pdf',
        "Planilhas (XLS)": f'site:{target} filetype:xls',
        "Documentos Word": f'site:{target} filetype:doc',
        "Configurações expostas (.env)": f'site:{target} ext:env | ext:ini | ext:conf',
        "Senhas em texto": f'site:{target} intext:senha | intext:password',
        "Painéis de Admin": f'site:{target} inurl:admin | intitle:admin',
        "Câmeras IP públicas": 'inurl:view/index.shtml',
        "Diretórios abertos": f'site:{target} intitle:"index of"',
        "Emails expostos": f'site:{target} intext:@{target}',
        "Usuários e senhas em logs": f'site:{target} filetype:log intext:username | intext:senha',
        "Busca por backups": f'site:{target} ext:bak | ext:old | ext:backup',
        "Busca geral com cache": f'cache:{target}',
        "Google Drive exposto": f'site:drive.google.com "{target}"',
        "LinkedIn": f'site:linkedin.com/in "{target}"',
        "GitHub": f'site:github.com "{target}"',
        "Pastebin leaks": f'site:pastebin.com "{target}"'
    }

    for title, query in dorks.items():
        url = f"https://www.google.com/search?q={query.replace(' ', '+')}"
        print(Fore.GREEN + f"[+] {title}")
        print(Fore.CYAN + f"=> {url}\n")

    print(Fore.YELLOW + "[~] Copie e cole os links no navegador para investigar.")
    pause()


def ip_geolocation():
    clear()
    print(banner_ascii)
    print(Fore.CYAN + "[IP Geolocation] Localização detalhada de IP público\n")

    ip = input(Fore.WHITE + "Digite o IP para geolocalização: ").strip()
    if not ip:
        print(Fore.RED + "\n[!] IP inválido.")
        pause()
        return

    print(Fore.YELLOW + "\n[~] Buscando informações via ip-api.com...\n")
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,continent,country,regionName,city,zip,lat,lon,timezone,isp,org,as,query")
        data = response.json()

        if data['status'] == 'success':
            print(Fore.GREEN + f"IP: {data['query']}")
            print(Fore.GREEN + f"Continente: {data['continent']}")
            print(Fore.GREEN + f"País: {data['country']}")
            print(Fore.GREEN + f"Região: {data['regionName']}")
            print(Fore.GREEN + f"Cidade: {data['city']}")
            print(Fore.GREEN + f"CEP: {data['zip']}")
            print(Fore.GREEN + f"Latitude: {data['lat']}")
            print(Fore.GREEN + f"Longitude: {data['lon']}")
            print(Fore.GREEN + f"Fuso horário: {data['timezone']}")
            print(Fore.GREEN + f"ISP: {data['isp']}")
            print(Fore.GREEN + f"Organização: {data['org']}")
            print(Fore.GREEN + f"AS: {data['as']}")
            print(Fore.YELLOW + f"🗺️ Google Maps: https://www.google.com/maps?q={data['lat']},{data['lon']}")
        else:
            print(Fore.RED + f"[!] Erro: {data.get('message', 'IP inválido ou não encontrado.')}")
    except Exception as e:
        print(Fore.RED + f"[!] Erro na requisição: {str(e)}")

    pause()

# Menus separados
network_options = [
    "Website Vulnerability Scanner",
    "IP Scanner",
    "Port Scanner"
]

osint_options = [
    "Username Tracker",
    "Email Lookup",
    "Phone Number Lookup"
]

utilities_options = [
    "Exif Image Reader",
    "Google Dorking",
    "IP Geolocation"
]

menus = [network_options, osint_options, utilities_options]
titles = ["[1] Network Scanner", "[2] OSINT", "[3] Utilities"]
current = 0

while True:
    menu_page(titles[current], menus[current], next_page=True, prev_page=(current > 0))

    choice = input(Fore.WHITE + "Escolha uma opção: ").strip().lower()

    if choice in ['q', 'quit']:
        break
    elif choice in ['i', 'info']:
        print(Fore.RED + "\n[Info]" + Fore.WHITE + " Tool.")
        pause()
    elif choice == 'n' and current < len(menus) - 1:
        current += 1
    elif choice == 'b' and current > 0:
        current -= 1
    elif choice == '1' and current == 0:
        website_vuln_scanner()
        pause()
    elif choice == '2' and current == 0:
        ip_scanner()
    elif choice == '3' and current == 0:
        port_scanner()
    
    elif choice == '1' and current == 1:
        username_tracker()
    elif choice == '2' and current == 1:
        email_lookup()
    elif choice == '3' and current == 1:
        phone_lookup()
    elif choice == '1' and current == 2:
        exif_reader()
    elif choice == '2' and current == 2:
        google_dorking()
    elif choice == '3' and current == 2:
        ip_geolocation()
    else:
        print(Fore.RED + "\n[!] Opção inválida.")

        pause()
