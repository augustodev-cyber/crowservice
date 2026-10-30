import json, socket
from concurrent.futures import ThreadPoolExecutor,as_completed
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress,SpinnerColumn,BarColumn,TextColumn,TimeElapsedColumn
from rich.prompt import Prompt,Confirm
from rich import box
from .branding import *
from .config import load as load_config
from .inputs import read_wordlist,validate_target,load_ports
from .fingerprint import scan_port,host_metadata
from .dns_whois import dns_lookup,whois_lookup,ptr_lookup
from .vulnintel import search_nvd
from .database import save_scan,save_lookup,recent_scans,services_for_scan,recent_lookups,db_summary
from .exporter import export_rows
from .web_audit import audit_site
from .database import save_web_audit, recent_web_audits
from .https_proxy import start_proxy, proxy_status, stop_proxy

console=Console()

def banner():
    art=r"""
   ______                     _____                 _
  / ____/________ _      __  / ___/___  ______   __(_)_______
 / /   / ___/ __ \ | /| / /  \__ \/ _ \/ ___/ | / / / ___/ _ \
/ /___/ /  / /_/ / |/ |/ /  ___/ /  __/ /   | |/ / / /__/  __/
\____/_/   \____/|__/|__/  /____/\___/_/    |___/_/\___/\___/
"""
    console.print(f"[bold cyan]{art}[/]")
    console.print(Panel.fit(f"[bold white]{APP}[/] [cyan]v{VERSION}[/]\n{TAGLINE}\n[bold]Autor:[/] {AUTHOR}\n[bold]GitHub:[/] {GITHUB}",
                            border_style="cyan"))
    console.print("[yellow]Use somente em ativos próprios ou com autorização explícita.[/]\n")

def choose_targets():
    console.print("[cyan]1[/] Informar um alvo específico\n[cyan]2[/] Importar wordlist .txt\n[cyan]3[/] Usar lists/ip_list.txt")
    mode=Prompt.ask("Origem dos alvos",choices=["1","2","3"],default="3")
    if mode=="1": vals=[validate_target(Prompt.ask("IP/hostname"))]
    else:
        path="lists/ip_list.txt" if mode=="3" else Prompt.ask("Caminho da wordlist",default="lists/ip_list.txt")
        vals=[validate_target(x) for x in read_wordlist(path)]
    if not vals: raise ValueError("Nenhum alvo carregado.")
    console.print(f"[green]{len(vals)} alvo(s) carregado(s).[/]")
    return vals

def service_risk(row, cves):
    scores=[x.get("cvss") for x in cves.get("items",[]) if isinstance(x.get("cvss"),(int,float))]
    if scores:
        score=max(scores)
        if score>=9: return "CRÍTICA",score
        if score>=7: return "ALTA",score
        if score>=4: return "MODERADA",score
        return "BAIXA",score
    if row["state"]!="open": return "N/A",None
    if row["port"] in (23,21): return "REVISAR",None
    return "INDETERMINADA",None

def run_scan():
    cfg=load_config()
    targets=choose_targets()
    ports_path=Prompt.ask("Wordlist de portas",default="lists/port_list.txt")
    ports=load_ports(ports_path,cfg.get("max_ports_per_target",512))
    jobs=[(h,p) for h in targets for p in ports]
    rows=[]; host_data=[]
    console.print(f"[bold]Escopo:[/] {len(targets)} host(s), {len(ports)} porta(s), {len(jobs)} testes TCP.")
    workers=max(1,min(int(cfg.get("max_workers",32)),64))
    with Progress(SpinnerColumn(),TextColumn("{task.description}"),BarColumn(),TextColumn("{task.completed}/{task.total}"),TimeElapsedColumn(),console=console) as progress:
        task=progress.add_task("Verificando serviços...",total=len(jobs))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures=[pool.submit(scan_port,h,p,cfg["timeout"],cfg) for h,p in jobs]
            for f in as_completed(futures):
                try: rows.append(f.result())
                except Exception as e: console.print(f"[red]Erro de probe: {type(e).__name__}[/]")
                progress.advance(task)
    for h in targets:
        host_data.append(host_metadata(h,cfg["timeout"]))
    opened=[r for r in rows if r["state"]=="open"]
    vulnmap={}
    if cfg.get("nvd_enabled") and Confirm.ask("Consultar CVEs aproximados na NVD para produtos/versões identificados?",default=False):
        candidates=[r for r in opened if r.get("product")]
        with Progress(SpinnerColumn(),TextColumn("{task.description}"),BarColumn(),console=console) as progress:
            task=progress.add_task("Consultando NVD...",total=len(candidates))
            for r in candidates:
                vulnmap[(r["host"],r["port"])]=search_nvd(r["product"],r["version"],cfg.get("nvd_results_per_query",8))
                progress.advance(task)
    table=Table(title="CrowService • Serviços detectados",box=box.ROUNDED,show_lines=True,header_style="bold cyan")
    for col in ("HOST","PORTA","SERVIÇO","PRODUTO","VERSÃO","TRIAGEM","CVSS","EVIDÊNCIA"):
        table.add_column(col,overflow="fold")
    for r in sorted(opened,key=lambda x:(x["host"],x["port"])):
        v=vulnmap.get((r["host"],r["port"]),{})
        risk,score=service_risk(r,v)
        color={"CRÍTICA":"bold red","ALTA":"red","MODERADA":"yellow","BAIXA":"green","REVISAR":"yellow"}.get(risk,"dim")
        evidence=r["banner"] or r["http_server"] or r["tls_version"] or "-"
        table.add_row(r["host"],str(r["port"]),r["service"],r["product"] or "-",r["version"] or "-",
                      f"[{color}]{risk}[/]",str(score) if score is not None else "-",
                      evidence[:100].replace("\n"," "))
    console.print(table)
    console.print(f"[bold]Resumo:[/] {len(opened)} serviço(s) aberto(s) de {len(rows)} testes.")
    scan_id=save_scan(rows,host_data,len(ports),vulnmap,note="TCP inventory")
    console.print(f"[green]Execução armazenada no SQLite: scan #{scan_id}[/]")
    jp,cp,digest=export_rows(rows,"services")
    console.print(f"[green]JSON:[/] {jp}\n[green]CSV:[/] {cp}\n[dim]SHA-256 JSON: {digest}[/]")
    if vulnmap:
        for key,data in vulnmap.items():
            if data.get("status")=="ok":
                console.print(f"[cyan]{key[0]}:{key[1]}[/] NVD: {data.get('total',0)} resultado(s) aproximado(s).")
            elif data.get("status")=="unavailable":
                console.print(f"[yellow]NVD indisponível para {key[0]}:{key[1]}[/]")

def run_dns():
    domain=Prompt.ask("Domínio")
    data=dns_lookup(domain,load_config()["timeout"])
    save_lookup("DNS",domain,data)
    t=Table(title=f"DNS • {domain}",box=box.ROUNDED)
    t.add_column("Registro",style="cyan");t.add_column("Valor",overflow="fold")
    for kind,vals in data["records"].items():
        for val in vals: t.add_row(kind,val)
    console.print(t)
    console.print("[green]Consulta salva no SQLite.[/]")

def run_whois():
    target=Prompt.ask("IP ou domínio")
    data=whois_lookup(target)
    save_lookup("WHOIS/RDAP",target,data)
    console.print_json(json.dumps(data,ensure_ascii=False,default=str))
    console.print("[green]Consulta salva no SQLite.[/]")

def db_menu():
    while True:
        console.print(Panel("[1] Resumo das tabelas\n[2] Histórico de varreduras\n[3] Serviços de uma varredura\n[4] Consultas DNS/WHOIS recentes\n[5] Voltar",title="SQLite • Banco local",border_style="cyan"))
        op=Prompt.ask("Banco",choices=["1","2","3","4","5"])
        if op=="1":
            s=db_summary(); t=Table(title="Registros armazenados")
            t.add_column("Tabela");t.add_column("Quantidade",justify="right")
            for k,v in s.items(): t.add_row(k,str(v))
            console.print(t)
        elif op=="2":
            rows=recent_scans()
            t=Table(title="Varreduras recentes")
            for c in ("id","started_utc","target_count","port_count","note"): t.add_column(c)
            for r in rows: t.add_row(*(str(r[c]) for c in ("id","started_utc","target_count","port_count","note")))
            console.print(t)
        elif op=="3":
            sid=int(Prompt.ask("ID da varredura"))
            rows=services_for_scan(sid)
            t=Table(title=f"Serviços • scan #{sid}")
            for c in ("host","port","state","service","product","version"): t.add_column(c)
            for r in rows: t.add_row(*(str(r.get(c) or "-") for c in ("host","port","state","service","product","version")))
            console.print(t)
        elif op=="4":
            rows=recent_lookups()
            t=Table(title="Consultas recentes")
            for c in ("id","created_utc","kind","query"): t.add_column(c)
            for r in rows: t.add_row(*(str(r[c]) for c in ("id","created_utc","kind","query")))
            console.print(t)
        else: break


def https_proxy_menu():
    while True:
        console.print(Panel(
            "[1] Iniciar proxy HTTPS com escopo por domínio\n"
            "[2] Como configurar navegador/dispositivo e certificado CA\n"
            "[3] Ver estado do proxy\n"
            "[4] Parar proxy\n"
            "[5] Voltar",
            title="Auditoria de domínios • Inspeção HTTP(S)", border_style="cyan", expand=True))
        op = Prompt.ask("Inspeção HTTPS", choices=["1", "2", "3", "4", "5"], default="5")
        if op == "1":
            domains = Prompt.ask("Domínios autorizados, separados por vírgula (ex.: exemplo.com, api.exemplo.com)")
            proxy_port = int(Prompt.ask("Porta do proxy local", default="8080"))
            web_port = int(Prompt.ask("Porta da interface web local", default="8081"))
            info = start_proxy(domains, proxy_port, web_port)
            console.print(Panel(
                f"[bold green]Proxy iniciado[/]\nEscopo: {', '.join(info['domains'])}\n"
                f"Proxy para configurar no cliente: [cyan]{info['proxy']}[/]\n"
                f"Painel de inspeção: [cyan]{info['web']}[/]\nPID: {info['pid']}\n\n"
                "Configure o navegador/dispositivo para usar o proxy HTTP indicado. "
                "O tráfego fora do escopo informado não terá descriptografia TLS.",
                title="Interceptação local autorizada", border_style="green", expand=True))
            console.print("[yellow]Atenção:[/] instale a CA do mitmproxy somente em um navegador/dispositivo de laboratório sob seu controle.")
        elif op == "2":
            console.print(Panel(
                "1. Inicie o proxy na opção 1.\n"
                "2. No navegador de teste, configure proxy HTTP e HTTPS para 127.0.0.1:8080 (ou a porta escolhida).\n"
                "3. Importe manualmente o certificado público ~/.mitmproxy/mitmproxy-ca-cert.pem na lista de CAs confiáveis do navegador de teste.\n"
                "4. A CA é criada pelo mitmproxy no primeiro início. Nunca compartilhe mitmproxy-ca.pem nem a chave privada.\n"
                "5. Remova a CA do dispositivo ao terminar os testes.\n\n"
                "O painel mitmweb permite visualizar fluxos, filtrar, inspecionar e editar requisições/respostas, "
                "repetir requisições e acompanhar cabeçalhos/corpos. Conteúdo protegido por certificate pinning "
                "pode não ser inspecionável sem configuração legítima do app de teste.",
                title="Configuração do cliente e CA", border_style="cyan", expand=True))
        elif op == "3":
            console.print(proxy_status())
        elif op == "4":
            console.print("[green]Proxy encerrado.[/]" if stop_proxy() else "[yellow]Nenhum proxy ativo nesta sessão.[/]")
        else:
            break


def run_web_audit_once():
    target=Prompt.ask("Domínio ou URL (ex.: exemplo.com)")
    cfg=load_config()
    console.print("[cyan]Analisando HTTP/HTTPS, TLS, cabeçalhos, cookies e redirecionamentos...[/]")
    data=audit_site(target,timeout=max(3,int(cfg.get("timeout",2.5))*3))
    save_web_audit(data)
    color={"BOM":"green","MODERADO":"yellow","ATENÇÃO":"yellow","FRACO":"red"}.get(data["grade"],"dim")
    console.print(Panel(
        f"[bold]URL:[/] {data['url']}\n[bold]Destino final:[/] {data.get('final_url') or '-'}\n"
        f"[bold]HTTP:[/] {data.get('status_code') or '-'} {data.get('reason','')}\n"
        f"[bold]Tempo:[/] {data.get('response_time_ms') or '-'} ms\n"
        f"[bold]Servidor:[/] {data.get('server') or '-'}\n[bold]Tecnologia declarada:[/] {data.get('powered_by') or '-'}\n"
        f"[bold]Redirecionamentos:[/] {data.get('redirect_count',0)}\n"
        f"[bold]Nota indicativa:[/] [{color}]{data['grade']} ({data['score']}/100)[/]",
        title="CrowService • Web Assessment",border_style="cyan"))
    if data.get("tls"):
        t=data["tls"]
        cert=Table(title="Certificado TLS",box=box.ROUNDED)
        cert.add_column("Campo",style="cyan"); cert.add_column("Valor",overflow="fold")
        for k,v in [
            ("Validado",t.get("tls_validated")),("Protocolo",t.get("tls_version")),
            ("Cipher",t.get("cipher")),("Autoridade/Issuer",t.get("issuer_authority") or t.get("issuer")),
            ("Válido até",t.get("not_after")),("Dias restantes",t.get("days_remaining")),
            ("Fingerprint SHA-256",t.get("sha256_fingerprint")),("SAN",", ".join(t.get("sans",[])))]:
            cert.add_row(k,str(v or "-"))
        console.print(cert)
        if t.get("tls_error"): console.print(f"[yellow]TLS: {t['tls_error']}[/]")
    h=Table(title="Cabeçalhos de segurança",box=box.ROUNDED)
    h.add_column("Cabeçalho"); h.add_column("Estado"); h.add_column("Valor",overflow="fold")
    for name,val in data.get("security_headers",{}).items():
        h.add_row(name,"[green]Presente[/]",str(val)[:180])
    for name in data.get("missing_security_headers",[]):
        h.add_row(name,"[yellow]Ausente[/]","-")
    console.print(h)
    if data.get("cookies"):
        c=Table(title="Cookies observados")
        for col in ("name","secure","httponly","samesite"): c.add_column(col)
        for cookie in data["cookies"]: c.add_row(*(str(cookie.get(k,"")) for k in ("name","secure","httponly","samesite")))
        console.print(c)
    if data.get("findings"):
        console.print("[bold]Observações:[/]")
        for item in data["findings"]: console.print(f" • {item}")
    jp,cp,digest=export_rows([data],"web_audit")
    console.print(f"[green]Banco SQLite atualizado.[/]\nJSON: {jp}\nCSV: {cp}\nSHA-256: {digest}")

def web_history():
    rows=recent_web_audits()
    t=Table(title="Histórico de auditorias web",box=box.ROUNDED)
    for col in ("id","created_utc","host","status_code","grade","score"): t.add_column(col)
    for r in rows: t.add_row(*(str(r.get(k) or "-") for k in ("id","created_utc","host","status_code","grade","score")))
    console.print(t if rows else "[yellow]Nenhuma auditoria web salva ainda.[/]")

def domain_audit_menu():
    while True:
        console.print(Panel(
            "[1] Avaliação HTTP/HTTPS, TLS, cabeçalhos e cookies\n"
            "[2] Interceptar requisições e respostas HTTPS (proxy local)\n"
            "[3] Histórico de auditorias web\n"
            "[4] Voltar",
            title="Auditoria de domínios", border_style="cyan", expand=True))
        op = Prompt.ask("Auditoria de domínios", choices=["1", "2", "3", "4"], default="4")
        if op == "1":
            run_web_audit_once()
        elif op == "2":
            https_proxy_menu()
        elif op == "3":
            web_history()
        else:
            break


def main():
    banner()
    while True:
        console.print(Panel(
          "[1] Análise TCP / fingerprint de serviços\n"
          "[2] Auditoria de domínios (HTTP, HTTPS, TLS, interceptação)\n"
          "[3] DNS lookup\n[4] WHOIS / RDAP\n[5] Banco SQLite / histórico\n"
          "[6] Exportar serviços de uma varredura\n[7] Histórico de auditorias web\n[8] Sair",
          title="MENU PRINCIPAL",border_style="cyan",expand=True))
        op=Prompt.ask("CrowService",choices=["1","2","3","4","5","6","7","8"],default="1")
        try:
            if op=="1": run_scan()
            elif op=="2": domain_audit_menu()
            elif op=="3": run_dns()
            elif op=="4": run_whois()
            elif op=="5": db_menu()
            elif op=="6":
                sid=int(Prompt.ask("ID da varredura"))
                rows=services_for_scan(sid)
                if not rows: console.print("[yellow]Nenhum serviço para esse ID.[/]")
                else:
                    jp,cp,d=export_rows(rows,f"scan_{sid}")
                    console.print(f"[green]{jp} | {cp}[/]\nSHA-256: {d}")
            elif op=="7": web_history()
            else: break
        except (ValueError,FileNotFoundError,OSError) as e:
            console.print(f"[red]Erro: {e}[/]")
        except Exception as e:
            console.print(f"[red]Operação não concluída: {type(e).__name__}: {e}[/]")
    console.print("[cyan]CrowService encerrado.[/]")
