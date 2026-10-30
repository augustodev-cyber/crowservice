"""Scoped local HTTPS inspection proxy powered by mitmproxy/mitmweb.

Only intercept traffic for explicitly supplied, authorized hostnames. The
proxy and its web interface bind to loopback by default.
"""
import re
import shutil
import subprocess
import time
from pathlib import Path

_PROCESS = None


def _normalize_domains(raw):
    domains = []
    for item in raw.split(","):
        host = item.strip().lower().rstrip(".")
        if not host:
            continue
        if host.startswith("*."):
            host = host[2:]
        if len(host) > 253 or not re.fullmatch(r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host):
            raise ValueError(f"Domínio inválido: {item.strip()}")
        if ".." in host:
            raise ValueError(f"Domínio inválido: {item.strip()}")
        if host not in domains:
            domains.append(host)
    if not domains:
        raise ValueError("Informe ao menos um domínio autorizado.")
    return domains


def start_proxy(raw_domains, proxy_port=8080, web_port=8081):
    global _PROCESS
    if _PROCESS is not None and _PROCESS.poll() is None:
        raise RuntimeError("O proxy já está em execução nesta sessão.")
    binary = shutil.which("mitmweb")
    if not binary:
        raise RuntimeError("mitmweb não encontrado. Instale com: pip install -r requirements.txt")
    domains = _normalize_domains(raw_domains)
    if proxy_port == web_port or not (1024 <= proxy_port <= 65535 and 1024 <= web_port <= 65535):
        raise ValueError("Use portas distintas entre 1024 e 65535.")

    # mitmproxy --allow-hosts only performs TLS interception for these hosts;
    # other destinations are not decrypted. Include exact host + subdomains.
    patterns = [rf"(^|\.){re.escape(host)}$" for host in domains]
    allow_hosts = "|".join(patterns)
    command = [
        binary,
        "--listen-host", "127.0.0.1", "--listen-port", str(proxy_port),
        "--web-host", "127.0.0.1", "--web-port", str(web_port),
        "--set", "web_open_browser=false",
        "--allow-hosts", allow_hosts,
    ]
    log_dir = Path("results")
    log_dir.mkdir(parents=True, exist_ok=True)
    log = open(log_dir / "https_proxy.log", "a", encoding="utf-8")
    try:
        _PROCESS = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                     stdin=subprocess.DEVNULL, start_new_session=True)
    except Exception:
        log.close()
        raise
    time.sleep(1.0)
    if _PROCESS.poll() is not None:
        log.close()
        _PROCESS = None
        raise RuntimeError("mitmweb encerrou ao iniciar. Consulte results/https_proxy.log.")
    return {"domains": domains, "proxy": f"127.0.0.1:{proxy_port}",
            "web": f"http://127.0.0.1:{web_port}", "pid": _PROCESS.pid}


def proxy_status():
    if _PROCESS is None:
        return "Não iniciado por esta sessão."
    code = _PROCESS.poll()
    return f"Em execução (PID {_PROCESS.pid})." if code is None else f"Encerrado (código {code})."


def stop_proxy():
    global _PROCESS
    if _PROCESS is None or _PROCESS.poll() is not None:
        _PROCESS = None
        return False
    _PROCESS.terminate()
    try:
        _PROCESS.wait(timeout=5)
    except subprocess.TimeoutExpired:
        _PROCESS.kill()
        _PROCESS.wait(timeout=3)
    _PROCESS = None
    return True
