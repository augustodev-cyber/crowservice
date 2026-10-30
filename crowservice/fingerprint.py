import re
import socket
import ssl
import http.client
import platform
from datetime import datetime, timezone

PORT_HINTS = {
  21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",
  111:"RPCbind",135:"MS RPC",139:"NetBIOS",143:"IMAP",389:"LDAP",
  443:"HTTPS",445:"SMB",465:"SMTPS",587:"SMTP Submission",636:"LDAPS",
  993:"IMAPS",995:"POP3S",1433:"MS SQL",1521:"Oracle DB",2049:"NFS",
  3306:"MySQL",3389:"RDP",5432:"PostgreSQL",5900:"VNC",5985:"WinRM HTTP",
  5986:"WinRM HTTPS",6379:"Redis",8080:"HTTP Alternate",8443:"HTTPS Alternate",
  9200:"Elasticsearch"
}

def _recv_banner(sock, limit=1024):
    try:
        data = sock.recv(limit)
        return data.decode("utf-8", errors="replace").strip()[:500]
    except (OSError, socket.timeout):
        return ""

def _http_probe(host, port, timeout, tls):
    out = {}
    try:
        if tls:
            ctx = ssl.create_default_context()
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("HEAD", "/", headers={"User-Agent":"CrowService/2.0"})
        res = conn.getresponse()
        out = {"http_status": res.status, "http_reason": res.reason,
               "http_server": res.getheader("Server", ""),
               "http_powered_by": res.getheader("X-Powered-By", "")}
        conn.close()
    except Exception:
        pass
    return out

def _tls_probe(host, port, timeout):
    out = {}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                cert = s.getpeercert()
                out = {
                    "tls_version": s.version() or "",
                    "tls_cipher": str(s.cipher()),
                    "tls_subject": str(cert.get("subject", ""))[:400],
                    "tls_issuer": str(cert.get("issuer", ""))[:400],
                    "tls_not_after": cert.get("notAfter", ""),
                    "tls_san": ", ".join(v for k,v in cert.get("subjectAltName",[]) if k=="DNS")[:800]
                }
    except Exception as e:
        out["tls_error"] = type(e).__name__
    return out

def classify_os_hint(ttl):
    if ttl is None: return "Não identificado"
    if ttl <= 64: return "Possível Unix/Linux (heurística TTL)"
    if ttl <= 128: return "Possível Windows (heurística TTL)"
    return "TTL elevado/roteado; inconclusivo"

def scan_port(host, port, timeout, cfg):
    row = {
      "host":host, "port":port, "state":"closed", "service":PORT_HINTS.get(port,"unknown"),
      "banner":"", "product":"", "version":"", "os_hint":"Não identificado",
      "http_status":None, "http_reason":"", "http_server":"", "http_powered_by":"",
      "tls_version":"", "tls_cipher":"", "tls_subject":"", "tls_issuer":"",
      "tls_not_after":"", "tls_san":"", "tls_error":"", "error":""
    }
    try:
        with socket.create_connection((host,port),timeout=timeout) as s:
            row["state"]="open"
            s.settimeout(min(timeout,1.0))
            row["banner"]=_recv_banner(s)
    except socket.timeout:
        row["error"]="timeout"
        return row
    except OSError as e:
        row["error"]=type(e).__name__
        return row

    # Identificação conservadora a partir de banners evidentes.
    b=row["banner"]
    patterns=[
      (r"OpenSSH[_ ]?([\d.pA-Za-z-]+)","OpenSSH"),
      (r"SSH-2\.0-([^\s]+)","SSH server"),
      (r"^220[- ].*(Postfix|Exim|Microsoft ESMTP|Sendmail)[^\r\n]*","SMTP server"),
      (r"^220[- ].*","SMTP server"),
      (r"FTP server.*","FTP server")
    ]
    for pattern, product in patterns:
        m=re.search(pattern,b,re.I)
        if m:
            row["product"]=product
            row["version"]=m.group(1) if m.lastindex else ""
            break

    if port in cfg.get("http_ports",[]):
        row.update(_http_probe(host,port,timeout,False))
        if row["http_server"] and not row["product"]:
            row["product"]=row["http_server"]
    if port in cfg.get("tls_ports",[]):
        row.update(_tls_probe(host,port,timeout))
        if port in (443,8443) and not row["http_status"]:
            row.update(_http_probe(host,port,timeout,True))
    return row

def host_metadata(host, timeout):
    import socket
    result={"host":host,"resolved_ips":[],"reverse_dns":"","ttl_os_hint":"Não identificado"}
    try:
        infos=socket.getaddrinfo(host,None)
        result["resolved_ips"]=sorted({x[4][0] for x in infos})
    except OSError:
        pass
    try:
        result["reverse_dns"]=socket.gethostbyaddr(host)[0]
    except OSError:
        pass
    # A fingerprint do SO por TTL exigiria ICMP raw; não é inferida sem evidência.
    return result
