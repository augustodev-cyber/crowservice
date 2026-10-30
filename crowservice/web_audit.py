import socket, ssl, hashlib
from urllib.parse import urlparse
import requests

SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS", "Ajuda a impor HTTPS em acessos futuros."),
    "content-security-policy": ("CSP", "Restringe origens de conteúdo carregável."),
    "x-content-type-options": ("MIME nosniff", "Reduz interpretação MIME indevida."),
    "x-frame-options": ("Frame protection", "Ajuda a mitigar clickjacking em navegadores antigos."),
    "referrer-policy": ("Referrer Policy", "Controla informações enviadas no Referer."),
    "permissions-policy": ("Permissions Policy", "Limita recursos do navegador."),
    "cross-origin-opener-policy": ("COOP", "Isola contextos de navegação quando configurado."),
    "cross-origin-resource-policy": ("CORP", "Controla carregamento cross-origin de recursos.")
}

def normalize_url(value):
    value=value.strip()
    if not value: raise ValueError("Informe um domínio ou URL.")
    if "://" not in value: value="https://"+value
    parsed=urlparse(value)
    if parsed.scheme not in ("http","https") or not parsed.hostname:
        raise ValueError("URL inválida. Use domínio, http:// ou https://.")
    if parsed.username or parsed.password:
        raise ValueError("URLs com credenciais embutidas não são aceitas.")
    return value

def tls_details(host, port, timeout):
    out={"tls_validated":False,"tls_version":"","cipher":"","subject":"","issuer":"",
         "issuer_authority":"","not_before":"","not_after":"","days_remaining":None,
         "sans":[],"sha256_fingerprint":"","tls_error":""}
    try:
        ctx=ssl.create_default_context()
        with socket.create_connection((host,port),timeout=timeout) as raw:
            with ctx.wrap_socket(raw,server_hostname=host) as s:
                cert=s.getpeercert()
                der=s.getpeercert(binary_form=True)
                out.update({
                    "tls_validated":True,"tls_version":s.version() or "",
                    "cipher":str(s.cipher()),
                    "subject":str(cert.get("subject",""))[:700],
                    "issuer":str(cert.get("issuer",""))[:700],
                    "not_before":cert.get("notBefore",""),
                    "not_after":cert.get("notAfter",""),
                    "sans":[v for k,v in cert.get("subjectAltName",[]) if k=="DNS"][:100],
                    "sha256_fingerprint":hashlib.sha256(der).hexdigest()
                })
                # Parse OpenSSL-style certificate date into remaining days.
                from datetime import datetime, timezone
                if out["not_after"]:
                    exp=datetime.strptime(out["not_after"],"%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    out["days_remaining"]=(exp-datetime.now(timezone.utc)).days
                issuer=cert.get("issuer",[])
                out["issuer_authority"]=", ".join("=".join(x) for group in issuer for x in group)
    except Exception as e:
        out["tls_error"]=type(e).__name__
    return out

def audit_site(value, timeout=8):
    url=normalize_url(value)
    parsed=urlparse(url)
    host=parsed.hostname
    port=parsed.port or (443 if parsed.scheme=="https" else 80)
    result={
        "input":value,"url":url,"host":host,"scheme":parsed.scheme,"port":port,
        "reachable":False,"final_url":"","status_code":None,"reason":"",
        "redirect_count":0,"redirect_chain":[],"response_time_ms":None,
        "server":"","powered_by":"","content_type":"","content_length":"",
        "headers":{},"security_headers":{},"missing_security_headers":[],
        "cookies":[],"tls":{},"findings":[],"grade":"INDETERMINADO","score":None
    }
    try:
        import time
        start=time.perf_counter()
        response=requests.get(url,timeout=timeout,allow_redirects=True,
            headers={"User-Agent":"CrowService/2.1 (authorized web security inventory)"},
            stream=True)
        result["response_time_ms"]=round((time.perf_counter()-start)*1000,2)
        result["reachable"]=True
        result["final_url"]=response.url
        result["status_code"]=response.status_code
        result["reason"]=response.reason
        result["redirect_count"]=len(response.history)
        result["redirect_chain"]=[{"status":r.status_code,"url":r.url,"location":r.headers.get("Location","")} for r in response.history]
        h={k.lower():v for k,v in response.headers.items()}
        result["headers"]=dict(response.headers)
        result["server"]=h.get("server","")
        result["powered_by"]=h.get("x-powered-by","")
        result["content_type"]=h.get("content-type","")
        result["content_length"]=h.get("content-length","")
        for key,(label,description) in SECURITY_HEADERS.items():
            if key in h: result["security_headers"][label]=h[key]
            else: result["missing_security_headers"].append(label)
        # Do not consume page bodies; inspect only response metadata and cookies.
        for c in response.cookies:
            result["cookies"].append({
                "name":c.name,"secure":bool(c.secure),
                "httponly":bool(c.has_nonstandard_attr("HttpOnly") or "httponly" in str(c).lower()),
                "samesite":c.get_nonstandard_attr("SameSite") or ""
            })
        response.close()
    except requests.RequestException as e:
        result["findings"].append("Falha de conexão HTTP: "+type(e).__name__)

    if parsed.scheme=="https":
        result["tls"]=tls_details(host,port,timeout)
    else:
        result["findings"].append("A URL inicial usa HTTP sem criptografia.")

    # Score is a transparent checklist, not a certification or penetration-test verdict.
    score=100
    if parsed.scheme!="https": score-=35
    if not result["reachable"]: score-=20
    if parsed.scheme=="https" and not result["tls"].get("tls_validated"): score-=35
    if parsed.scheme=="https" and result["tls"].get("days_remaining") is not None and result["tls"]["days_remaining"]<0:
        score-=40; result["findings"].append("Certificado TLS expirado.")
    elif parsed.scheme=="https" and result["tls"].get("days_remaining") is not None and result["tls"]["days_remaining"]<21:
        score-=15; result["findings"].append("Certificado TLS expira em menos de 21 dias.")
    if parsed.scheme=="https" and "HSTS" in result["missing_security_headers"]: score-=8
    for key in ("CSP","MIME nosniff","Frame protection","Referrer Policy"):
        if key in result["missing_security_headers"]: score-=4
    if parsed.scheme=="http" and result["final_url"].startswith("https://"):
        result["findings"].append("O site redireciona HTTP para HTTPS.")
    if result["status_code"] in (401,403):
        result["findings"].append("A página respondeu com controle de acesso (401/403); não é evidência de falha.")
    result["score"]=max(0,min(100,score))
    result["grade"]="BOM" if score>=85 else "MODERADO" if score>=65 else "ATENÇÃO" if score>=40 else "FRACO"
    result["findings"].append("A pontuação é uma triagem baseada em sinais observáveis, não certificação de segurança.")
    return result
