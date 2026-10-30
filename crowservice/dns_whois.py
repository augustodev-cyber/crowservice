import socket
import dns.resolver
import dns.reversename

def dns_lookup(domain, timeout=3):
    out={"domain":domain,"records":{},"errors":{}}
    r=dns.resolver.Resolver(); r.timeout=timeout; r.lifetime=timeout
    for kind in ("A","AAAA","CNAME","MX","NS","TXT","SOA"):
        try: out["records"][kind]=[str(x).strip('"') for x in r.resolve(domain,kind)]
        except Exception as e: out["records"][kind]=[]; out["errors"][kind]=type(e).__name__
    return out

def ptr_lookup(ip, timeout=3):
    try:
        rev=dns.reversename.from_address(ip)
        return [str(x).rstrip(".") for x in dns.resolver.resolve(rev,"PTR",lifetime=timeout)]
    except Exception:
        return []

def whois_lookup(value):
    import ipaddress
    try:
        ipaddress.ip_address(value)
        from ipwhois import IPWhois
        d=IPWhois(value).lookup_rdap(depth=1)
        n=d.get("network") or {}
        return {"query":value,"type":"IP/RDAP","asn":d.get("asn"),"asn_description":d.get("asn_description"),
                "country":n.get("country"),"network_name":n.get("name"),"cidr":n.get("cidr"),
                "handle":n.get("handle")}
    except ValueError:
        import whois
        w=whois.whois(value)
        def clean(v): return str(v)[:1000] if v else ""
        return {"query":value,"type":"DOMAIN/WHOIS","registrar":clean(w.registrar),
                "creation_date":clean(w.creation_date),"expiration_date":clean(w.expiration_date),
                "name_servers":clean(w.name_servers),"status":clean(w.status)}
