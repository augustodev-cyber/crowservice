from pathlib import Path
import ipaddress

def read_wordlist(path):
    p = Path(path).expanduser()
    if not p.is_file():
        raise FileNotFoundError(f"Wordlist não encontrada: {p}")
    items = []
    for raw in p.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        value = raw.split("#", 1)[0].strip()
        if value:
            items.append(value)
    return list(dict.fromkeys(items))

def validate_target(value):
    value = value.strip()
    if not value or any(ch.isspace() for ch in value):
        raise ValueError("Alvo vazio ou inválido.")
    if len(value) > 253:
        raise ValueError("Alvo excede o tamanho permitido.")
    return value

def load_ports(path, max_count=512):
    values = read_wordlist(path)
    ports = sorted({int(x) for x in values if x.isdigit() and 1 <= int(x) <= 65535})
    if not ports:
        raise ValueError("Nenhuma porta TCP válida na wordlist.")
    if len(ports) > max_count:
        raise ValueError(f"Wordlist contém {len(ports)} portas; limite configurado: {max_count}.")
    return ports
