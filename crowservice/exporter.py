import json,csv,hashlib
from pathlib import Path
from datetime import datetime,timezone

def export_rows(rows,prefix):
    out=Path("results"); out.mkdir(exist_ok=True)
    stamp=datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    jp=out/f"{prefix}_{stamp}.json"; cp=out/f"{prefix}_{stamp}.csv"
    jp.write_text(json.dumps(rows,indent=2,ensure_ascii=False),encoding="utf-8")
    if rows:
        keys=list(dict.fromkeys(k for row in rows for k in row.keys()))
        with cp.open("w",newline="",encoding="utf-8") as f:
            w=csv.DictWriter(f,fieldnames=keys,extrasaction="ignore"); w.writeheader(); w.writerows(rows)
    else: cp.write_text("",encoding="utf-8")
    digest=hashlib.sha256(jp.read_bytes()).hexdigest()
    (out/(jp.name+".sha256")).write_text(f"{digest}  {jp.name}\n",encoding="utf-8")
    return str(jp),str(cp),digest
