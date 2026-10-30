import requests
from urllib.parse import quote

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def severity_from_score(score):
    if score is None: return "Sem classificação"
    if score >= 9.0: return "CRÍTICA"
    if score >= 7.0: return "ALTA"
    if score >= 4.0: return "MODERADA"
    if score > 0: return "BAIXA"
    return "INFORMATIVA"

def search_nvd(product, version="", limit=8, timeout=12):
    # Busca textual aproximada: não equivale a validação CPE.
    term=" ".join(x for x in (product,version) if x).strip()
    if not term: return {"query":term,"status":"skipped","items":[]}
    try:
        response=requests.get(NVD,params={"keywordSearch":term,"resultsPerPage":min(limit,20)},
                             headers={"User-Agent":"CrowService/2.0"},timeout=timeout)
        response.raise_for_status()
        data=response.json()
        items=[]
        for entry in data.get("vulnerabilities",[]):
            cve=entry.get("cve",{})
            metrics=cve.get("metrics",{})
            score=None; vector=""
            for metric_key in ("cvssMetricV40","cvssMetricV31","cvssMetricV30","cvssMetricV2"):
                vals=metrics.get(metric_key) or []
                if vals:
                    cv=vals[0].get("cvssData",{})
                    score=cv.get("baseScore"); vector=cv.get("vectorString","")
                    if score is not None: break
            desc=next((d.get("value","") for d in cve.get("descriptions",[]) if d.get("lang")=="en"),"")
            items.append({"cve_id":cve.get("id",""),"published":cve.get("published",""),
                          "last_modified":cve.get("lastModified",""),"cvss":score,
                          "severity":severity_from_score(score),"vector":vector,
                          "description":desc[:1200],"source":"NVD"})
        return {"query":term,"status":"ok","total":data.get("totalResults",0),"items":items}
    except Exception as e:
        return {"query":term,"status":"unavailable","error":type(e).__name__,"items":[]}
