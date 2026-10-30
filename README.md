# CrowService v1.0.0

**Autor:** augustodev-cyber  
**GitHub:** https://github.com/augustodev-cyber  
**Tipo:** inventário técnico, triagem de exposição e coleta forense não intrusiva.

CrowService ajuda equipes a documentar serviços expostos em ativos autorizados, registrar evidências e priorizar revisões. Não explora vulnerabilidades, não executa brute force, não tenta credenciais e não realiza evasão.

## Instalação (sem venv)
```bash
chmod +x install.sh
./install.sh
python3 main.py
```
O instalador usa `pip3 --break-system-packages`, conforme solicitado. Isso pode conflitar com pacotes Python gerenciados pelo Linux; prefira uma VM de laboratório.

## Auditoria web (domínios e sites)
- Aceita domínio simples ou URL `http://` / `https://`.
- Verifica resposta HTTP, código, motivo, latência, destino final e cadeia de redirecionamento.
- Coleta cabeçalhos declarados, servidor, X-Powered-By, tipo e tamanho reportado.
- Verifica presença de HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP e CORP.
- Lista cookies observados e flags Secure, HttpOnly e SameSite quando disponíveis.
- Para HTTPS, coleta protocolo TLS, cipher, subject, issuer/autoridade, validade, SAN e fingerprint SHA-256.
- Guarda resultado no SQLite e exporta JSON/CSV.

A nota web é uma checklist indicativa de configuração observável, não um selo, pentest ou prova de que o site é seguro/vulnerável. Cabeçalhos ausentes podem ser intencionais ou compensados por outros controles. Tecnologias e versões só são exibidas quando declaradas/identificáveis; não há fingerprint invasivo.

## Funções
- Alvo único ou importação de wordlist `.txt` de IPs/hostnames.
- Portas TCP configuráveis por wordlist.
- Banner grabbing limitado e identificação heurística de serviços.
- Coleta HTTP HEAD e metadados TLS com validação padrão de certificado.
- DNS A/AAAA/CNAME/MX/NS/TXT/PTR.
- WHOIS/RDAP para domínio ou IP.
- Consulta opcional à API pública NVD para CVEs por produto/versão identificados.
- Avaliação de triagem (informativa/baixa/moderada/alta/crítica) baseada em CVSS conhecido; ausência de CVE retornada não prova que o serviço é seguro.
- Banco SQLite local: ativos, serviços, execuções, CVEs, DNS e WHOIS.
- Menu para consultar histórico e tabelas; exportação JSON/CSV.
- Hash SHA-256 dos arquivos de evidência exportados.

## Uso
1. Edite `lists/port_list.txt` e, se quiser, `lists/ip_list.txt`.
2. Abra o programa.
3. Escolha análise de alvo único ou importação da lista.
4. Consulte o histórico no menu **Banco de dados**.

## CVEs: limitações importantes
O CrowService tenta inferir produto/versão por banners e metadados. Essa inferência pode estar errada, incompleta ou ser falsificada. A consulta NVD é uma busca textual aproximada, não uma correspondência CPE garantida. CVEs encontrados exigem validação manual de produto, versão, configuração, backports e exposição real. CVEs não encontrados não significam ausência de vulnerabilidades. A severidade exibida é a maior pontuação CVSS devolvida pela NVD, não um veredito de comprometimento.

A consulta NVD exige internet. Se a API estiver indisponível, a varredura e o armazenamento local continuam funcionando.

## Escopo e segurança
Execute somente em redes e sistemas próprios ou com autorização explícita. Use limites conservadores, janela de manutenção e listas de escopo. O scanner realiza conexões TCP convencionais e requisições HTTP HEAD. Não faz exploração, fuzzing, DoS, enumeração de contas ou tentativa de senhas.

## Banco
O arquivo `results/crowservice.db` é criado automaticamente. Faça backup antes de remover ou compartilhar. Não armazene segredos ou dados pessoais desnecessários.

## Interceptação HTTP/HTTPS (proxy local)
Dentro de **Auditoria de domínios**, a opção **Interceptar requisições e respostas HTTPS** inicia o `mitmweb`, com interface web local. Recursos disponíveis no painel incluem visualização de fluxos, inspeção de headers e corpos, filtros, edição de requests/responses, replay e histórico da sessão.

1. Informe somente domínios próprios ou explicitamente autorizados. O CrowService exige uma lista de escopo e passa esses hosts ao filtro `--allow-hosts` do mitmproxy; hosts fora da lista não têm TLS descriptografado.
2. Configure o navegador/dispositivo de laboratório para usar `127.0.0.1:8080` como proxy HTTP e HTTPS (ou as portas escolhidas).
3. Importe manualmente o certificado público `~/.mitmproxy/mitmproxy-ca-cert.pem` na lista de CAs confiáveis do navegador/dispositivo de teste; o mitmproxy cria esse certificado no primeiro início. A interface de fluxos fica em `http://127.0.0.1:8081` (ou porta escolhida).
4. Ao concluir, pare o proxy e remova a CA do cliente de teste. Os arquivos `mitmproxy-ca.pem` e a chave privada em `~/.mitmproxy/` são sensíveis e nunca devem ser compartilhados; importe apenas o certificado público `mitmproxy-ca-cert.pem`.

Por segurança, o listener do proxy e a interface web ficam vinculados a `127.0.0.1`, não à rede inteira. Certificate pinning, aplicativos com trust store próprio e alguns protocolos podem impedir a inspeção. Não use para interceptar tráfego de terceiros ou dispositivos sem consentimento.
