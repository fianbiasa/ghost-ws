import asyncio, os, sys, socket, ssl, requests, urllib3, subprocess, platform, re, uuid, json, argparse
from datetime import datetime
from urllib.parse import urlparse, urljoin
try:
    from bs4 import BeautifulSoup
except ImportError:
    print("\033[1;31m[!] Modul 'bs4' belum terinstal. Jalankan: pip install beautifulsoup4\033[0m")
    sys.exit()


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


RED, GREEN, YELLOW, BLUE, CYAN, WHITE, RESET, BOLD = "\033[1;31m", "\033[1;32m", "\033[1;33m", "\033[1;34m", "\033[1;36m", "\033[1;37m", "\033[0m", "\033[1m"
ORANGE = "\033[1;33m"

class GhostHunterV47:
    def __init__(self):
        self.target, self.domain, self.target_ip = "", "", "Detecting..."
        self.session = requests.Session()
        self.timeout = 7 
        self.max_concurrency = 8
        self.retry_count = 2
        self.backoff_base = 0.35
        self._semaphore = asyncio.Semaphore(self.max_concurrency)
        self.scan_queue = [] 
        self.vuln_log = []
        self.subdomains_found = []
        self.forms_found = []
        self.findings = []
        self._finding_keys = set()
        self.request_errors = []
        self.verify_tls = True
        self.scan_mode = "normal"
        self.min_severity = "LOW"

        self.tech_stack = []
        self.firewall = "Not Detected / Unknown"
        self.server_loc = "Unknown"
        self.header_issues = []
        self.cookie_issues = []
        self.tls_info = {}
        self.endpoint_notes = []

    def set_scan_mode(self, mode):
        profile = {
            "cepat": {"timeout": 4, "retry": 1, "backoff": 0.2, "concurrency": 12},
            "normal": {"timeout": 7, "retry": 2, "backoff": 0.35, "concurrency": 8},
            "agresif": {"timeout": 12, "retry": 3, "backoff": 0.6, "concurrency": 4},
        }
        if mode not in profile:
            mode = "normal"
        cfg = profile[mode]
        self.scan_mode = mode
        self.timeout = cfg["timeout"]
        self.retry_count = cfg["retry"]
        self.backoff_base = cfg["backoff"]
        self.max_concurrency = cfg["concurrency"]
        self._semaphore = asyncio.Semaphore(self.max_concurrency)

    def strip_ansi(self, text):
        return re.sub(r"\x1B\[[0-?]*[ -/]*[@-~]", "", str(text))

    def _tls_probe_sync(self, host, port):
        context = ssl.create_default_context() if self.verify_tls else ssl._create_unverified_context()
        with socket.create_connection((host, port), timeout=self.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return {
                    "tls_version": ssock.version(),
                    "cipher": ssock.cipher()[0] if ssock.cipher() else "Unknown",
                    "cert": cert,
                }

    def add_finding(self, category, severity, confidence, target, evidence):
        key = (category, target, evidence)
        if key in self._finding_keys:
            return
        self._finding_keys.add(key)
        finding = {
            "category": category,
            "severity": severity,
            "confidence": confidence,
            "target": target,
            "evidence": evidence,
        }
        self.findings.append(finding)
        self.vuln_log.append(f"[{severity}/{confidence}] {category}: {target} | {evidence}")

    def risk_score(self):
        sev_weight = {"CRITICAL": 35, "HIGH": 25, "MEDIUM": 12, "LOW": 5, "INFO": 1}
        conf_weight = {"HIGH": 1.0, "MEDIUM": 0.65, "LOW": 0.35}
        score = 0.0
        for f in self.findings:
            score += sev_weight.get(f["severity"], 0) * conf_weight.get(f["confidence"], 0)
        return min(int(score), 100)

    def severity_rank(self, sev):
        ranks = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        return ranks.get((sev or "").upper(), 1)

    def set_min_severity(self, sev):
        valid = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
        sev = (sev or "LOW").upper()
        self.min_severity = sev if sev in valid else "LOW"

    def filtered_findings(self):
        min_rank = self.severity_rank(self.min_severity)
        return [f for f in self.findings if self.severity_rank(f["severity"]) >= min_rank]

    def risk_level(self, score):
        if score >= 70:
            return f"{RED}HIGH{RESET}"
        if score >= 35:
            return f"{YELLOW}MEDIUM{RESET}"
        return f"{GREEN}LOW{RESET}"

    def get_sys_info(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
        except Exception: ip = "Disconnected"
        
        if os.path.exists("/system/build.prop"):
            model = subprocess.getoutput("getprop ro.product.model") or "Android"
        else:
            model = platform.node() or "Linux"
            
        batt = "N/A"
        if subprocess.call("command -v termux-battery-status", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
            try:
                batt_raw = subprocess.getoutput("termux-battery-status")
                batt = re.search(r'"percentage":\s*(\d+)', batt_raw).group(1) + "%"
            except Exception: pass
        return ip, model, batt

    def banner(self):
        os.system("clear" if os.name == "posix" else "cls")
        ip_addr, model_dev, battery = self.get_sys_info()
        print(f"{RED}{BOLD}    _____ _    _  ____   _____ _______ {RESET}")
        print(f"{RED}{BOLD}   / ____| |  | |/ __ \\ / ____|__   __|{RESET}")
        print(f"{RED}{BOLD}  | |  __| |__| | |  | | (___    | |   {RESET}")
        print(f"{RED}{BOLD}  | | |_ |  __  | |  | |\\___ \\   | |   {RESET}")
        print(f"{RED}{BOLD}  | |__| | |  | | |__| |____) |  | |   {RESET}")
        print(f"{RED}{BOLD}   \\_____|_|  |_|\\____/|_____/   |_|   {RESET}")
        print(f"{CYAN}GHOST WEB SCANNER{RESET}")
        print(f"{GREEN}----------------------------------------{RESET}")
        print(f"{BLUE}Tool Name : {RED}Ghost Web Scanner{RESET}")
        print(f"{BLUE}Engine    : {GREEN}Heuristic Security Audit{RESET}")
        print(f"{BLUE}Author    : {RED}Zulfianto{RESET}")
        print(f"{YELLOW}[github.com/fianbiasa/ghost-ws]{RESET}")
        print(f"{GREEN}----------------------------------------{RESET}")
        print(f"{BLUE}USER   : {RED}Ghost (Root){RESET}")
        print(f"{BLUE}OS     : {GREEN}{model_dev[:15]}{RESET} ({battery})")
        print(f"{BLUE}TARGET : {ORANGE}{self.domain if self.domain else 'Ready'}{RESET}")
        print(f"{BLUE}IP TGT : {YELLOW}{self.target_ip}{RESET}")
        print(f"{BLUE}[ {ORANGE}KALI LINUX {WHITE}| {BLUE}TERMUX {WHITE}| {CYAN}PRO MODE {BLUE}]{RESET}")
        print(f"{GREEN}========================================================{RESET}")

    async def sync_bar(self, duration, label, task):
        steps = 20
        for i in range(steps + 1):
            if task.done(): break
            percent = (i / steps) * 100
            bar = f"{CYAN}█{RESET}" * i + f"{WHITE}-{RESET}" * (steps - i)
            sys.stdout.write(f"\r    {WHITE}[{label}] [{percent:3.0f}%] [{bar}] {RESET}")
            sys.stdout.flush()
            await asyncio.sleep(duration / steps)
        res = await task
        sys.stdout.write(f"\r    {WHITE}[{label}] [100%] [{GREEN}{'█' * steps}{RESET}] {RESET}\n")
        return res

    async def fetch(self, url, params=None, method="GET", headers=None):
        loop = asyncio.get_running_loop()
        async with self._semaphore:
            for attempt in range(self.retry_count + 1):
                try:
                    return await loop.run_in_executor(
                        None,
                        lambda: self.session.request(
                            method=method,
                            url=url,
                            params=params,
                            headers=headers,
                            timeout=self.timeout,
                            verify=self.verify_tls,
                            allow_redirects=True,
                        ),
                    )
                except Exception as e:
                    if attempt < self.retry_count:
                        await asyncio.sleep(self.backoff_base * (2 ** attempt))
                        continue
                    if len(self.request_errors) < 15:
                        self.request_errors.append(f"{url} -> {e}")
                    return None

    def export_json_report(self, score):
        safe_domain = re.sub(r"[^a-zA-Z0-9._-]", "_", self.domain or "unknown")
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%SZ")
        os.makedirs("reports", exist_ok=True)
        out_path = os.path.join("reports", f"scan_{safe_domain}_{ts}.json")

        selected_findings = self.filtered_findings()
        findings = []
        for f in selected_findings:
            findings.append(
                {
                    "category": f["category"],
                    "severity": f["severity"],
                    "confidence": f["confidence"],
                    "target": f["target"],
                    "evidence": self.strip_ansi(f["evidence"]),
                }
            )

        report = {
            "tool": "Ghost Web Scanner",
            "version": "gws.py",
            "generated_at_utc": datetime.utcnow().isoformat() + "Z",
            "target": {
                "url": self.target,
                "domain": self.domain,
                "ip": self.target_ip,
                "server_location": self.server_loc,
                "firewall": self.firewall,
                "tls": self.tls_info,
            },
            "settings": {
                "timeout_seconds": self.timeout,
                "max_concurrency": self.max_concurrency,
                "retry_count": self.retry_count,
                "backoff_base": self.backoff_base,
                "verify_tls": self.verify_tls,
                "min_severity": self.min_severity,
            },
            "summary": {
                "risk_score": score,
                "total_findings": len(selected_findings),
                "total_findings_all": len(self.findings),
                "subdomains_found": len(self.subdomains_found),
                "forms_found": len(self.forms_found),
                "request_warnings": len(self.request_errors),
            },
            "web_technologies": [self.strip_ansi(t) for t in self.tech_stack],
            "subdomains": [self.strip_ansi(s) for s in self.subdomains_found],
            "forms": [self.strip_ansi(f) for f in self.forms_found],
            "findings": findings,
            "endpoint_notes": [self.strip_ansi(n) for n in self.endpoint_notes],
            "request_warnings": [self.strip_ansi(e) for e in self.request_errors],
            "notes": [
                "Heuristic scan only. Findings require manual validation for exploitability.",
                "Use only on targets you are authorized to test.",
            ],
        }

        with open(out_path, "w", encoding="utf-8") as fp:
            json.dump(report, fp, indent=2)
        return out_path

    def export_sarif_report(self):
        safe_domain = re.sub(r"[^a-zA-Z0-9._-]", "_", self.domain or "unknown")
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%SZ")
        os.makedirs("reports", exist_ok=True)
        out_path = os.path.join("reports", f"scan_{safe_domain}_{ts}.sarif")

        rules = {}
        level_map = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}

        selected_findings = self.filtered_findings()

        for f in selected_findings:
            rid = f"GWS-{re.sub(r'[^A-Z0-9]+', '-', f['category'].upper()).strip('-')}"
            if rid not in rules:
                rules[rid] = {
                    "id": rid,
                    "name": f["category"],
                    "shortDescription": {"text": f["category"]},
                    "help": {"text": f["evidence"]},
                    "properties": {"severity": f["severity"], "confidence": f["confidence"]},
                }

        results = []
        for f in selected_findings:
            rid = f"GWS-{re.sub(r'[^A-Z0-9]+', '-', f['category'].upper()).strip('-')}"
            results.append(
                {
                    "ruleId": rid,
                    "level": level_map.get(f["severity"], "note"),
                    "message": {
                        "text": f"[{f['severity']}/{f['confidence']}] {f['category']} on {f['target']} | {self.strip_ansi(f['evidence'])}"
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": self.target or "target"},
                                "region": {"startLine": 1},
                            }
                        }
                    ],
                }
            )

        sarif_doc = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Ghost Web Scanner",
                            "version": "gws.py",
                            "informationUri": "https://github.com/fianbiasa/ghost-ws",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }

        with open(out_path, "w", encoding="utf-8") as fp:
            json.dump(sarif_doc, fp, indent=2)
        return out_path


    async def get_target_intel(self):
        print(f"\n{YELLOW}[*] PHASE 0.1: EXTRACTING TARGET INTELLIGENCE...{RESET}")
        try:

            loc_req = requests.get(f"http://ip-api.com/json/{self.target_ip}", timeout=5).json()
            if loc_req.get('status') == 'success':
                self.server_loc = f"{loc_req.get('city')}, {loc_req.get('country')}"


            r = await self.fetch(self.target)
            if r:
                server = r.headers.get("Server", "Unknown")
                powered = r.headers.get("X-Powered-By", "Unknown")
                self.tech_stack.append(f"Server Type: {server}")
                if powered != "Unknown": self.tech_stack.append(f"Language: {powered}")
                
                # Deteksi Firewall Sederhana
                h_str = str(r.headers).lower()
                if "cloudflare" in h_str: self.firewall = "Cloudflare WAF"
                elif "mod_security" in h_str: self.firewall = "ModSecurity"
                elif "sucuri" in h_str: self.firewall = "Sucuri CloudProxy"
                elif "akamai" in h_str: self.firewall = "Akamai WAF"
        except: pass

    async def audit_security_headers(self):
        print(f"\n{YELLOW}[*] PHASE 0.3: SECURITY HEADER AUDIT...{RESET}")
        r = await self.fetch(self.target)
        if not r:
            return

        required = {
            "Content-Security-Policy": ("HIGH", "MEDIUM"),
            "Strict-Transport-Security": ("MEDIUM", "HIGH"),
            "X-Content-Type-Options": ("LOW", "HIGH"),
            "X-Frame-Options": ("MEDIUM", "HIGH"),
            "Referrer-Policy": ("LOW", "MEDIUM"),
            "Permissions-Policy": ("LOW", "LOW"),
        }

        for h_name, (sev, conf) in required.items():
            if h_name not in r.headers:
                self.header_issues.append(f"Missing {h_name}")
                self.add_finding(
                    "Missing Security Header",
                    sev,
                    conf,
                    self.target,
                    f"Header '{h_name}' not present",
                )

        xfo = r.headers.get("X-Frame-Options", "").upper()
        if xfo and xfo not in ["DENY", "SAMEORIGIN"]:
            self.add_finding(
                "Weak Clickjacking Protection",
                "MEDIUM",
                "MEDIUM",
                self.target,
                f"Unexpected X-Frame-Options value: {xfo}",
            )

        cto = r.headers.get("X-Content-Type-Options", "").lower()
        if cto and cto != "nosniff":
            self.add_finding(
                "Weak MIME Sniffing Protection",
                "LOW",
                "MEDIUM",
                self.target,
                f"Unexpected X-Content-Type-Options value: {cto}",
            )

        set_cookie = r.headers.get("Set-Cookie", "")
        if set_cookie:
            c = set_cookie.lower()
            if "secure" not in c:
                self.cookie_issues.append("Cookie missing Secure")
                self.add_finding(
                    "Insecure Cookie Flag",
                    "MEDIUM",
                    "MEDIUM",
                    self.target,
                    "Set-Cookie without Secure flag",
                )
            if "httponly" not in c:
                self.cookie_issues.append("Cookie missing HttpOnly")
                self.add_finding(
                    "Missing HttpOnly Cookie Flag",
                    "LOW",
                    "MEDIUM",
                    self.target,
                    "Set-Cookie without HttpOnly flag",
                )
            if "samesite" not in c:
                self.cookie_issues.append("Cookie missing SameSite")
                self.add_finding(
                    "Missing SameSite Cookie Flag",
                    "LOW",
                    "MEDIUM",
                    self.target,
                    "Set-Cookie without SameSite attribute",
                )

    async def audit_http_methods(self):
        print(f"\n{YELLOW}[*] PHASE 0.4: HTTP METHOD EXPOSURE CHECK...{RESET}")
        r = await self.fetch(self.target, method="OPTIONS")
        if not r:
            return

        allow = (r.headers.get("Allow", "") or "")
        if not allow:
            return

        methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
        risky = [m for m in methods if m in {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}]
        if risky:
            self.add_finding(
                "Risky HTTP Methods Exposed",
                "MEDIUM",
                "MEDIUM",
                self.target,
                f"Allow header exposes: {', '.join(risky)}",
            )

    async def audit_cors(self):
        print(f"\n{YELLOW}[*] PHASE 0.5: CORS POLICY CHECK...{RESET}")
        origin = "https://evil.example"
        r = await self.fetch(self.target, headers={"Origin": origin})
        if not r:
            return

        acao = (r.headers.get("Access-Control-Allow-Origin", "") or "").strip()
        acc = (r.headers.get("Access-Control-Allow-Credentials", "") or "").strip().lower()

        if acao == "*" and acc == "true":
            self.add_finding(
                "Dangerous CORS Configuration",
                "HIGH",
                "HIGH",
                self.target,
                "ACAO='*' with Access-Control-Allow-Credentials=true",
            )
        elif acao == "*":
            self.add_finding(
                "Permissive CORS Configuration",
                "MEDIUM",
                "MEDIUM",
                self.target,
                "Access-Control-Allow-Origin set to '*'",
            )
        elif acao == origin:
            self.add_finding(
                "Reflective CORS Origin",
                "MEDIUM",
                "MEDIUM",
                self.target,
                "Server reflects arbitrary Origin header",
            )

    async def audit_tls_certificate(self):
        print(f"\n{YELLOW}[*] PHASE 0.6: TLS CERTIFICATE CHECK...{RESET}")
        parsed = urlparse(self.target)
        if parsed.scheme != "https":
            self.endpoint_notes.append("Target uses HTTP (no TLS)")
            self.add_finding(
                "No TLS in Use",
                "MEDIUM",
                "HIGH",
                self.target,
                "Target URL is not HTTPS",
            )
            return

        host = parsed.hostname or self.domain
        port = parsed.port or 443
        try:
            loop = asyncio.get_running_loop()
            probe = await loop.run_in_executor(None, self._tls_probe_sync, host, port)
            cert = probe.get("cert", {})
            not_after = cert.get("notAfter")
            subject = cert.get("subject", ())
            issuer = cert.get("issuer", ())

            days_left = None
            if not_after:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (exp - datetime.utcnow()).days

            self.tls_info = {
                "host": host,
                "port": port,
                "tls_version": probe.get("tls_version", "Unknown"),
                "cipher": probe.get("cipher", "Unknown"),
                "days_to_expire": days_left,
                "subject": str(subject),
                "issuer": str(issuer),
            }

            if days_left is not None:
                if days_left < 0:
                    self.add_finding(
                        "Expired TLS Certificate",
                        "CRITICAL",
                        "HIGH",
                        self.target,
                        f"Certificate expired {abs(days_left)} days ago",
                    )
                elif days_left <= 15:
                    self.add_finding(
                        "TLS Certificate Near Expiry",
                        "HIGH",
                        "HIGH",
                        self.target,
                        f"Certificate expires in {days_left} days",
                    )
                elif days_left <= 45:
                    self.add_finding(
                        "TLS Certificate Expiry Warning",
                        "MEDIUM",
                        "MEDIUM",
                        self.target,
                        f"Certificate expires in {days_left} days",
                    )

            tls_ver = (probe.get("tls_version") or "").upper()
            if tls_ver in {"TLSV1", "TLSV1.1"}:
                self.add_finding(
                    "Legacy TLS Version",
                    "HIGH",
                    "HIGH",
                    self.target,
                    f"Negotiated deprecated protocol: {probe.get('tls_version')}",
                )

            if subject and issuer and str(subject) == str(issuer):
                self.add_finding(
                    "Potential Self-Signed Certificate",
                    "MEDIUM",
                    "MEDIUM",
                    self.target,
                    "Certificate subject and issuer appear identical",
                )
        except Exception as e:
            if len(self.request_errors) < 20:
                self.request_errors.append(f"TLS probe {host}:{port} -> {e}")
            self.add_finding(
                "TLS Handshake/Certificate Error",
                "HIGH",
                "MEDIUM",
                self.target,
                f"TLS probe failed: {e}",
            )

    async def audit_well_known_endpoints(self):
        print(f"\n{YELLOW}[*] PHASE 0.7: WELL-KNOWN ENDPOINT CHECK...{RESET}")
        endpoints = [
            "/.well-known/security.txt",
            "/security.txt",
            "/robots.txt",
            "/sitemap.xml",
            "/crossdomain.xml",
            "/clientaccesspolicy.xml",
            "/.git/HEAD",
            "/.env",
        ]

        base = self.target.rstrip("/")
        found = {}
        for p in endpoints:
            r = await self.fetch(f"{base}{p}")
            if r and r.status_code == 200:
                found[p] = r.text[:5000]
                self.endpoint_notes.append(f"Accessible: {p}")

        if "/.well-known/security.txt" not in found and "/security.txt" not in found:
            self.add_finding(
                "Missing security.txt",
                "LOW",
                "HIGH",
                self.target,
                "security.txt contact policy not found",
            )

        git_head = found.get("/.git/HEAD", "")
        if "ref:" in git_head.lower():
            self.add_finding(
                "Exposed Git Metadata",
                "HIGH",
                "HIGH",
                self.target,
                "/.git/HEAD is publicly accessible",
            )

        env_body = found.get("/.env", "")
        if any(k in env_body for k in ["APP_KEY=", "DB_PASSWORD=", "SECRET_KEY=", "AWS_SECRET"]):
            self.add_finding(
                "Potential Secret Exposure (.env)",
                "CRITICAL",
                "HIGH",
                self.target,
                "Sensitive-looking variables found in public .env",
            )

        for policy_path in ["/crossdomain.xml", "/clientaccesspolicy.xml"]:
            txt = found.get(policy_path, "")
            if "*" in txt and "allow-access-from" in txt:
                self.add_finding(
                    "Overly Permissive Client Policy",
                    "MEDIUM",
                    "MEDIUM",
                    self.target,
                    f"{policy_path} allows wildcard client access",
                )

    async def subdomain_hunter(self):
        print(f"\n{YELLOW}[*] PHASE 0.2: SUBDOMAIN SCANNING & HTTP CHECK...{RESET}")
        subs = ["www", "mail", "dev", "staging", "admin", "api", "test", "webmail", "blog", "vpn", "cloud", "cpanel", "whm", "mysql"]
        base_domain = self.domain.replace("www.", "")
        
        async def check_sub(s):
            target_sub = f"{s}.{base_domain}"
            try:
                loop = asyncio.get_running_loop()
                ip = await loop.run_in_executor(None, socket.gethostbyname, target_sub)
                r = await self.fetch(f"http://{target_sub}")
                status = f"[HTTP {r.status_code}]" if r else "[No HTTP]"
                return f"{target_sub} ({ip}) {status}"
            except Exception: return None

        for s in subs:
            res = await self.sync_bar(0.05, f"Sub: {s}", asyncio.create_task(check_sub(s)))
            if res:
                print(f"    {GREEN}[SUB] Found: {res}{RESET}")
                self.subdomains_found.append(res)

    async def form_hunter(self, html):
        print(f"\n{YELLOW}[*] PHASE 2.7: SECURITY AUDIT ON FORMS...{RESET}")
        soup = BeautifulSoup(html, "html.parser")
        forms = soup.find_all("form")
        
        if not forms:
            print(f"    {WHITE}[!] Tidak menemukan form login pada halaman utama.{RESET}")

        for i, form in enumerate(forms):
            action = form.get("action", self.target)
            method = form.get("method", "GET").upper()
            inputs = []
            is_login = False
            has_csrf = False
            
            for tag in form.find_all(["input", "textarea", "select"]):
                t_type = tag.get("type", "text")
                name = tag.get("name", "unknown")
                inputs.append(f"{name}({t_type})")
                
                if t_type == "password": is_login = True
                if "csrf" in name.lower() or "token" in name.lower(): has_csrf = True
            
            vuln_prefix = ""
            if is_login and method == "GET":
                vuln_prefix = f"{RED}[VULN: Sensitive Info in GET]{RESET} "
                self.add_finding(
                    "Weak Authentication Form",
                    "MEDIUM",
                    "HIGH",
                    action,
                    "Login form uses GET method",
                )
            if not has_csrf and method == "POST":
                vuln_prefix += f"{ORANGE}[WARN: No CSRF Token]{RESET} "
                self.add_finding(
                    "Missing Anti-CSRF Token",
                    "LOW",
                    "MEDIUM",
                    action,
                    "POST form without visible csrf/token parameter",
                )

            form_info = f"FORM #{i+1} | {method} -> {action} | Inputs: {', '.join(inputs)}"
            print(f"    {WHITE}» {vuln_prefix}{form_info}{RESET}")
            self.forms_found.append(form_info)

    async def scan_params(self):
        if not self.scan_queue: return
        print(f"\n{YELLOW}[*] PHASE 3: PARAMETER VULNERABILITY TESTING...{RESET}")
        sqli_regex = re.compile(r"(sql syntax|mysql|syntax error|odbc|pdo|postgresql|sqlite|ora-\d+|database error)", re.I)
        for url, param in self.scan_queue:
            target_url = urljoin(self.target, url)
            baseline_token = f"ghostprobe_{uuid.uuid4().hex[:8]}"
            base_resp = await self.fetch(target_url, params={param: baseline_token})
            base_text = base_resp.text if base_resp else ""
            base_status = base_resp.status_code if base_resp else 0

            tests = [
                ("SQLi", "'"),
                ("SQLi", "\""),
                ("XSS", "<script>alert(1)</script>"),
                ("XSS", "\"><svg/onload=alert(1)>"),
            ]
            for kind, payload in tests:
                r = await self.sync_bar(0.2, f"Test: {param}", asyncio.create_task(self.fetch(target_url, params={param: payload})))
                if not r:
                    continue

                body = r.text or ""
                evidence = None
                severity = "LOW"
                confidence = "LOW"

                if kind == "SQLi":
                    new_error = bool(sqli_regex.search(body)) and not bool(sqli_regex.search(base_text))
                    status_shift = r.status_code >= 500 and base_status < 500
                    size_delta = abs(len(body) - len(base_text)) > max(250, int(len(base_text) * 0.3))

                    if new_error and status_shift:
                        evidence = f"DB error pattern + server status changed ({base_status}->{r.status_code})"
                        severity = "HIGH"
                        confidence = "HIGH"
                    elif new_error or status_shift:
                        evidence = f"Anomalous SQL behavior detected (status {base_status}->{r.status_code})"
                        severity = "MEDIUM"
                        confidence = "MEDIUM"
                    elif size_delta and payload in ["'", "\""]:
                        evidence = "Response body length changed significantly after quote payload"
                        severity = "LOW"
                        confidence = "LOW"

                if kind == "XSS":
                    reflected_raw = payload in body
                    reflected_encoded = payload.replace("<", "&lt;").replace(">", "&gt;") in body
                    dangerous_context = "<script" in body.lower() and "alert(1)" in body

                    if reflected_raw and dangerous_context:
                        evidence = "Payload reflected in script-like context"
                        severity = "HIGH"
                        confidence = "MEDIUM"
                    elif reflected_raw:
                        evidence = "Raw payload reflected in response"
                        severity = "MEDIUM"
                        confidence = "MEDIUM"
                    elif reflected_encoded:
                        evidence = "Payload reflected but encoded"
                        severity = "LOW"
                        confidence = "LOW"

                if evidence:
                    print(f"    {ORANGE}[?] {kind} indicator: {target_url}?{param}=... ({confidence}){RESET}")
                    self.add_finding(f"{kind} Indicator", severity, confidence, f"{target_url}?{param}", evidence)

    async def start(self, cli_args=None):
        self.banner()
        self.target = (cli_args.target if cli_args and cli_args.target else input(f"{CYAN}Target URL: {WHITE}").strip())
        if not self.target: return
        if not self.target.startswith("http"): self.target = "http://" + self.target
        if cli_args and cli_args.mode:
            mode = cli_args.mode.strip().lower()
        else:
            mode = input(f"{CYAN}Mode [cepat/normal/agresif] (default: normal): {WHITE}").strip().lower() or "normal"
        self.set_scan_mode(mode)
        if cli_args and cli_args.insecure:
            self.verify_tls = False
        self.set_min_severity(cli_args.min_severity if cli_args else "LOW")
        self.domain = urlparse(self.target).netloc
        try: 
            loop = asyncio.get_running_loop()
            self.target_ip = await loop.run_in_executor(None, socket.gethostbyname, self.domain)
        except Exception: self.target_ip = "Error"
        
        self.banner()
        await self.get_target_intel()
        await self.audit_security_headers()
        await self.audit_http_methods()
        await self.audit_cors()
        await self.audit_tls_certificate()
        await self.audit_well_known_endpoints()
        await self.subdomain_hunter()
        
        print(f"\n{YELLOW}[*] PHASE 1: DIRECTORY BRUTEFORCE...{RESET}")
        paths = ["admin", "login", ".env", "config.php.bak", "backup.zip", ".git/config", "phpinfo.php", "server-status", "robots.txt", "wp-admin"]
        for p in paths:
            url = f"{self.target.rstrip('/')}/{p}"
            r = await self.sync_bar(0.1, f"Path: /{p}", asyncio.create_task(self.fetch(url)))
            if r and r.status_code in [200, 403]:
                print(f"    {GREEN}[FOUND] {url} ({r.status_code}){RESET}")
                self.vuln_log.append(f"DIR: {url} [{r.status_code}]")

        r = await self.fetch(self.target)
        if r:
            await self.form_hunter(r.text)
            soup = BeautifulSoup(r.text, "html.parser")
            for f in soup.find_all("form"):
                act = f.get("action", "")
                for i in f.find_all("input"):
                    name = i.get("name")
                    if name and (act, name) not in self.scan_queue:
                        self.scan_queue.append((act, name))
        
        await self.scan_params()

        print(f"\n{GREEN}══════════════════ HUNTER FINAL REPORT ══════════════════{RESET}")
        print(f" {BLUE}SCAN MODE   : {ORANGE}{self.scan_mode.upper()}{RESET}")
        print(f" {BLUE}MIN SEV     : {ORANGE}{self.min_severity}{RESET}")
        print(f" {BLUE}TARGET IP   : {YELLOW}{self.target_ip}{RESET}")
        print(f" {BLUE}SERVER LOC  : {WHITE}{self.server_loc}{RESET}")
        print(f" {BLUE}FIREWALL    : {RED}{self.firewall}{RESET}")
        if self.tls_info:
            print(f" {BLUE}TLS         : {WHITE}{self.tls_info.get('tls_version', 'Unknown')} / {self.tls_info.get('cipher', 'Unknown')}{RESET}")
            if self.tls_info.get("days_to_expire") is not None:
                print(f" {BLUE}TLS EXPIRE  : {YELLOW}{self.tls_info['days_to_expire']} days{RESET}")
        
        if self.tech_stack:
            print(f"\n {CYAN}[WEB TECHNOLOGIES DETECTED]{RESET}")
            for tech in self.tech_stack: print(f"  {WHITE}» {tech}{RESET}")

        score = self.risk_score()
        risk_level = self.risk_level(score)
        print(f"\n {YELLOW}KERENTANAN WEB : {RED}{score}% ({risk_level} RISK){RESET}")
        print(f" {WHITE}Catatan: hasil berbasis heuristic, bukan bukti final exploitability.{RESET}")

        if self.subdomains_found:
            print(f"\n {CYAN}[SUBDOMAINS DETAIL]{RESET}")
            for s in self.subdomains_found: print(f"  {GREEN}» {s}{RESET}")

        if self.forms_found:
            print(f"\n {CYAN}[LOGIN FORMS DETAIL]{RESET}")
            for f in self.forms_found: print(f"  {GREEN}» {f}{RESET}")
        else:
            print(f"\n {WHITE}[!] Status: Tidak menemukan form login di halaman utama.{RESET}")

        if self.header_issues or self.cookie_issues:
            print(f"\n {CYAN}[HEADER/COOKIE HARDENING NOTES]{RESET}")
            for item in self.header_issues + self.cookie_issues:
                print(f"  {WHITE}» {item}{RESET}")

        if self.endpoint_notes:
            print(f"\n {CYAN}[WELL-KNOWN ENDPOINT NOTES]{RESET}")
            for n in self.endpoint_notes:
                print(f"  {WHITE}» {n}{RESET}")

        if self.findings:
            print(f"\n {RED}[SECURITY FINDINGS]{RESET}")
            for f in self.findings:
                print(f"  {RED}» [{f['severity']}/{f['confidence']}] {f['category']} -> {f['target']} | {f['evidence']}{RESET}")

            print(f"\n {ORANGE}[REMEDIATION GUIDE]{RESET}")
            printed = set()
            for f in self.findings:
                cat = f["category"]
                if cat in printed:
                    continue
                printed.add(cat)
                if "SQLi" in cat:
                    print(f"  {YELLOW}» Gunakan prepared statements/ORM parameterized query, validasi input, dan sembunyikan DB error detail.{RESET}")
                if "XSS" in cat:
                    print(f"  {YELLOW}» Terapkan output encoding sesuai konteks, sanitasi input, dan aktifkan Content-Security-Policy.{RESET}")
                if "CSRF" in cat:
                    print(f"  {YELLOW}» Tambahkan CSRF token per request, validasi origin/referer, dan gunakan SameSite cookies.{RESET}")
                if "Weak Authentication Form" in cat:
                    print(f"  {YELLOW}» Ubah login form ke POST + HTTPS, hindari kredensial pada URL/query string.{RESET}")
        else:
            print(f"\n  {GREEN}Tidak ada indikator kuat yang terdeteksi pada cek heuristic ini.{RESET}")

        if self.request_errors:
            print(f"\n {WHITE}[REQUEST WARNINGS]{RESET}")
            for err in self.request_errors:
                print(f"  {WHITE}» {err}{RESET}")

        report_path = self.export_json_report(score)
        sarif_path = self.export_sarif_report()
        print(f"\n {CYAN}[JSON REPORT]{RESET} {WHITE}{report_path}{RESET}")
        print(f" {CYAN}[SARIF REPORT]{RESET} {WHITE}{sarif_path}{RESET}")
        
        print(f"\n{GREEN}═════════════════════════════════════════════════════════{RESET}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ghost Web Scanner (heuristic)")
    parser.add_argument("--target", help="Target URL, contoh: https://example.com")
    parser.add_argument("--mode", choices=["cepat", "normal", "agresif"], help="Mode scanning")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    parser.add_argument(
        "--min-severity",
        default="LOW",
        choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL", "info", "low", "medium", "high", "critical"],
        help="Minimum severity untuk export JSON/SARIF",
    )
    args = parser.parse_args()
    try: 
        asyncio.run(GhostHunterV47().start(args))
    except KeyboardInterrupt: 
        print(f"\n{RED}[!] Aborted by User.{RESET}")
    except Exception as e:
        print(f"\n{RED}[ERROR] {e}{RESET}")