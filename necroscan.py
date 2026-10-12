#!/usr/bin/env python3
"""
Necroscan - Visual recon + wordlist generator
==============================================
Rastreia um site (mesmo dominio), bate screenshots de todas as paginas via
aquatone e gera wordlists completas a partir do conteudo do proprio site,
no estilo CeWL/cupp. Se encontra funcionarios (nomes, e-mails, cargos),
monta tambem uma wordlist direcionada baseada nessas pessoas.

Uso basico:
    python necroscan.py https://alvo.com
    python necroscan.py https://alvo.com --depth 3 --out loot/alvo

Requisitos: requests, beautifulsoup4  (aquatone e opcional)
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from datetime import datetime
from urllib.parse import urljoin, urlparse

try:
    import requests
    from bs4 import BeautifulSoup, Comment
except ImportError:
    print("[!] Faltam dependencias. Instale com:  pip install requests beautifulsoup4")
    sys.exit(1)

requests.packages.urllib3.disable_warnings()  # alvos com TLS quebrado sao comuns em pentest

BANNER = r"""
   _   _
  | \ | | ___  ___ _ __ ___  ___  ___ __ _ _ __
  |  \| |/ _ \/ __| '__/ _ \/ __|/ __/ _` | '_ \
  | |\  |  __/ (__| | | (_) \__ \ (_| (_| | | | |
  |_| \_|\___|\___|_|  \___/|___/\___\__,_|_| |_|
        visual recon + wordlist reaper
"""

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36")

# palavras muito curtas / lixo HTML que nao agregam a wordlist
STOP_JUNK = {"the", "and", "for", "you", "that", "this", "with", "from",
             "https", "http", "www", "com", "html", "span", "div", "img"}

# termos tecnicos de JS/CSS/DOM/frameworks que poluem a wordlist (ruido de .js)
# NAO inclui palavras valiosas como admin/login/user/senha/password/token.
TECH_STOP = {
    # CSS: propriedades e valores
    "width", "height", "margin", "padding", "color", "fill", "stroke", "opacity",
    "display", "block", "inline", "flex", "grid", "none", "auto", "font", "size",
    "style", "border", "background", "position", "absolute", "relative", "static",
    "align", "justify", "center", "left", "right", "top", "bottom", "transform",
    "rotate", "scale", "translate", "linejoin", "linecap", "round", "hidden",
    "visible", "overflow", "zindex", "cursor", "pointer", "radius", "shadow",
    "weight", "family", "spacing", "wrap", "content", "box", "aria", "viewport",
    "initial", "webkit", "rgba", "rgb", "var", "class", "attribute", "selector",
    "query", "lang", "current", "path", "svg", "stylesheet", "media", "screen",
    # DOM / JS APIs
    "document", "window", "navigator", "languages", "insert", "adjacent",
    "append", "appendchild", "prepend", "afterbegin", "afterend", "beforebegin",
    "beforeend", "children", "innerhtml", "textcontent", "classlist", "element",
    "createelement", "getattribute", "setattribute", "getelementbyid", "parentnode",
    "nodetype", "undefined", "function", "return", "const", "let", "true", "false",
    "null", "typeof", "prototype", "constructor", "arguments", "callback", "promise",
    "async", "await", "console", "error", "warn", "split", "join", "push", "pop",
    "slice", "splice", "length", "foreach", "map", "filter", "reduce", "indexof",
    "includes", "replace", "match", "test", "parse", "stringify", "json", "value",
    "event", "listener", "addeventlistener", "target", "preventdefault", "string",
    "object", "array", "number", "boolean", "default", "export", "exports", "require",
    "import", "module", "typeof", "instanceof", "apply", "bind", "call",
    # frameworks / libs comuns
    "react", "reactdom", "vue", "angular", "jquery", "bootstrap", "webpack",
    "babel", "polyfill", "lodash", "moment", "axios", "props", "state", "component",
    "render", "hooks", "usestate", "useeffect", "fragment", "svelte", "nextjs",
}

LEET_MAP = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"})

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

# ---- OSINT de redes sociais ----
# redes: nome -> (template de URL com {u}, status/condicao que indica NAO-existe)
SOCIAL_SITES = {
    "github":    ("https://github.com/{u}", 404),
    "gitlab":    ("https://gitlab.com/{u}", 404),
    "instagram": ("https://www.instagram.com/{u}/", 404),
    "facebook":  ("https://www.facebook.com/{u}", 404),
    "twitter":   ("https://x.com/{u}", 404),
    "linkedin":  ("https://www.linkedin.com/in/{u}", 404),
    "tiktok":    ("https://www.tiktok.com/@{u}", 404),
    "youtube":   ("https://www.youtube.com/@{u}", 404),
    "reddit":    ("https://www.reddit.com/user/{u}", 404),
    "pinterest": ("https://www.pinterest.com/{u}/", 404),
    "telegram":  ("https://t.me/{u}", 404),
    "medium":    ("https://medium.com/@{u}", 404),
    "twitch":    ("https://www.twitch.tv/{u}", 404),
    "keybase":   ("https://keybase.io/{u}", 404),
}
# dominios sociais p/ detectar os perfis que o PROPRIO site linka (passivo)
SOCIAL_DOMAINS = {
    "linkedin.com": "linkedin", "instagram.com": "instagram", "facebook.com": "facebook",
    "fb.com": "facebook", "twitter.com": "twitter", "x.com": "twitter",
    "youtube.com": "youtube", "youtu.be": "youtube", "tiktok.com": "tiktok",
    "github.com": "github", "gitlab.com": "gitlab", "t.me": "telegram",
    "telegram.me": "telegram", "pinterest.com": "pinterest", "medium.com": "medium",
    "twitch.tv": "twitch", "reddit.com": "reddit",
}

# locais comuns do big.txt do SecLists (Windows, Kali/WSL, Linux)
SECLISTS_BIG = [
    r"C:\SecLists\Discovery\Web-Content\big.txt",
    r"C:\Tools\SecLists\Discovery\Web-Content\big.txt",
    os.path.expanduser(r"~\SecLists\Discovery\Web-Content\big.txt"),
    "/usr/share/seclists/Discovery/Web-Content/big.txt",
    "/usr/share/wordlists/seclists/Discovery/Web-Content/big.txt",
    "/usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt",
    os.path.expanduser("~/SecLists/Discovery/Web-Content/big.txt"),
]
# fallback: baixa o big.txt oficial do SecLists (so com --download-wordlist)
SECLISTS_BIG_URL = ("https://raw.githubusercontent.com/danielmiessler/SecLists/"
                    "master/Discovery/Web-Content/big.txt")

# cargos/titulos comuns (PT-BR + EN) usados p/ detectar funcionarios no texto
JOB_TITLES = [
    "ceo", "cto", "cfo", "coo", "cio", "ciso", "founder", "cofounder", "president",
    "diretor", "diretora", "gerente", "coordenador", "coordenadora", "supervisor",
    "analista", "assistente", "estagiario", "estagiaria", "consultor", "consultora",
    "desenvolvedor", "desenvolvedora", "programador", "engenheiro", "engenheira",
    "arquiteto", "designer", "advogado", "advogada", "contador", "contadora",
    "vendedor", "vendedora", "secretaria", "secretario", "presidente", "socio", "socia",
    "manager", "developer", "engineer", "architect", "analyst", "consultant",
    "director", "officer", "administrator", "administrador", "administradora",
    "tecnico", "tecnica", "especialista", "head", "lead", "owner", "partner",
    "recepcionista", "financeiro", "comercial", "marketing", "suporte", "rh",
]

# titulos de tratamento que costumam preceder nomes de pessoas
NAME_PREFIX = ["dr", "dra", "sr", "sra", "eng", "prof", "mr", "mrs", "ms"]

# tokens que parecem nome mas nao sao (reduz falso-positivo em nomes de 1 palavra)
NAME_STOP = {"contato", "email", "e-mail", "fone", "telefone", "endereco", "sobre",
             "equipe", "nossa", "nosso", "home", "menu", "fale", "conosco", "contact",
             "about", "team", "whatsapp", "copyright", "todos", "direitos", "staff", "our"}

# conectores/verbos: se aparecem num "nome", e fragmento de frase -> rejeita o nome inteiro
NAME_BLOCK = {"is", "are", "was", "were", "be", "been", "on", "in", "as", "at", "to",
              "of", "the", "and", "for", "with", "this", "that", "who", "will", "has",
              "have", "works", "work", "join", "joined", "responsible", "focusing",
              "administering", "managing", "looks", "after", "our", "their", "his",
              "her", "e", "da", "de", "do", "das", "dos", "para", "com", "que"}


class Crawler:
    """Rastreador simples de mesmo-dominio que coleta URLs, texto e HTML bruto."""

    def __init__(self, base_url, depth=2, max_pages=300, timeout=10, verbose=True):
        self.base_url = base_url.rstrip("/")
        self.root = urlparse(self.base_url).netloc
        self.depth = depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": DEFAULT_UA})
        self.visited = set()
        self.found_urls = []          # todas as URLs HTTP(S) vistas (p/ aquatone)
        self.corpus = []              # pedacos de texto coletados (p/ wordlist)
        self.pages = []               # (soup, texto) p/ coleta de pessoas
        self.script_urls = []         # .js referenciados (p/ mineracao)
        self.endpoints = set()        # endpoints/paths extraidos de JS
        self.social_links = {}        # rede -> set de URLs sociais linkadas pelo site

    def _same_site(self, url):
        return urlparse(url).netloc == self.root

    def _log(self, msg):
        if self.verbose:
            print(msg)

    def crawl(self):
        queue = [(self.base_url, 0)]
        while queue and len(self.visited) < self.max_pages:
            url, d = queue.pop(0)
            if url in self.visited or d > self.depth:
                continue
            self.visited.add(url)
            try:
                r = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
            except requests.RequestException as e:
                self._log(f"  [x] {url} -> {e.__class__.__name__}")
                continue

            self.found_urls.append(r.url)
            ctype = r.headers.get("Content-Type", "")
            if "html" not in ctype.lower():
                continue

            self._log(f"  [+] [{d}] {r.url} ({r.status_code})")
            soup = BeautifulSoup(r.text, "html.parser")
            raw_text = soup.get_text(separator=" ")
            self.pages.append((soup, raw_text))
            self._harvest_text(soup)

            # coleta scripts do mesmo site p/ mineracao posterior
            for sc in soup.find_all("script", src=True):
                js = urljoin(r.url, sc["src"].split("#")[0])
                if js.startswith("http") and self._same_site(js):
                    self.script_urls.append(js)

            # coleta perfis de redes sociais que o site linka (passivo)
            for a in soup.find_all("a", href=True):
                net = social_network_of(a["href"])
                if net:
                    self.social_links.setdefault(net, set()).add(a["href"].split("?")[0].rstrip("/"))

            if d < self.depth:
                for a in soup.find_all("a", href=True):
                    link = urljoin(r.url, a["href"].split("#")[0])
                    if link.startswith("http") and self._same_site(link) and link not in self.visited:
                        queue.append((link, d + 1))
        return self

    def mine_js(self, max_scripts=40, max_bytes=300_000):
        """Baixa os .js do mesmo site e extrai palavras/identificadores e endpoints."""
        seen = set()
        ident_re = re.compile(r"[A-Za-z][A-Za-z0-9_]{3,}")
        ep_re = re.compile(r"""['"`](/[A-Za-z0-9_\-./]{2,}|https?://[^'"`\s]{4,})['"`]""")
        mined = 0
        for su in self.script_urls:
            if su in seen or mined >= max_scripts:
                continue
            seen.add(su)
            try:
                r = self.session.get(su, timeout=self.timeout, verify=False)
            except requests.RequestException:
                continue
            if r.status_code != 200:
                continue
            mined += 1
            txt = r.text[:max_bytes]
            for m in ep_re.findall(txt):
                self.endpoints.add(m)
            for ident in ident_re.findall(txt):
                for w in split_identifier(ident):
                    if len(w) >= 3:
                        self.corpus.append(w)
        self._log(f"  [+] JS minerados: {mined} arquivo(s), {len(self.endpoints)} endpoints.")
        return mined

    def _harvest_text(self, soup):
        clone = BeautifulSoup(str(soup), "html.parser")
        for tag in clone(["script", "style", "noscript"]):
            tag.decompose()
        self.corpus.append(clone.get_text(separator=" "))
        for meta in clone.find_all("meta"):
            c = meta.get("content")
            if c:
                self.corpus.append(c)
        for cm in clone.find_all(string=lambda t: isinstance(t, Comment)):
            self.corpus.append(str(cm))
        for tag in clone.find_all(True):
            for attr in ("alt", "title", "placeholder", "name", "id", "value"):
                v = tag.get(attr)
                if v and isinstance(v, str):
                    self.corpus.append(v)


class WordlistBuilder:
    """Extrai, filtra e (opcionalmente) muta palavras no estilo CeWL/cupp."""

    def __init__(self, min_len=3, max_len=40, lowercase=False, with_numbers=False,
                 tech_filter=True):
        self.min_len = min_len
        self.max_len = max_len
        self.lowercase = lowercase
        self.with_numbers = with_numbers
        self.tech_filter = tech_filter
        self.stop = STOP_JUNK | TECH_STOP if tech_filter else STOP_JUNK
        self.counter = Counter()

    def feed(self, corpus):
        pattern = r"[A-Za-z0-9]+" if self.with_numbers else r"[A-Za-z]+"
        for chunk in corpus:
            for w in re.findall(pattern, chunk):
                if self.min_len <= len(w) <= self.max_len:
                    word = w.lower() if self.lowercase else w
                    if word.lower() not in self.stop:
                        self.counter[word] += 1
        return self

    def base_words(self):
        return [w for w, _ in self.counter.most_common()]

    def mangle(self, words, years=None, specials="!@#$", caps=True, leet=True,
               numbers=True, extra_suffixes=None):
        if years is None:
            cy = datetime.now().year
            years = [str(y) for y in range(cy - 3, cy + 1)]
        suffixes = list(dict.fromkeys(list(years) + ["1", "123", "12", "2", "01", "007"]
                                      + list(extra_suffixes or [])))
        out, seen = [], set()

        def add(x):
            if x and x not in seen:
                seen.add(x)
                out.append(x)

        for w in words:
            add(w)
            variants = {w}
            if caps:
                variants.add(w.capitalize())
                variants.add(w.upper())
            if leet:
                variants.add(w.translate(LEET_MAP))
                variants.add(w.capitalize().translate(LEET_MAP))
            for v in list(variants):
                add(v)
                if numbers:
                    for s in suffixes:
                        add(v + s)
                    for sp in specials:
                        add(v + sp)
                        for s in suffixes:
                            add(v + s + sp)
                            add(v + sp + s)
        return out


class PeopleHarvester:
    """Extrai funcionarios (nomes, e-mails, cargos) do site e gera wordlist
    direcionada estilo cupp (combinacoes de nome + sobrenome + ano + cargo)."""

    def __init__(self):
        self.emails = set()
        self.names = set()        # tuplas (nome, sobrenome, ...)
        self.roles = set()        # cargos encontrados
        self.usernames = set()    # usernames detectados em artefatos (ex: rweston.jpg)

    def feed(self, soup, raw_text):
        # 1) e-mails
        for m in EMAIL_RE.findall(raw_text):
            self.emails.add(m.lower())

        # 2) dados estruturados schema.org (itemprop name/jobTitle) + meta author
        for tag in soup.find_all(attrs={"itemprop": True}):
            prop = (tag.get("itemprop") or "").lower()
            val = (tag.get("content") or tag.get_text(" ", strip=True) or "").strip()
            if prop == "name" and val:
                self._add_name(val)
            if prop == "jobtitle" and val:
                self.roles.add(val.lower())
        for meta in soup.find_all("meta"):
            if (meta.get("name") or "").lower() == "author" and meta.get("content"):
                self._add_name(meta["content"].strip())

        # 3) nomes em celulas de tabela / cabecalhos / destaques ("Rhys Weston")
        name_cell = re.compile(r"^[A-ZÀ-Ü][a-zà-ü]+(?:\s+[A-ZÀ-Ü][a-zà-ü]+){1,2}$")
        for tag in soup.find_all(["th", "td", "h3", "h4", "h5", "h6", "strong", "b", "li", "figcaption"]):
            txt = tag.get_text(" ", strip=True)
            if txt and name_cell.match(txt):
                self._add_name(txt)

        # 4) usernames em artefatos: headshots/avatares/mailto (revela a convencao!)
        for tag in soup.find_all(["img", "a"]):
            src = tag.get("src") or tag.get("href") or ""
            if re.search(r"headshot|avatar|staff|team|employee|people|profile|user", src, re.I):
                base = re.sub(r"\.[a-z0-9]{2,4}$", "", os.path.basename(src))
                base = base.split("?")[0].strip().lower()
                if re.fullmatch(r"[a-z][a-z.\-_]{2,30}", base):
                    self.usernames.add(base)
            if src.lower().startswith("mailto:"):
                self.emails.add(src[7:].split("?")[0].strip().lower())

        # 5) heuristica em texto puro
        self._scan_text_for_people(raw_text)

    def _add_name(self, full):
        parts = [p for p in re.split(r"\s+", full.strip()) if p.isalpha() and len(p) > 1]
        # se contem conector/verbo, e fragmento de frase -> descarta
        if any(p.lower() in NAME_BLOCK for p in parts):
            return
        parts = [p for p in parts if p.lower() not in NAME_STOP]
        if len(parts) == 1 and parts[0].lower() in JOB_TITLES:
            return  # um unico token que e cargo nao e nome
        if 2 <= len(parts) <= 4:
            self.names.add(tuple(p.capitalize() for p in parts))

    def _scan_text_for_people(self, text):
        # nomes apos titulos de tratamento: "Dr. Joao Silva"
        prefix_re = re.compile(
            r"\b(?:%s)\.?\s+([A-ZA-Ü][a-zà-ü]+(?:\s+[A-ZA-Ü][a-zà-ü]+){0,3})" %
            "|".join(NAME_PREFIX), re.UNICODE)
        for m in prefix_re.findall(text):
            self._add_name(m)

        # "Nome Sobrenome" junto de um cargo conhecido
        for role in JOB_TITLES:
            r1 = re.compile(
                r"\b([A-ZÀ-Ü][a-zà-ü]+(?:\s+[A-ZÀ-Ü][a-zà-ü]+){0,2})\s*[,\-–|:]\s*%s\b" % role,
                re.IGNORECASE | re.UNICODE)
            r2 = re.compile(
                r"\b%s\s*[:\-–|,]\s*([A-ZÀ-Ü][a-zà-ü]+(?:\s+[A-ZÀ-Ü][a-zà-ü]+){0,2})" % role,
                re.IGNORECASE | re.UNICODE)
            for rx in (r1, r2):
                for m in rx.findall(text):
                    self._add_name(m)
            if re.search(r"\b%s\b" % role, text, re.IGNORECASE):
                self.roles.add(role)

    def summary(self):
        return len(self.names), len(self.emails), len(self.roles)

    def build_wordlist(self, years=None, specials="!@#$."):
        if years is None:
            cy = datetime.now().year
            years = [str(y) for y in range(cy - 4, cy + 1)]
        suffixes = list(years) + ["1", "123", "12", "01"]
        out, seen = [], set()

        def add(x):
            x = x.strip()
            if x and x not in seen:
                seen.add(x)
                out.append(x)

        locals_ = {e.split("@")[0] for e in self.emails}

        name_tokens = set()
        for parts in self.names:
            p = [x.lower() for x in parts]
            name_tokens.update(p)
            if len(p) >= 2:
                f, l = p[0], p[-1]
                name_tokens.update({
                    f + l, f + "." + l, f[0] + l, f + l[0],
                    l + f, f + "_" + l, f + "-" + l, l + f[0], f[0] + "." + l,
                })

        seeds = set()
        seeds.update(locals_)
        seeds.update(name_tokens)
        seeds.update(r.replace(" ", "") for r in self.roles)

        for base in sorted(x for x in seeds if x):
            for variant in {base, base.capitalize(), base.upper()}:
                add(variant)
                for s in suffixes:
                    add(variant + s)
                for sp in specials:
                    add(variant + sp)
                    for s in suffixes:
                        add(variant + s + sp)
                        add(variant + sp + s)
        return out

    def username_permutations(self):
        """Gera todas as convencoes de username a partir dos nomes capturados."""
        perms = {}  # username -> pessoa (nome completo)
        for parts in self.names:
            p = [x.lower() for x in parts]
            full = " ".join(w.capitalize() for w in parts)
            if len(p) < 2:
                perms.setdefault(p[0], full)
                continue
            f, l = p[0], p[-1]
            for u in (f, l, f + l, l + f, f + "." + l, l + "." + f,
                      f[0] + l, l + f[0], f + l[0], f[0] + "." + l,
                      f + "_" + l, f + "-" + l, f[0] + l[0], l + f[0] + f[1:2]):
                perms.setdefault(u, full)
        return perms

    def detect_convention(self):
        """Infere a convencao real de username cruzando artefatos (ex: rweston) com os nomes."""
        hits = []
        for parts in self.names:
            p = [x.lower() for x in parts]
            if len(p) < 2:
                continue
            f, l = p[0], p[-1]
            cands = {"flast": f[0] + l, "first.last": f + "." + l, "firstlast": f + l,
                     "firstl": f + l[0], "lastf": l + f[0], "last.first": l + "." + f,
                     "f.last": f[0] + "." + l, "last": l, "first": f}
            for conv, u in cands.items():
                if u in self.usernames:
                    hits.append(conv)
        if hits:
            return Counter(hits).most_common(1)[0][0]
        return None

    def osint_people(self, email_domain=None):
        """OSINT a partir dos nomes do site: usernames, convencao detectada e e-mails.
        Retorna dict com 'usernames', 'convention', 'emails', 'report' (linhas)."""
        perms = self.username_permutations()
        all_users = set(perms) | set(self.usernames)
        convention = self.detect_convention()
        emails = set(self.emails)
        if email_domain:
            for u in all_users:
                emails.add(f"{u}@{email_domain}")
        # relatorio legivel por pessoa
        report = []
        for parts in sorted(self.names):
            p = [x.lower() for x in parts]
            full = " ".join(w.capitalize() for w in parts)
            if len(p) >= 2:
                f, l = p[0], p[-1]
                guess = (f[0] + l) if convention in (None, "flast") else None
                line = f"{full}: {f[0]+l}, {f+'.'+l}, {f+l}, {l+f[0]}"
                if email_domain:
                    line += f"  |  {f[0]+l}@{email_domain}"
                report.append(line)
        return {"usernames": sorted(all_users), "convention": convention,
                "emails": sorted(emails), "report": report}


# =========================================================================
#  MODO PROFILE (estilo cupp -i, porem mais completo + mistura OSINT)
# =========================================================================

# senhas/palavras comuns no Brasil p/ enriquecer o profile (pacote --br)
BR_PACK = [
    "senha", "mudar123", "123mudar", "brasil", "amor", "deus", "jesus", "familia",
    "amORdeus", "saudade", "felicidade", "campeao", "mengao", "flamengo", "corinthians",
    "palmeiras", "saopaulo", "vasco", "gremio", "internacional", "cruzeiro", "galo",
    "verao", "carnaval", "futebol", "cerveja", "churrasco", "fortaleza", "bahia",
    "123456", "senha123", "admin", "master", "trocar", "primeiro", "janeiro",
    "fevereiro", "marco", "abril", "maio", "junho", "julho", "agosto", "setembro",
    "outubro", "novembro", "dezembro", "verao2024", "amor2024",
]

MONTHS_PT = ["janeiro", "fevereiro", "marco", "abril", "maio", "junho", "julho",
             "agosto", "setembro", "outubro", "novembro", "dezembro"]

# pacote EUA / ingles
US_PACK = [
    "password", "passw0rd", "welcome", "letmein", "admin", "root", "qwerty",
    "iloveyou", "monkey", "dragon", "football", "baseball", "superman", "batman",
    "master", "shadow", "sunshine", "princess", "trustno1", "freedom", "whatever",
    "summer", "winter", "spring", "autumn", "january", "february", "march", "april",
    "god", "jesus", "love", "money", "hockey", "ranger", "soccer", "america", "usa",
    "changeme", "secret", "ninja", "access", "hello", "charlie", "liverpool",
]

# pacote espanhol / LatAm
ES_PACK = [
    "contraseña", "clave", "amor", "dios", "familia", "hola", "cariño", "corazon",
    "fútbol", "futbol", "barcelona", "madrid", "realmadrid", "america", "boca",
    "river", "chivas", "verano", "invierno", "enero", "febrero", "marzo", "abril",
    "mayo", "junio", "julio", "agosto", "mexico", "argentina", "espana", "quiero",
    "princesa", "estrella", "libertad", "123456", "qwerty", "admin", "cambiar",
]

# pacote global (senhas mais comuns no mundo, independente de idioma)
GLOBAL_PACK = [
    "123456", "123456789", "12345678", "password", "qwerty", "abc123", "111111",
    "123123", "000000", "iloveyou", "admin", "welcome", "monkey", "dragon", "letmein",
    "login", "princess", "qwertyuiop", "solo", "passw0rd", "starwars", "master",
    "hello", "freedom", "whatever", "trustno1", "1q2w3e4r", "zaq12wsx", "qazwsx",
    "1qaz2wsx", "superman", "football", "000", "1234", "12345", "root", "toor",
    "changeme", "secret", "google", "facebook", "internet", "samsung", "apple",
]

LOCALE_PACKS = {"br": BR_PACK, "us": US_PACK, "es": ES_PACK, "global": GLOBAL_PACK}


def expand_dates(birth):
    """De uma data DDMMAAAA (ou DD/MM/AAAA) gera varios tokens numericos, inclui idade."""
    toks = set()
    digits = re.sub(r"\D", "", birth or "")
    if len(digits) == 8:
        dd, mm, yyyy = digits[:2], digits[2:4], digits[4:]
        yy = yyyy[2:]
        toks.update({yyyy, yy, dd, mm, dd + mm, mm + dd, dd + mm + yy,
                     dd + mm + yyyy, mm + yyyy, yyyy + mm + dd, yy + mm + dd,
                     dd + yyyy, mm + yy, dd + "/" + mm, dd + "-" + mm})
        try:
            age = datetime.now().year - int(yyyy)
            if 0 < age < 120:
                toks.add(str(age))
        except ValueError:
            pass
    elif len(digits) == 4:  # so o ano
        toks.update({digits, digits[2:]})
    return {t for t in toks if t}


def build_hashcat_rules(dates, use_leet=True, use_special=True):
    """Gera dinamicamente um .rule do hashcat (anos do alvo + leet + especiais)."""
    rules = [":", "l", "u", "c", "t0", "r"]        # nada/lower/upper/cap/toggle/reverso
    if use_leet:
        leet = "sa4 se3 si1 so0 ss5 st7"
        rules += [leet, "c " + leet]
    if use_special:
        for suf in ("!", "@", "#", "$", "!!", "2", "1"):
            rules.append("".join("$" + ch for ch in suf))
        rules.append("$1$2$3")                      # 123
        rules.append("c $!")                         # Capitaliza + !
    # anexa cada token de data (ex: 1990 -> $1$9$9$0), e cap+data, e data+!
    for dt in sorted(dates):
        ap = "".join("$" + ch for ch in dt if ch.isalnum())
        if ap:
            rules.append(ap)
            rules.append("c " + ap)
            if use_special:
                rules.append(ap + " $!")
    # dedup preservando ordem
    return "\n".join(dict.fromkeys(rules))


class ProfileBuilder:
    """Gera wordlist a partir do perfil de um alvo (estilo cupp), bem mais completa:
    nomes/apelidos, datas, parceiro(a), filhos, pet, empresa, palavras extras e OSINT,
    com combinacoes par-a-par, leet, caps, especiais, pacote BR, variacoes extras,
    ranking por probabilidade, filtro por politica de senha e saida em regras hashcat."""

    def __init__(self, data, use_leet=True, use_special=True, use_numbers=True,
                 min_len=4, max_len=32, merged=None, max_merged=150,
                 locales=None, policy=None, max_words=0):
        self.d = data
        self.use_leet = use_leet
        self.use_special = use_special
        self.use_numbers = use_numbers
        self.min_len = min_len
        self.max_len = max_len
        self.merged = list(dict.fromkeys(merged or []))[:max_merged]
        self.locales = set(locales or [])    # ex: {"br","us","global"}
        self.policy = policy                 # dict {minlen,upper,digit,special} ou None
        self.max_words = max_words           # 0 = sem limite
        self.name_tokens = set()             # p/ ranking (nomes do alvo)
        self.year_tokens = set()             # p/ ranking (anos de nascimento)

    def _base_words(self):
        w = set()
        for key in ("nome", "sobrenome", "apelido", "pet", "empresa"):
            v = (self.d.get(key) or "").strip()
            if v:
                w.add(v.lower())
                self.name_tokens.add(v.lower())
        for key in ("parceiro_nome", "parceiro_apelido"):
            v = (self.d.get(key) or "").strip()
            if v:
                w.add(v.lower())
                self.name_tokens.add(v.lower())
        for lst in ("filhos", "extra"):
            for v in self.d.get(lst, []) or []:
                v = v.strip()
                if v:
                    w.add(v.lower())
                    self.name_tokens.add(v.lower())
        w.update(x.lower() for x in self.merged)        # OSINT / palavras externas (pessoais)
        # pacotes de pais/global vao p/ dicionario (NAO entram no combinador par-a-par)
        self.dict_words = set()
        for loc in self.locales:
            self.dict_words.update(x.lower() for x in LOCALE_PACKS.get(loc, []))
        # 7) variacoes extras: invertido e duplicado (so palavras pessoais)
        extra = set()
        for x in list(w):
            if 3 <= len(x) <= 12:
                extra.add(x[::-1])          # invertido: joao -> oaoj
                extra.add(x + x)            # duplicado: joaojoao
        w |= extra
        return {x for x in w if x}

    def _date_tokens(self):
        toks = set()
        for key in ("nascimento", "parceiro_nascimento"):
            toks |= expand_dates(self.d.get(key))
        for dt in list(toks):
            if len(dt) == 4 and dt.isdigit():
                self.year_tokens.add(dt)
        return toks

    def _score(self, w):
        """Probabilidade heuristica: nome + ano + especial no topo."""
        low = w.lower()
        s = 0
        if any(nt and nt in low for nt in self.name_tokens):
            s += 50
        if any(y in w for y in self.year_tokens):
            s += 30
        if re.search(r"[!@#$.]", w):
            s += 12
        if re.search(r"\d", w):
            s += 8
        if 8 <= len(w) <= 14:
            s += 10
        if w[:1].isupper():
            s += 3
        s -= max(0, len(w) - 16)
        return s

    def _passes_policy(self, w):
        p = self.policy
        if not p:
            return True
        if len(w) < p.get("minlen", 0):
            return False
        if p.get("upper") and not re.search(r"[A-Z]", w):
            return False
        if p.get("digit") and not re.search(r"\d", w):
            return False
        if p.get("special") and not re.search(r"[^A-Za-z0-9]", w):
            return False
        return True

    def base_for_rules(self):
        """Lista-base enxuta p/ usar com hashcat -r (sem expandir)."""
        words = self._base_words()
        dates = self._date_tokens()
        base = set(words) | set(dates) | getattr(self, "dict_words", set())
        wl = sorted(words)
        for a in wl:                         # pares essenciais (nome+sobrenome, etc.)
            for b in wl:
                if a != b:
                    base.add(a + b)
        return sorted(x for x in base if 1 <= len(x) <= self.max_len)

    def generate(self):
        words = self._base_words()
        dates = self._date_tokens()
        specials = ["", "!", "@", "#", "$", "123", "1234", "!!", "1", "01", "007", "."] \
            if self.use_special else [""]
        seen = set()
        cands = []

        def add(x):
            if x and self.min_len <= len(x) <= self.max_len and x not in seen:
                if self._passes_policy(x):
                    seen.add(x)
                    cands.append(x)

        def case_variants(x):
            v = {x, x.capitalize(), x.upper()}
            if self.use_leet:
                v.add(x.translate(LEET_MAP))
                v.add(x.capitalize().translate(LEET_MAP))
            return v

        wl = sorted(words)
        # palavras isoladas (pessoais + dicionario de pais) com case/leet/datas/especiais
        for base in sorted(words | getattr(self, "dict_words", set())):
            for v in case_variants(base):
                add(v)
                for dt in dates:
                    add(v + dt)
                    add(dt + v)
                if self.use_special:
                    for sp in specials:
                        add(v + sp)
                        for dt in dates:
                            add(v + dt + sp)
                            add(v + sp + dt)
        for dt in dates:
            add(dt)
        # 6) multi-pessoa: combinacoes par-a-par entre TODAS as palavras (alvo+familia+osint)
        seps = ["", ".", "_", "-"] if self.use_special else [""]
        for a in wl:
            for b in wl:
                if a == b:
                    continue
                for sep in seps:
                    combo = a + sep + b
                    add(combo)
                    add(combo.capitalize())
                    for dt in dates:
                        add(combo + dt)
        # 2) ranking por probabilidade (mais provaveis primeiro)
        cands.sort(key=self._score, reverse=True)
        if self.max_words and len(cands) > self.max_words:
            cands = cands[:self.max_words]
        return cands


def load_merge_words(path):
    """Carrega palavras de um arquivo OU de um diretorio de loot (usernames/part_people)."""
    words = []
    if not path:
        return words
    candidates = []
    if os.path.isdir(path):
        for fn in ("usernames.txt", "part_people.txt", "emails.txt", "wordlist.txt"):
            fp = os.path.join(path, fn)
            if os.path.exists(fp):
                candidates.append(fp)
    elif os.path.isfile(path):
        candidates.append(path)
    for fp in candidates:
        try:
            with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    t = line.split("\t")[0].split("@")[0].strip()
                    if t and t.isascii():
                        words.append(t)
        except Exception:
            pass
    return list(dict.fromkeys(words))


def ask(prompt, default=""):
    try:
        v = input(f"  {prompt}" + (f" [{default}]" if default else "") + ": ").strip()
        return v or default
    except EOFError:
        return default


def collect_profile_interactive():
    """Questionario estilo cupp (em PT-BR), porem mais completo."""
    print("\n[ Perfil do alvo - responda o que souber, Enter pula ]\n")
    d = {}
    d["nome"] = ask("Nome")
    d["sobrenome"] = ask("Sobrenome")
    d["apelido"] = ask("Apelido/nick")
    d["nascimento"] = ask("Nascimento (DDMMAAAA)")
    d["parceiro_nome"] = ask("Nome do(a) parceiro(a)")
    d["parceiro_apelido"] = ask("Apelido do(a) parceiro(a)")
    d["parceiro_nascimento"] = ask("Nascimento do(a) parceiro(a) (DDMMAAAA)")
    d["filhos"] = [x for x in ask("Filhos/pets (separe por virgula)").split(",") if x.strip()]
    d["pet"] = ask("Pet")
    d["empresa"] = ask("Empresa")
    d["extra"] = [x for x in ask("Palavras extras (virgula): hobbies, time, cidade...").split(",") if x.strip()]
    d["_leet"] = ask("Incluir leet (a=4,e=3...)? s/n", "s").lower().startswith("s")
    d["_special"] = ask("Incluir caracteres especiais/numeros? s/n", "s").lower().startswith("s")
    d["_locale"] = ask("Pacotes de pais (br,us,es,global ou all; vazio=nenhum)")
    d["_merge"] = ask("Arquivo/pasta de OSINT p/ misturar (ex: loot/alvo)")
    return d


def parse_locales(raw):
    """Converte 'br,us' ou 'all' num conjunto de pacotes validos."""
    raw = (raw or "").strip().lower()
    if not raw:
        return set()
    if raw == "all":
        return set(LOCALE_PACKS)
    return {x.strip() for x in raw.split(",") if x.strip() in LOCALE_PACKS}


def parse_policy(raw):
    """'8,upper,digit,special' -> dict de politica de senha."""
    raw = (raw or "").strip().lower()
    if not raw:
        return None
    pol = {"minlen": 0, "upper": False, "digit": False, "special": False}
    for part in raw.split(","):
        part = part.strip()
        if part.isdigit():
            pol["minlen"] = int(part)
        elif part in ("upper", "maiuscula", "maiusc. "):
            pol["upper"] = True
        elif part in ("digit", "numero", "num"):
            pol["digit"] = True
        elif part in ("special", "especial", "simbolo"):
            pol["special"] = True
    return pol


def profile_osint(d, email_domain=None):
    """Faz OSINT em cima dos dados do perfil e devolve palavras p/ a wordlist:
    usernames do alvo e do(a) parceiro(a), subdominios (se empresa for dominio) e e-mails."""
    extra = []
    # 1) usernames a partir dos nomes (alvo + parceiro), via mesma logica do scan
    ph = PeopleHarvester()
    nome, sobren = (d.get("nome") or "").strip(), (d.get("sobrenome") or "").strip()
    if nome and sobren:
        ph.names.add((nome.capitalize(), sobren.capitalize()))
    elif nome:
        ph.names.add((nome.capitalize(),))
    pn = (d.get("parceiro_nome") or "").strip()
    if pn:
        ph.names.add((pn.capitalize(), sobren.capitalize()) if sobren else (pn.capitalize(),))
    apelido = (d.get("apelido") or "").strip()
    if apelido:
        ph.usernames.add(apelido.lower())

    # 2) empresa como dominio -> crt.sh (subdominios) + base p/ e-mail
    company = (d.get("empresa") or "").strip()
    dom = email_domain
    if not dom and company and "." in company and " " not in company:
        dom = company.lower()
    if dom:
        try:
            subs, mails = osint_subdomains(dom, timeout=25, run_theharvester=False)
            for s in subs:
                for lab in s.split("."):
                    if lab not in COMMON_SLD and len(lab) > 2:
                        extra.append(lab)
            extra.extend(m.split("@")[0] for m in mails)
            if subs:
                print(f"[+] crt.sh ({dom}): {len(subs)} subdominios -> seeds.")
        except Exception as e:
            print(f"[!] crt.sh falhou: {e}")

    info = ph.osint_people(email_domain=dom)
    extra.extend(info["usernames"])
    if info["convention"]:
        print(f"[!] Convencao de username provavel: '{info['convention']}'")
    print(f"[+] OSINT do perfil: +{len(set(extra))} palavras (usernames/e-mails/subdominios).")
    return list(dict.fromkeys(extra))


def run_profile(args):
    """Executa o modo profile: coleta dados, mistura OSINT e gera a wordlist."""
    print(BANNER)
    print("[*] Modo PROFILE (estilo cupp, mais completo + OSINT)\n")
    if args.profile_file:
        import json
        with open(args.profile_file, "r", encoding="utf-8") as f:
            d = json.load(f)
        print(f"[+] Perfil carregado de {args.profile_file}")
    else:
        d = collect_profile_interactive()

    merge_path = args.merge or d.get("_merge")
    merged = load_merge_words(merge_path)
    if merged:
        print(f"[+] {len(merged)} palavras de arquivo/loot misturadas ({merge_path}).")

    # ---- OSINT em cima dos dados do perfil ----
    merged += profile_osint(d, args.email_domain)

    locales = parse_locales(args.locale or d.get("_locale"))
    policy = parse_policy(args.policy)
    if locales:
        print(f"[+] Pacotes de pais: {', '.join(sorted(locales))}")
    if policy:
        print(f"[+] Filtro de politica: {policy}")

    pb = ProfileBuilder(d, use_leet=d.get("_leet", True), use_special=d.get("_special", True),
                        merged=merged, locales=locales, policy=policy,
                        max_words=args.max_words)

    name = (d.get("nome") or "alvo").lower()
    # modo regras hashcat: lista-base enxuta + .rule (expande na GPU)
    if args.rule:
        base = pb.base_for_rules()
        dates = pb._date_tokens()
        rules = build_hashcat_rules(dates, use_leet=pb.use_leet, use_special=pb.use_special)
        base_out = args.out or f"profile_{name}_base.txt"
        rule_out = os.path.splitext(base_out)[0].replace("_base", "") + ".rule"
        _save(base_out, base)
        _save(rule_out, rules.splitlines())
        print(f"\n[=] MODO HASHCAT:")
        print(f"[+] Lista-base ({len(base)} palavras) -> {os.path.abspath(base_out)}")
        print(f"[+] Regras ({len(rules.splitlines())}) -> {os.path.abspath(rule_out)}")
        print(f"[*] Uso: hashcat -a 0 -m <hash> alvo.hash {base_out} -r {rule_out}")
        return

    wl = pb.generate()
    out = args.out or f"profile_{name}.txt"
    _save(out, wl)
    print(f"\n[=] WORDLIST DE PERFIL: {len(wl)} entradas (ranqueada por probabilidade) -> {os.path.abspath(out)}")


def find_aquatone(explicit=None):
    """Localiza o binario do aquatone (Windows PATH ou WSL)."""
    if explicit:
        return [explicit]
    path = shutil.which("aquatone") or shutil.which("aquatone.exe")
    if path:
        return [path]
    if shutil.which("wsl"):
        try:
            r = subprocess.run(["wsl", "which", "aquatone"],
                               capture_output=True, text=True, timeout=15)
            if r.returncode == 0 and r.stdout.strip():
                return ["wsl", "aquatone"]
        except Exception:
            pass
    return None


def detect_chrome():
    """Localiza um binario chromium/chrome p/ o aquatone (Windows ou WSL)."""
    for name in ("chromium", "chromium-browser", "google-chrome", "chrome", "chrome.exe"):
        p = shutil.which(name)
        if p:
            return p
    for p in ("/usr/bin/chromium", "/usr/bin/chromium-browser", "/usr/bin/google-chrome",
              "/snap/bin/chromium"):
        if os.path.exists(p):
            return p
    return None


def run_aquatone(urls, outdir, aqua_cmd, threads=5, timeout=1200, chrome_path=None):
    """Alimenta a lista de URLs no aquatone (stdin) e gera o relatorio visual."""
    os.makedirs(outdir, exist_ok=True)
    data = "\n".join(sorted(set(urls)))
    cmd = list(aqua_cmd) + ["-out", outdir, "-threads", str(threads)]
    chrome_path = chrome_path or detect_chrome()
    if chrome_path:
        cmd += ["-chrome-path", chrome_path]
    print(f"[*] Rodando aquatone ({' '.join(cmd)}) em {len(set(urls))} URLs...")
    try:
        proc = subprocess.run(cmd, input=data, capture_output=True, text=True, timeout=timeout)
        if proc.stdout:
            print(proc.stdout[-2000:])
        if proc.returncode != 0 and proc.stderr:
            print("[!] aquatone stderr:\n" + proc.stderr[-2000:])
        report = os.path.join(outdir, "aquatone_report.html")
        if os.path.exists(report):
            print(f"[+] Relatorio visual: {report}")
        return proc.returncode == 0
    except FileNotFoundError:
        print("[!] aquatone nao encontrado no comando resolvido.")
    except subprocess.TimeoutExpired:
        print("[!] aquatone excedeu o timeout.")
    return False


def find_wordlist(explicit=None, allow_download=False, cache_dir="."):
    """Localiza o big.txt do SecLists; opcionalmente baixa se nao achar."""
    if explicit and os.path.exists(explicit):
        return explicit
    for p in SECLISTS_BIG:
        if os.path.exists(p):
            return p
    # tenta resolver caminho dentro do WSL -> caminho Windows (\\wsl$)
    if shutil.which("wsl"):
        try:
            r = subprocess.run(["wsl", "test", "-f",
                                "/usr/share/seclists/Discovery/Web-Content/big.txt"],
                               capture_output=True, timeout=10)
            if r.returncode == 0:
                return r"\\wsl$\kali-linux\usr\share\seclists\Discovery\Web-Content\big.txt"
        except Exception:
            pass
    if allow_download:
        dest = os.path.join(cache_dir, "big.txt")
        print(f"[*] Baixando big.txt do SecLists -> {dest}")
        try:
            resp = requests.get(SECLISTS_BIG_URL, timeout=60, verify=False)
            resp.raise_for_status()
            with open(dest, "wb") as f:
                f.write(resp.content)
            n = resp.content.count(b"\n")
            print(f"[+] big.txt baixado ({n} linhas).")
            return dest
        except Exception as e:
            print(f"[!] Falha ao baixar big.txt: {e}")
    return None


class Fuzzer:
    """Fuzzing de diretorios/arquivos com a wordlist (big.txt do SecLists).

    Usa ffuf/feroxbuster se disponiveis; senao, fuzzer proprio em Python
    com threads. Filtra por codigos de status interessantes."""

    def __init__(self, base_url, wordlist, extensions=None, threads=20,
                 timeout=8, match_codes=None, verbose=True):
        self.base = base_url.rstrip("/")
        self.wordlist = wordlist
        self.extensions = extensions or []
        self.threads = threads
        self.timeout = timeout
        self.match = match_codes or {200, 204, 301, 302, 307, 401, 403, 405, 500}
        self.verbose = verbose
        self.hits = []

    def _load_words(self):
        with open(self.wordlist, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                w = line.strip()
                if w and not w.startswith("#"):
                    yield w

    def run_external(self, outdir):
        """Tenta ffuf, depois feroxbuster. Retorna True se rodou."""
        target = self.base + "/FUZZ"
        if shutil.which("ffuf"):
            out = os.path.join(outdir, "ffuf.json")
            cmd = ["ffuf", "-u", target, "-w", self.wordlist,
                   "-t", str(self.threads), "-mc", ",".join(str(c) for c in sorted(self.match)),
                   "-o", out, "-of", "json", "-s"]
            if self.extensions:
                cmd += ["-e", ",".join("." + e.lstrip(".") for e in self.extensions)]
            print(f"[*] ffuf: {' '.join(cmd)}")
            try:
                subprocess.run(cmd, timeout=3600)
                print(f"[+] Resultado ffuf -> {out}")
                return True
            except Exception as e:
                print(f"[!] ffuf falhou: {e}")
        if shutil.which("feroxbuster"):
            out = os.path.join(outdir, "feroxbuster.txt")
            cmd = ["feroxbuster", "-u", self.base, "-w", self.wordlist,
                   "-t", str(self.threads), "-o", out]
            if self.extensions:
                cmd += ["-x", ",".join(e.lstrip(".") for e in self.extensions)]
            print(f"[*] feroxbuster: {' '.join(cmd)}")
            try:
                subprocess.run(cmd, timeout=3600)
                print(f"[+] Resultado feroxbuster -> {out}")
                return True
            except Exception as e:
                print(f"[!] feroxbuster falhou: {e}")
        return False

    def run_builtin(self):
        """Fuzzer interno em Python (sem dependencias externas)."""
        from concurrent.futures import ThreadPoolExecutor, as_completed
        session = requests.Session()
        session.headers.update({"User-Agent": DEFAULT_UA})

        paths = []
        for w in self._load_words():
            paths.append(w)
            for e in self.extensions:
                paths.append(w + "." + e.lstrip("."))
        total = len(paths)
        print(f"[*] Fuzzer interno: {total} caminhos, {self.threads} threads...")

        def probe(path):
            url = f"{self.base}/{path}"
            try:
                r = session.get(url, timeout=self.timeout, verify=False, allow_redirects=False)
                if r.status_code in self.match:
                    return (r.status_code, len(r.content), url)
            except requests.RequestException:
                return None
            return None

        done = 0
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(probe, p): p for p in paths}
            for fut in as_completed(futures):
                done += 1
                if self.verbose and done % 500 == 0:
                    print(f"    ... {done}/{total}")
                res = fut.result()
                if res:
                    code, size, url = res
                    self.hits.append(res)
                    print(f"  [{code}] {url}  ({size}b)")
        self.hits.sort()
        return self.hits


# SLDs comuns p/ extrair o nome da empresa do dominio
COMMON_SLD = {"com", "net", "org", "gov", "edu", "co", "io", "br", "app", "info", "biz"}


def split_identifier(ident):
    """Quebra camelCase / snake_case / kebab em palavras: getUserToken -> get,User,Token."""
    words = []
    for part in re.split(r"[_\-]", ident):
        words.extend(re.findall(r"[A-Z]?[a-z]{2,}|[A-Z]{2,}(?![a-z])", part))
    return [w for w in words if len(w) >= 3]


def social_network_of(url):
    """Diz a qual rede social uma URL pertence (ou None)."""
    try:
        host = urlparse(url if "//" in url else "https://" + url).netloc.lower()
    except Exception:
        return None
    host = host[4:] if host.startswith("www.") else host
    for dom, net in SOCIAL_DOMAINS.items():
        if host == dom or host.endswith("." + dom):
            return net
    return None


def social_handle_of(url):
    """Extrai o handle/usuario de uma URL de perfil social."""
    path = urlparse(url if "//" in url else "https://" + url).path.strip("/")
    if not path:
        return None
    seg = path.split("/")
    # formatos tipo /in/<user>, /user/<user>, /@<user>, /<user>
    if seg[0] in ("in", "user", "profile", "u") and len(seg) > 1:
        h = seg[1]
    else:
        h = seg[-1] if seg[0] in ("@",) else seg[0]
    h = h.lstrip("@").split("?")[0]
    if re.fullmatch(r"[A-Za-z0-9._-]{2,40}", h) and h not in (
            "pages", "company", "groups", "sharer", "share", "home", "watch"):
        return h
    return None


def enrich_from_social_urls(urls, timeout=10):
    """Faz OSINT em URLs de perfil social passadas pelo usuario: extrai handle, nome
    provavel e palavras (og:title/description, title) p/ alimentar a wordlist.
    Retorna {handles:set, names:set(tuplas), words:[], report:[]}."""
    handles, names, words, report = set(), set(), [], []
    sess = requests.Session()
    sess.headers.update({"User-Agent": DEFAULT_UA})
    for url in urls:
        url = url.strip()
        if not url:
            continue
        net = social_network_of(url) or "?"
        h = social_handle_of(url)
        if h:
            handles.add(h.lower())
            # handle "joao.silva" / "joao-silva" vira tokens tambem
            for tok in re.split(r"[._\-]", h):
                if len(tok) > 2 and tok.isalpha():
                    words.append(tok.lower())
        title = desc = ""
        try:
            r = sess.get(url, timeout=timeout, verify=False, allow_redirects=True)
            soup = BeautifulSoup(r.text, "html.parser")
            for m in soup.find_all("meta"):
                prop = (m.get("property") or m.get("name") or "").lower()
                if prop in ("og:title", "twitter:title") and m.get("content"):
                    title = m["content"].strip()
                if prop in ("og:description", "twitter:description", "description") and m.get("content"):
                    desc = m["content"].strip()
            if not title and soup.title:
                title = soup.title.get_text(" ", strip=True)
        except requests.RequestException as e:
            report.append(f"[{net}] {url} -> erro: {e.__class__.__name__}")
        # nome provavel: parte antes de separadores tipo "Nome (@handle) | LinkedIn"
        if title:
            cand = re.split(r"[\|\(\-–—•·@]", title)[0].strip()
            parts = [p for p in cand.split() if p.isalpha() and len(p) > 1]
            if 2 <= len(parts) <= 4:
                names.add(tuple(p.capitalize() for p in parts))
            for p in parts:
                words.append(p.lower())
        # palavras da bio/descricao
        for w in re.findall(r"[A-Za-zÀ-ÿ]{4,20}", desc):
            words.append(w.lower())
        report.append(f"[{net}] {url}  handle={h or '?'}  nome={title[:60] or '?'}")
    return {"handles": handles, "names": names, "words": words, "report": report}


def social_osint(usernames, site_social=None, check=False, timeout=8, max_users=15):
    """OSINT de redes sociais.
    - Passivo: lista os perfis que o site ja linka (site_social: rede->set de URLs).
    - Ativo (check=True): p/ cada username, gera a URL em cada rede e testa existencia
      (best-effort; LinkedIn/IG/FB usam anti-bot, entao trate como indicio).
    Retorna dict {report:[linhas], handles:set, urls:[...]}."""
    report, handles, urls = [], set(), []

    # 1) passivo: perfis sociais publicados no proprio site
    if site_social:
        for net, links in sorted(site_social.items()):
            for link in sorted(links):
                report.append(f"[site] {net}: {link}")
                urls.append(link)
                h = social_handle_of(link)
                if h:
                    handles.add(h.lower())

    # 2) ativo: enumera usernames nas redes
    if usernames:
        sess = requests.Session()
        sess.headers.update({"User-Agent": DEFAULT_UA})
        for u in list(dict.fromkeys(usernames))[:max_users]:
            for net, (tpl, notfound) in SOCIAL_SITES.items():
                url = tpl.format(u=u)
                urls.append(url)
                if not check:
                    continue
                try:
                    r = sess.get(url, timeout=timeout, verify=False, allow_redirects=True)
                    status = "existe?" if r.status_code == 200 else (
                        "nao" if r.status_code == notfound else f"http {r.status_code}")
                except requests.RequestException:
                    status = "erro/timeout"
                if status != "nao":
                    report.append(f"[{net}] {u} -> {url}  ({status})")
    return {"report": report, "handles": handles, "urls": urls}


def osint_subdomains(domain, timeout=30, run_theharvester=True):
    """OSINT externo: subdominios via crt.sh + (opcional) theHarvester p/ hosts/e-mails.
    Retorna (subdominios:set, emails:set)."""
    subs, emails = set(), set()
    base = domain.split(":")[0]
    # --- crt.sh (certificate transparency, sem dependencia) ---
    try:
        url = f"https://crt.sh/?q=%25.{base}&output=json"
        r = requests.get(url, timeout=timeout, verify=False,
                         headers={"User-Agent": DEFAULT_UA})
        if r.status_code == 200 and r.text.strip():
            for entry in r.json():
                for name in str(entry.get("name_value", "")).splitlines():
                    name = name.strip().lstrip("*.").lower()
                    if name.endswith(base) and "@" not in name:
                        subs.add(name)
        print(f"  [+] crt.sh: {len(subs)} subdominios.")
    except Exception as e:
        print(f"  [!] crt.sh falhou: {e}")
    # --- theHarvester (se instalado) ---
    if run_theharvester:
        thbin = shutil.which("theHarvester") or shutil.which("theharvester")
        if thbin:
            try:
                r = subprocess.run([thbin, "-d", base, "-b", "all"],
                                   capture_output=True, text=True, timeout=600)
                out = (r.stdout or "") + (r.stderr or "")
                emails.update(e.lower() for e in EMAIL_RE.findall(out) if e.lower().endswith(base)
                              or base in e.lower())
                for h in re.findall(r"\b[a-z0-9.\-]+\.%s\b" % re.escape(base), out):
                    subs.add(h.lower())
                print(f"  [+] theHarvester: +{len(emails)} e-mails.")
            except Exception as e:
                print(f"  [!] theHarvester falhou: {e}")
        else:
            print("  [-] theHarvester nao instalado (usando so crt.sh).")
    return subs, emails


def combine_words(words, seeds, suffixes, top=40):
    """Combina palavras entre si e com seeds (senhas compostas): acmeseguranca, seguranca2024."""
    out, seen = [], set()

    def add(x):
        if x and 4 <= len(x) <= 40 and x not in seen:
            seen.add(x)
            out.append(x)

    top_words = [w.lower() for w in words[:top]]
    pool = list(dict.fromkeys([s.lower() for s in seeds] + top_words))
    for a in pool:
        # palavra + palavra
        for b in top_words:
            if a != b:
                add(a + b)
                add(a + b.capitalize())
        # palavra + sufixo (ano/numero real)
        for s in suffixes:
            add(a + s)
    return out


def domain_seeds(netloc):
    """Deriva palavras-semente do nome do dominio/empresa (empresa.com.br -> empresa)."""
    host = netloc.split(":")[0].lower()
    labels = [l for l in host.split(".") if l and l != "www"]
    seeds = set()
    for lab in labels:
        if lab not in COMMON_SLD and len(lab) > 1:
            seeds.add(lab)
            # separa palavras coladas por hifen: minha-empresa -> minha, empresa, minhaempresa
            for part in re.split(r"[-_]", lab):
                if len(part) > 1:
                    seeds.add(part)
            seeds.add(lab.replace("-", "").replace("_", ""))
    return sorted(seeds)


def url_tokens(urls):
    """Extrai segmentos de path e nomes de parametros de query das URLs."""
    toks = set()
    for u in urls:
        p = urlparse(u)
        for seg in re.split(r"[/.\-_]", p.path):
            seg = re.sub(r"[^A-Za-z0-9]", "", seg)
            if 3 <= len(seg) <= 40 and not seg.isdigit():
                toks.add(seg)
        for pair in p.query.split("&"):
            key = pair.split("=")[0].strip()
            if 2 <= len(key) <= 40 and key.isalnum():
                toks.add(key)
    return toks


def harvest_numbers(corpus):
    """Coleta numeros reais do site (anos, codigos) p/ usar como sufixos dinamicos."""
    nums = set()
    for chunk in corpus:
        for n in re.findall(r"\b\d{2,4}\b", chunk):
            nums.add(n)
    # prioriza anos plausiveis e numeros curtos
    return sorted(n for n in nums if len(n) <= 4)[:60]


def build_master(base, wb, people_wl, seeds, dyn_suffixes, plain=False, combine=True):
    """Consolida TUDO numa unica wordlist ordenada por relevancia e deduplicada:
    seeds (empresa) -> palavras do site (por freq) -> combos de pessoas ->
    senhas compostas (palavra+palavra) -> mutacoes."""
    order, seen = [], set()

    def add_many(items):
        for x in items:
            if x and x not in seen:
                seen.add(x)
                order.append(x)

    add_many(seeds)                    # nome da empresa/dominio (alta relevancia)
    add_many(base)                     # palavras do site por frequencia
    add_many(people_wl)                # funcionarios/cargos (ja mutados)
    if combine:
        all_suffixes = list(dict.fromkeys(list(dyn_suffixes) + ["2024", "2025", "123"]))
        add_many(combine_words(base, seeds, all_suffixes))   # senhas compostas
    if not plain:
        # mutacoes das palavras do site + seeds, com anos/numeros reais do alvo
        add_many(wb.mangle(seeds + base, extra_suffixes=dyn_suffixes))
    return order


def _save(path, lines):
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def main():
    ap = argparse.ArgumentParser(
        description="Necroscan - recon visual (aquatone) + wordlists estilo cupp/CeWL",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("url", nargs="?", default=None, help="URL alvo (ex: https://alvo.com); opcional no modo --profile")
    ap.add_argument("--profile", action="store_true", help="modo cupp: gera wordlist por perfil do alvo (interativo)")
    ap.add_argument("--profile-file", default=None, help="JSON com o perfil (nao-interativo)")
    ap.add_argument("--merge", default=None, help="arquivo/pasta de OSINT p/ misturar no perfil (ex: loot/alvo)")
    ap.add_argument("--locale", default=None, help="pacotes de pais no profile: br,us,es,global ou all")
    ap.add_argument("--policy", default=None, help="filtra por politica: ex '8,upper,digit,special'")
    ap.add_argument("--max-words", type=int, default=0, help="limita a wordlist do profile (0=sem limite)")
    ap.add_argument("--rule", action="store_true", help="profile em modo hashcat: lista-base + .rule (expande na GPU)")
    ap.add_argument("--depth", type=int, default=2, help="profundidade do crawl (default 2)")
    ap.add_argument("--max-pages", type=int, default=300, help="maximo de paginas (default 300)")
    ap.add_argument("--out", default=None, help="diretorio de saida (default: loot/<dominio>)")
    ap.add_argument("--timeout", type=int, default=10, help="timeout por request em s (default 10)")

    ap.add_argument("--min-len", type=int, default=3, help="tamanho min de palavra (default 3)")
    ap.add_argument("--max-len", type=int, default=40, help="tamanho max de palavra (default 40)")
    ap.add_argument("--lowercase", action="store_true", help="forca tudo minusculo")
    ap.add_argument("--with-numbers", action="store_true", help="inclui tokens com numeros")
    ap.add_argument("--plain", action="store_true", help="wordlist enxuta: sem mutacoes (menor, so palavras-base)")
    ap.add_argument("--keep-parts", action="store_true", help="salva tambem os arquivos separados (conteudo, pessoas, etc.)")
    ap.add_argument("--no-people", action="store_true", help="nao incluir funcionarios na wordlist")
    ap.add_argument("--no-js", action="store_true", help="nao minerar arquivos .js")
    ap.add_argument("--no-tech-filter", action="store_true", help="nao filtrar termos tecnicos de JS/CSS/framework")
    ap.add_argument("--no-combine", action="store_true", help="nao gerar senhas compostas (palavra+palavra)")
    ap.add_argument("--with-count", action="store_true", help="salva wordlist_counts.txt (palavra + frequencia, estilo CeWL)")
    ap.add_argument("--osint", action="store_true", help="OSINT: subdominios (crt.sh) + usernames/e-mails a partir dos nomes capturados")
    ap.add_argument("--email-domain", default=None, help="dominio p/ gerar candidatos de e-mail (ex: empresa.com)")
    ap.add_argument("--social", action="store_true", help="OSINT de redes sociais: enumera usernames (LinkedIn, Instagram, Facebook, GitHub, X...)")
    ap.add_argument("--social-url", action="append", default=[], help="URL(s) de perfil social p/ OSINT (repetivel ou separada por virgula)")
    ap.add_argument("--social-file", default=None, help="arquivo com URLs de redes sociais (uma por linha)")

    ap.add_argument("--no-screens", action="store_true", help="pula screenshots (so wordlist)")
    ap.add_argument("--aquatone", default=None, help="caminho explicito do binario aquatone")
    ap.add_argument("--chrome-path", default=None, help="caminho do chromium/chrome p/ o aquatone")
    ap.add_argument("--threads", type=int, default=5, help="threads do aquatone (default 5)")

    # fuzzing
    ap.add_argument("--fuzz", action="store_true", help="faz fuzzing de dirs/arquivos com big.txt (SecLists)")
    ap.add_argument("--fuzz-wordlist", default=None, help="wordlist p/ fuzzing (default: big.txt do SecLists)")
    ap.add_argument("--fuzz-ext", default="", help="extensoes separadas por virgula (ex: php,bak,txt)")
    ap.add_argument("--fuzz-threads", type=int, default=20, help="threads do fuzzer (default 20)")
    ap.add_argument("--fuzz-codes", default="", help="codigos HTTP a aceitar (ex: 200,301,403); vazio=padrao")
    ap.add_argument("--download-wordlist", action="store_true", help="baixa big.txt do SecLists se nao achar")

    ap.add_argument("-q", "--quiet", action="store_true", help="menos output")
    args = ap.parse_args()

    # modo profile (cupp): nao precisa de URL
    if args.profile or args.profile_file:
        run_profile(args)
        return

    if not args.url:
        ap.error("informe a URL alvo, ou use --profile para o modo cupp")
    if not args.url.startswith("http"):
        args.url = "https://" + args.url

    domain = urlparse(args.url).netloc.replace(":", "_")
    outdir = args.out or os.path.join("loot", domain)
    os.makedirs(outdir, exist_ok=True)

    if not args.quiet:
        print(BANNER)
    print(f"[*] Alvo        : {args.url}")
    print(f"[*] Saida       : {os.path.abspath(outdir)}")
    print(f"[*] Profundidade: {args.depth}  | max paginas: {args.max_pages}")
    print("-" * 60)

    # 1) CRAWL
    print("[*] Fase 1/5: rastreando o site...")
    c = Crawler(args.url, depth=args.depth, max_pages=args.max_pages,
                timeout=args.timeout, verbose=not args.quiet).crawl()
    print(f"[+] {len(c.visited)} paginas visitadas, {len(set(c.found_urls))} URLs coletadas.")
    _save(os.path.join(outdir, "urls.txt"), sorted(set(c.found_urls)))
    print(f"[+] URLs salvas em {os.path.join(outdir, 'urls.txt')}")

    # mineracao de JavaScript (palavras/identificadores + endpoints)
    if not args.no_js and c.script_urls:
        print("[*] Minerando arquivos .js do site...")
        c.mine_js()
        if c.endpoints:
            _save(os.path.join(outdir, "endpoints.txt"), sorted(c.endpoints))
            print(f"[+] {len(c.endpoints)} endpoints -> endpoints.txt")

    # fontes extras p/ enriquecer a wordlist: nome da empresa, tokens de URL, numeros reais
    seeds = set(domain_seeds(urlparse(args.url).netloc))
    utoks = url_tokens(c.found_urls)
    c.corpus.extend(utoks)                 # tokens de URL entram no corpus de palavras

    # OSINT externo opcional (subdominios + e-mails)
    osint_emails = set()
    if args.osint:
        print("[*] OSINT externo (crt.sh / theHarvester)...")
        subs, osint_emails = osint_subdomains(urlparse(args.url).netloc)
        if subs:
            _save(os.path.join(outdir, "subdomains.txt"), sorted(subs))
            print(f"[+] {len(subs)} subdominios -> subdomains.txt")
            # labels de subdominio viram seeds (ex: api.vpn.empresa.com -> api, vpn)
            for s in subs:
                for lab in s.split("."):
                    if lab not in COMMON_SLD and len(lab) > 2:
                        seeds.add(lab)

    seeds = sorted(seeds)
    dyn_suffixes = harvest_numbers(c.corpus)
    if seeds:
        print(f"[+] Seeds (empresa/subdominios): {', '.join(seeds[:20])}{'...' if len(seeds) > 20 else ''}")
    if utoks:
        print(f"[+] {len(utoks)} tokens extraidos de URLs (paths/parametros).")
    if dyn_suffixes:
        print(f"[+] {len(dyn_suffixes)} numeros reais do site usados como sufixos dinamicos.")

    # 2) WORDLIST DE CONTEUDO
    print("\n[*] Fase 2/5: minerando palavras do conteudo...")
    wb = WordlistBuilder(min_len=args.min_len, max_len=args.max_len,
                         lowercase=args.lowercase, with_numbers=args.with_numbers,
                         tech_filter=not args.no_tech_filter).feed(c.corpus)
    base = wb.base_words()
    print(f"[+] {len(base)} palavras-base (por frequencia).")

    # 3) FUNCIONARIOS
    print("\n[*] Fase 3/5: coleta de funcionarios (nomes/e-mails/cargos)...")
    people_wl = []
    if args.no_people:
        print("[-] Pulado (--no-people).")
    else:
        ph = PeopleHarvester()
        for soup, raw in c.pages:
            ph.feed(soup, raw)

        # URLs de redes sociais passadas pelo usuario (--social-url / --social-file)
        social_urls = []
        for item in args.social_url:
            social_urls += [u for u in item.split(",") if u.strip()]
        if args.social_file and os.path.exists(args.social_file):
            with open(args.social_file, encoding="utf-8", errors="ignore") as f:
                social_urls += [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
        if social_urls:
            print(f"[*] OSINT em {len(social_urls)} URL(s) de rede social fornecida(s)...")
            en = enrich_from_social_urls(social_urls)
            for nm in en["names"]:
                ph.names.add(nm)
            ph.usernames.update(en["handles"])
            base[:0] = [w for w in dict.fromkeys(en["words"]) if w not in base]
            for h in en["handles"]:
                if h not in seeds:
                    seeds.insert(0, h)
            _save(os.path.join(outdir, "social_input.txt"), en["report"])
            for line in en["report"]:
                print("      " + line)

        ph.emails.update(osint_emails)          # inclui e-mails do OSINT (theHarvester)
        n_names, n_mails, n_roles = ph.summary()
        print(f"[+] {n_names} nomes, {n_mails} e-mails, {n_roles} cargos detectados.")
        if ph.emails:
            _save(os.path.join(outdir, "emails.txt"), sorted(ph.emails))
            print(f"[+] e-mails -> emails.txt")
        if n_names or n_mails or n_roles:
            people_wl = ph.build_wordlist(years=dyn_suffixes or None)
            print(f"[+] {len(people_wl)} combinacoes de pessoas/cargos geradas.")
        else:
            print("[-] Nenhum funcionario identificado.")

        # OSINT em cima dos nomes capturados (usernames, convencao, e-mails)
        if args.osint and (ph.names or ph.usernames):
            print("[*] OSINT de pessoas (usernames/convencao/e-mails a partir dos nomes)...")
            info = ph.osint_people(email_domain=args.email_domain)
            if info["convention"]:
                print(f"[!] CONVENCAO DE USERNAME DETECTADA: '{info['convention']}' "
                      f"(cruzando artefatos do site com os nomes)")
            _save(os.path.join(outdir, "usernames.txt"), info["usernames"])
            print(f"[+] {len(info['usernames'])} usernames -> usernames.txt")
            if info["emails"]:
                _save(os.path.join(outdir, "emails.txt"), info["emails"])
                print(f"[+] {len(info['emails'])} e-mails (incl. candidatos) -> emails.txt")
            if info["report"]:
                _save(os.path.join(outdir, "osint_people.txt"), info["report"])
                print(f"[+] Relatorio por pessoa -> osint_people.txt")
                for line in info["report"]:
                    print("      " + line)
            # usernames entram na wordlist mestre (como seeds de alta relevancia)
            seeds[:0] = [u for u in info["usernames"] if u not in seeds]
            people_wl = list(dict.fromkeys(info["usernames"] + people_wl))

        # OSINT de redes sociais (perfis linkados pelo site + enum de usernames)
        if (args.osint or args.social) and (c.social_links or (args.social and ph.usernames)):
            print("[*] OSINT de redes sociais...")
            unames = sorted(ph.usernames) if args.social else []
            sinfo = social_osint(unames, site_social=c.social_links,
                                 check=args.social)
            if sinfo["report"]:
                _save(os.path.join(outdir, "social.txt"), sinfo["report"])
                print(f"[+] {len(sinfo['report'])} achados -> social.txt")
                for line in sinfo["report"][:20]:
                    print("      " + line)
            if sinfo["urls"]:
                _save(os.path.join(outdir, "social_urls.txt"), sorted(set(sinfo["urls"])))
            # handles das redes viram seeds da wordlist
            for h in sinfo["handles"]:
                if h not in seeds:
                    seeds.insert(0, h)

    # >>> CONSOLIDACAO: uma unica wordlist com TUDO <<<
    master = build_master(base, wb, people_wl, seeds, dyn_suffixes,
                          plain=args.plain, combine=not args.no_combine)
    master_path = os.path.join(outdir, "wordlist.txt")
    _save(master_path, master)
    print(f"\n[=] WORDLIST MESTRE: {len(master)} entradas (tudo consolidado) -> {master_path}")

    if args.with_count:
        counts = [f"{w}\t{n}" for w, n in wb.counter.most_common()]
        _save(os.path.join(outdir, "wordlist_counts.txt"), counts)
        print(f"[+] Contagem de frequencia (CeWL-style) -> wordlist_counts.txt")

    if args.keep_parts:
        _save(os.path.join(outdir, "part_content.txt"), base)
        if not args.plain:
            _save(os.path.join(outdir, "part_content_mangled.txt"),
                  wb.mangle(seeds + base, extra_suffixes=dyn_suffixes))
        if people_wl:
            _save(os.path.join(outdir, "part_people.txt"), people_wl)
        print("[+] Arquivos separados salvos (--keep-parts).")

    # 4) SCREENSHOTS (aquatone)
    print("\n[*] Fase 4/5: screenshots com aquatone...")
    if args.no_screens:
        print("[-] Pulado (--no-screens).")
    elif not c.found_urls:
        print("[-] Nenhuma URL para fotografar.")
    else:
        aqua = find_aquatone(args.aquatone)
        if not aqua:
            print("[!] aquatone nao encontrado. Instale: go install github.com/michenriksen/aquatone@latest")
            print("    ou use --aquatone <caminho>. Wordlists e URLs ja foram geradas.")
        else:
            run_aquatone(c.found_urls, os.path.join(outdir, "screenshots"), aqua,
                         threads=args.threads, chrome_path=args.chrome_path)

    # 5) FUZZING (SecLists big.txt)
    print("\n[*] Fase 5/5: fuzzing de diretorios/arquivos...")
    if not args.fuzz:
        print("[-] Pulado (use --fuzz para ativar).")
    else:
        wl = find_wordlist(args.fuzz_wordlist, allow_download=args.download_wordlist, cache_dir=outdir)
        if not wl:
            print("[!] big.txt do SecLists nao encontrado.")
            print("    Rode com --download-wordlist para baixar, ou passe --fuzz-wordlist <caminho>.")
        else:
            print(f"[+] Wordlist de fuzzing: {wl}")
            exts = [e for e in args.fuzz_ext.split(",") if e.strip()]
            codes = {int(c) for c in args.fuzz_codes.split(",") if c.strip().isdigit()} or None
            fz = Fuzzer(args.url, wl, extensions=exts, threads=args.fuzz_threads,
                        match_codes=codes, verbose=not args.quiet)
            fuzz_dir = os.path.join(outdir, "fuzz")
            os.makedirs(fuzz_dir, exist_ok=True)
            if not fz.run_external(fuzz_dir):
                print("[*] ffuf/feroxbuster indisponiveis; usando fuzzer interno.")
                hits = fz.run_builtin()
                lines = [f"{code}\t{size}\t{url}" for code, size, url in hits]
                _save(os.path.join(fuzz_dir, "fuzz_results.txt"), lines)
                print(f"[+] {len(hits)} achados -> {os.path.join(fuzz_dir, 'fuzz_results.txt')}")

    print("\n[=] Concluido. Loot em: " + os.path.abspath(outdir))


if __name__ == "__main__":
    main()
