# Necroscan

**Visual recon + wordlist reaper** — uma ferramenta só que rastreia um site, bate
screenshots de tudo (aquatone), minera palavras do próprio alvo e gera wordlists
completas no estilo **CeWL + cupp**, ainda fazendo **OSINT** de funcionários e
**fuzzing** de diretórios. Pensada para pentest com escopo, bug bounty e CTF.

> ⚠️ **Uso autorizado apenas.** Rode somente contra alvos que você tem permissão
> explícita para testar (seu lab, CTF, ou engajamento contratado). Você é o
> responsável pelo uso.

---

## Recursos

- **Crawler** de mesmo-domínio: coleta URLs, texto, meta tags, comentários HTML e atributos.
- **Wordlist de conteúdo** (CeWL): palavras do site ordenadas por frequência.
- **Mineração de `.js`**: extrai identificadores (quebra camelCase/snake), palavras e endpoints de API.
- **OSINT de pessoas**: detecta funcionários (nomes, e-mails, cargos) e gera **usernames** em todas as convenções (`jsilva`, `joao.silva`, `jsilva`...). **Detecta a convenção real de login** cruzando artefatos do site (ex: `/images/headshots/rweston.jpg`) com os nomes.
- **OSINT externo**: subdomínios via **crt.sh** + **theHarvester** (se instalado).
- **Screenshots**: integra o **aquatone** (acha o binário no PATH ou no WSL; autodetecta chromium).
- **Fuzzing**: brute de diretórios/arquivos com o **big.txt do SecLists** (usa ffuf/feroxbuster se houver, senão fuzzer interno).
- **Wordlist mestre única**: consolida tudo (seeds + site + funcionários + compostas + mutações), deduplicado e ordenado por relevância.
- **Filtro técnico**: remove ruído de JS/CSS/framework mantendo palavras valiosas.
- **Modo Profile (cupp)**: gera wordlist pelo perfil de um alvo, com ranking por probabilidade, filtro de política de senha, pacotes de país (BR/US/ES/global), saída em **regras hashcat** e OSINT automático sobre os dados.

---

## Instalação

```bash
pip install requests beautifulsoup4
# opcionais:
#  aquatone (screenshots):
go install github.com/michenriksen/aquatone@latest
#  ffuf/feroxbuster (fuzzing mais rápido) e theHarvester (OSINT) via gerenciador de pacotes
```

SecLists (para `--fuzz`): normalmente em `/usr/share/seclists` no Kali, ou use `--download-wordlist`.

---

## Uso

### Scan de site
```bash
python3 necroscan.py https://alvo.com
python3 necroscan.py https://alvo.com --depth 3 --osint --fuzz --with-count
python3 necroscan.py https://alvo.com --no-screens          # só wordlist
python3 necroscan.py https://alvo.com --plain               # sem mutações (enxuta)
python3 necroscan.py https://alvo.com --keep-parts          # salva componentes separados
```

### Modo Profile (estilo cupp)
```bash
python3 necroscan.py --profile                              # questionário interativo
python3 necroscan.py --profile --locale br,us,global        # pacotes de país
python3 necroscan.py --profile --policy "8,upper,digit,special" --max-words 50000
python3 necroscan.py --profile --rule                       # saída p/ hashcat (base + .rule)
python3 necroscan.py --profile --merge loot/alvo            # mistura OSINT já coletado
python3 necroscan.py --profile-file alvo.json               # não-interativo
```

---

## Saída (em `loot/<domínio>/`)

| Arquivo | Conteúdo |
|---|---|
| `wordlist.txt` | **Wordlist mestre** — tudo consolidado, por relevância |
| `urls.txt` | URLs encontradas no crawl |
| `endpoints.txt` | Endpoints extraídos dos `.js` |
| `usernames.txt` | Usernames dos funcionários (todas as convenções) `--osint` |
| `osint_people.txt` | Relatório por pessoa (usernames prováveis + e-mail) `--osint` |
| `emails.txt` | E-mails descobertos / candidatos |
| `subdomains.txt` | Subdomínios (crt.sh / theHarvester) `--osint` |
| `wordlist_counts.txt` | Palavra + frequência (CeWL `-c`) `--with-count` |
| `screenshots/aquatone_report.html` | Relatório visual do aquatone |
| `fuzz/` | Resultados do fuzzing (ffuf.json / feroxbuster / fuzz_results.txt) |
| `part_*.txt` | Componentes separados `--keep-parts` |

A wordlist mestre é ordenada por relevância: **seeds (empresa/subdomínios) → palavras
do site (+ `.js`) → funcionários/usernames → senhas compostas → mutações (leet, anos
reais do site, sufixos, especiais)**.

---

## Flags principais

**Scan:** `--depth N` · `--max-pages N` · `--out DIR` · `--timeout S`
**Wordlist:** `--plain` · `--keep-parts` · `--with-numbers` · `--lowercase` · `--min-len`/`--max-len` · `--no-combine` · `--no-tech-filter` · `--with-count`
**OSINT:** `--osint` · `--email-domain DOM` · `--no-people`
**JS:** `--no-js`
**Screenshots:** `--no-screens` · `--aquatone PATH` · `--chrome-path PATH` · `--threads N`
**Fuzzing:** `--fuzz` · `--fuzz-wordlist PATH` · `--fuzz-ext php,bak,txt` · `--fuzz-codes 200,301,403` · `--fuzz-threads N` · `--download-wordlist`
**Profile:** `--profile` · `--profile-file JSON` · `--merge PATH` · `--locale br,us,es,global|all` · `--policy "8,upper,digit,special"` · `--max-words N` · `--rule`

---

## Modo Profile — detalhes

Questionário (nome, sobrenome, apelido, nascimento, parceiro(a), filhos/pets,
empresa, palavras extras) → gera combinações com datas em vários formatos, leet,
capitalização, especiais e combinações par-a-par (multi-pessoa). Extras:

- **Ranking por probabilidade** (nome+ano+especial no topo).
- **Filtro de política** `--policy` (só o que casa com a regra do alvo).
- **Pacotes de país** `--locale` (dicionários locais que entram isolados).
- **Modo hashcat** `--rule`: gera `*_base.txt` + `*.rule` (leet, especiais e **anos do alvo** como regras) para expandir na GPU:
  ```bash
  hashcat -a 0 -m <hash> alvo.hash profile_x_base.txt -r profile_x.rule
  ```
- **OSINT automático**: dos nomes informados, gera usernames do alvo e do(a) parceiro(a); se a empresa for um domínio (ou `--email-domain`), puxa subdomínios/e-mails.

---

## Requisitos

- Python 3.8+ com `requests` e `beautifulsoup4`.
- Opcionais: `aquatone` + chromium (screenshots), `ffuf`/`feroxbuster` (fuzzing), `theHarvester` (OSINT), SecLists (big.txt).

---

## Aviso legal

Ferramenta de segurança ofensiva de uso **dual**. Destinada a testes autorizados,
pesquisa e educação. Não use contra sistemas sem autorização explícita e por
escrito. O autor e os contribuidores não se responsabilizam por uso indevido.

## Licença

MIT — veja [LICENSE](LICENSE).
