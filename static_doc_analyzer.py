import os
import re
import sys
import zlib
import zipfile
import binascii

# ==============================================================================
# CONFIGURATION DE SÉCURITÉ (OPSEC AVANCÉE)
# ==============================================================================
MAX_STREAM_SIZE = 25 * 1024 * 1024  # 25 Mo max par flux/fichier
MAX_ZIP_FILES = 500                 # Arrêt du parsing après 500 fichiers (Anti-fragmentation)
CHUNK_SIZE = 1024 * 1024            # Analyse par blocs de 1 Mo (Anti-ReDoS)
OVERLAP = 1024                      # Chevauchement de 1 Ko entre les blocs

def sanitize_filename(filename):
    safe_name = os.path.basename(filename)
    return re.sub(r'[^a-zA-Z0-9_.\-]', '_', safe_name)

def decode_pdf_hex(text):
    """Désobfusque les tags PDF encodés en hexa (ex: /J#61vaScript -> /JavaScript)."""
    def hex_repl(match):
        try:
            return bytes([int(match.group(1), 16)])
        except ValueError:
            return match.group(0)
    return re.sub(rb'#([0-9a-fA-F]{2})', hex_repl, text)

# ==============================================================================
# MOTEUR DE SIGNATURES COMPORTEMENTALES
# ==============================================================================
# (Pré-compilation des regex pour optimiser les performances CPU)
THREAT_SIGNATURES = {
    "Network / Droppers": [
        re.compile(rb"(?i)(?:System\.Net\.WebClient|Net\.WebRequest|WinHttp\.WinHttpRequest)"),
        re.compile(rb"(?i)\.DownloadString\s*\("),
        re.compile(rb"(?i)\.DownloadFile\s*\("),
        re.compile(rb"(?i)Invoke-WebRequest"),
        re.compile(rb"(?i)WScript\.Network")
    ],
    "Windows Execution Chains": [
        re.compile(rb"(?i)\bcmd(?:\.exe)?\s*(?:/c|/k)\b"),
        re.compile(rb"(?i)\bpowershell(?:\.exe)?\s+-(?:enc|nop|w|ep)\b"),
        re.compile(rb"(?i)\bsc(?:\.exe)?\s+(?:create|start|config)\b"),
        re.compile(rb"(?i)\bcscript(?:\.exe)?\s+(?://B|//E:)\b"),
        re.compile(rb"(?i)\bmshta(?:\.exe)?\s+(?:http|vbscript:)\b"),
        re.compile(rb"(?i)\bregsvr32(?:\.exe)?\s+(?:/s|/u|/i:)\b"),
        re.compile(rb"(?i)\brundll32(?:\.exe)?\s+[^\s]+\.dll\s*,\s*[^\s]+"),
        re.compile(rb"(?i)\bInvoke-Expression\b|\bIEX\s*\("),
    ],
    "Reverse Shells & Linux": [
        re.compile(rb"\bbash\s+-i\b"),
        re.compile(rb"\bnc\s+-e\s+/bin/(?:ba)?sh\b"),
        re.compile(rb"/dev/tcp/\d{1,3}(?:\.\d{1,3}){3}/\d{1,5}"),
    ],
    "Macros VBA Malveillantes": [
        re.compile(rb"(?i)WScript\.Shell"),
        re.compile(rb"(?i)Shell\.Application"),
        re.compile(rb"(?i)Adodb\.Stream"),
        re.compile(rb"(?i)Scripting\.FileSystemObject"),
        re.compile(rb"(?i)Environ\s*\(\s*[\"'](?:TEMP|APPDATA|USERPROFILE)[\"']\s*\)"),
        re.compile(rb"(?i)ChrW?\s*\(\s*\d+\s*\)"),
    ]
}

# ==============================================================================
# FONCTIONS UTILITAIRES SÉCURISÉES
# ==============================================================================

def scan_buffer(data, source_name="Buffer"):
    """Scanne un buffer en utilisant le chunking pour éviter les attaques ReDoS."""
    findings = {}

    # Découpage du buffer en chunks (Anti-ReDoS)
    for i in range(0, len(data), CHUNK_SIZE - OVERLAP):
        chunk = data[i:i + CHUNK_SIZE]

        for category, patterns in THREAT_SIGNATURES.items():
            for pattern in patterns:
                for match in pattern.finditer(chunk):
                    match_str = match.group(0).decode('utf-8', errors='ignore').strip()
                    if match_str:
                        findings.setdefault(category, set()).add(f"[{source_name}] {match_str}")
    return findings

def extract_strings(data, min_length=5):
    ascii_pattern = rb'[\x20-\x7E]{%d,}' % min_length
    unicode_pattern = rb'(?:[\x20-\x7E]\x00){%d,}' % min_length

    strings = []
    # Les regex de strings sont exécutées de manière bornée grâce au chunking en amont
    for match in re.finditer(ascii_pattern, data):
        strings.append(match.group(0))
    for match in re.finditer(unicode_pattern, data):
        strings.append(match.group(0).replace(b'\x00', b''))

    return b' '.join(strings)

# ==============================================================================
# PARSERS SPÉCIFIQUES BLINDÉS
# ==============================================================================

class DeepPDFParser:
    def __init__(self, filepath):
        self.filepath = filepath
        with open(filepath, 'rb') as f:
            self.content = f.read(MAX_STREAM_SIZE * 2)

    def parse(self):
        print(f"[*] Parsing structurel PDF profond : {self.filepath}")
        findings = {}

        obj_pattern = re.compile(rb'(\d+)\s+\d+\s+obj(.*?)endobj', re.DOTALL)
        objects = obj_pattern.findall(self.content)

        for obj_id, obj_content in objects:
            safe_obj_name = f"Object_{obj_id.decode('utf-8', errors='ignore')}"

            # Anti-Évasion : Décodage des tags hexadécimaux
            normalized_content = decode_pdf_hex(obj_content)

            suspect_tags = [b'/JS', b'/JavaScript', b'/OpenAction', b'/Launch', b'/SubmitForm']
            for tag in suspect_tags:
                if tag in normalized_content:
                    findings.setdefault("PDF Structural Triggers", set()).add(f"[{safe_obj_name}] Tag détecté : {tag.decode('utf-8')}")

            if b'stream' in obj_content:
                stream_match = re.search(rb'stream[\r\n\s]+(.*?)[\r\n\s]+endstream', obj_content, re.DOTALL)
                if stream_match:
                    raw_stream = stream_match.group(1)
                    if b'/FlateDecode' in obj_content:
                        try:
                            decompress_obj = zlib.decompressobj()
                            decoded = decompress_obj.decompress(raw_stream, MAX_STREAM_SIZE)

                            res = scan_buffer(decoded, safe_obj_name)
                            for k, v in res.items():
                                findings.setdefault(k, set()).update(v)
                        except zlib.error as e:
                            # Fin du "Silent Fail" : on loggue l'anomalie structurelle
                            findings.setdefault("Structural Anomalies", set()).add(f"[{safe_obj_name}] Erreur Zlib (Fichier potentiellement malformé/obfusqué)")
                    else:
                        res = scan_buffer(raw_stream[:MAX_STREAM_SIZE], safe_obj_name)
                        for k, v in res.items():
                            findings.setdefault(k, set()).update(v)

        return findings

class DeepOOXMLParser:
    def __init__(self, filepath):
        self.filepath = filepath

    def parse(self):
        print(f"[*] Parsing structurel OOXML (ZIP/Rels) : {self.filepath}")
        findings = {}

        try:
            with zipfile.ZipFile(self.filepath, 'r') as z:
                files = z.namelist()

                # Anti-Épuisement : Arrêt prématuré si l'archive contient trop de fichiers
                if len(files) > MAX_ZIP_FILES:
                    findings.setdefault("Structural Anomalies", set()).add(f"Archive suspecte : Plus de {MAX_ZIP_FILES} fichiers internes.")
                    files = files[:MAX_ZIP_FILES]

                for f_name in files:
                    safe_f_name = sanitize_filename(f_name)

                    if not f_name.endswith(('.xml', '.bin', '.vbs', '.rels', '.ps1')):
                        continue

                    try:
                        with z.open(f_name) as f:
                            data = f.read(MAX_STREAM_SIZE)
                    except Exception as e:
                        findings.setdefault("Structural Anomalies", set()).add(f"[{safe_f_name}] Impossible de lire le fichier dans l'archive.")
                        continue

                    if f_name.endswith('.rels'):
                        rel_pattern = rb'<Relationship[^>]+>'
                        for rel_match in re.finditer(rel_pattern, data):
                            rel_tag = rel_match.group(0)
                            if b'TargetMode="External"' in rel_tag or b"TargetMode='External'" in rel_tag:
                                target_match = re.search(rb'Target=[\'"]([^\'"]+)[\'"]', rel_tag)
                                if target_match:
                                    target = target_match.group(1).decode('utf-8', errors='ignore')
                                    if target.startswith(('http', 'smb', '\\\\')):
                                        findings.setdefault("OOXML External Relationships (Template Injection)", set()).add(
                                            f"[{safe_f_name}] Lien externe suspect : {target}"
                                        )

                    elif "vbaProject.bin" in f_name or f_name.endswith(('.bin', '.vbs', '.ps1')):
                        findings.setdefault("Office Macro Structure", set()).add(f"Composant script/macro trouvé : {safe_f_name}")
                        text_strings = extract_strings(data)
                        res = scan_buffer(text_strings, safe_f_name)
                        for k, v in res.items():
                            findings.setdefault(k, set()).update(v)

                    elif f_name.endswith('.xml'):
                        res = scan_buffer(data, safe_f_name)
                        for k, v in res.items():
                            findings.setdefault(k, set()).update(v)

        except zipfile.BadZipFile:
             return self.fallback_parse()

        return findings

    def fallback_parse(self):
        print(f"[!] Fichier non-ZIP. Bascule sur l'extracteur binaire OLE/Legacy.")
        try:
            with open(self.filepath, 'rb') as f:
                data = f.read(MAX_STREAM_SIZE * 2)
                if data.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"):
                    print("[*] Structure OLE (Format Legacy) détectée.")

                text_strings = extract_strings(data)
                return scan_buffer(text_strings, "Legacy Binary")
        except Exception:
            return {"Structural Anomalies": set(["Impossible de parser le binaire de repli."])}

# ==============================================================================
# POINT D'ENTRÉE
# ==============================================================================

def main(target_path):
    if not os.path.exists(target_path):
        print(f"[-] Erreur : Fichier '{target_path}' introuvable.")
        sys.exit(1)

    ext = os.path.splitext(target_path)[1].lower()

    if ext == ".pdf":
        parser = DeepPDFParser(target_path)
    elif ext in [".docx", ".xlsx", ".docm", ".xlsm", ".pptx", ".pptm"]:
        parser = DeepOOXMLParser(target_path)
    else:
        parser = DeepOOXMLParser(target_path)

    results = parser.parse()

    print("\n" + "=" * 70)
    print(f"RAPPORT DE PARSING PROFOND (HARDENED) : {sanitize_filename(target_path)}")
    print("=" * 70)

    if not results:
        print("[+] Fichier sain : Aucune structure d'exécution ni payload détectés.")
    else:
        print("[ALERT] Éléments suspects ou malveillants confirmés :")
        for category, items in results.items():
            print(f"\n[!] {category} :")
            for item in items:
                print(f"    - {item}")
    print("=" * 70 + "\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python deep_doc_parser_hardened.py <chemin_du_document>")
        sys.exit(1)
    main(sys.argv[1])
