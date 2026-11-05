#!/usr/bin/env python3
"""
Carlos Proxy V39 - parche + re-firma (v1 + v2) en Python puro.
Sin Java, sin apktool, sin apksigner.

PARCHES APLICADOS
 1. package: "com.edsonmodz.vpn" -> "com.Carlos.Modzofc"   (el check无比 fallaba)
 2. fingerprint de firma -> SHA-256 del nuevo certificado
 3. LoginActivity.onCreate -> unlockApp() (ya no manda al canal de WhatsApp)
 4. MTU 1500 -> 1400 (TUN + tunnel.yml + log)
 5. DNS 1.1.1.1 -> 8.8.8.8
 6. ThreadPoolExecutor de La/Z: core 0 -> 8, keepAlive 30 -> 60
 7. ThreadPoolExecutor de La/N: core 1 -> 4, max 1 -> 8, cola 1 -> 8
"""
import hashlib, io, os, struct, sys, zipfile, base64, shutil, datetime, zlib
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.serialization import pkcs7

SRC_DIR = "/home/user/app-hack/Carlos Proxy V39\u003f\u003f\u003f"
SRC_DIR = "/home/user/app-hack/Carlos Proxy V39\U0001F9F8"
OUT_APK = "/home/user/app-hack/Carlos Proxy V39 PERU (patched).apk"
KEY_PEM = "/home/user/app-hack/carlos-release-key.pem"
CRT_PEM = "/home/user/app-hack/carlos-release-cert.pem"

log = lambda *a: print(*a, flush=True)

# ---------------------------------------------------------------- certificados
def make_key_cert():
    if os.path.exists(KEY_PEM) and os.path.exists(CRT_PEM):
        key = serialization.load_pem_private_key(open(KEY_PEM,'rb').read(), None)
        crt = x509.load_pem_x509_certificate(open(CRT_PEM,'rb').read())
        log("[*] Reutilizando clave existente")
        return key, crt
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subj = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Carlos Proxy V39 PERU"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EdsonModz"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PE"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    crt = (x509.CertificateBuilder()
           .subject_name(subj).issuer_name(subj)
           .public_key(key.public_key())
           .serial_number(x509.random_serial_number())
           .not_valid_before(now - datetime.timedelta(days=1))
           .not_valid_after(now + datetime.timedelta(days=3650))
           .sign(key, hashes.SHA256()))
    open(KEY_PEM,'wb').write(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    open(CRT_PEM,'wb').write(crt.public_bytes(serialization.Encoding.PEM))
    log("[+] Clave + certificado generados")
    return key, crt

key, cert = make_key_cert()
cert_der = cert.public_bytes(serialization.Encoding.DER)
FINGERPRINT = hashlib.sha256(cert_der).hexdigest()
log("[*] SHA-256 del certificado (nuevo fingerprint):", FINGERPRINT)

# ---------------------------------------------------------------- DEX patches
sys.path.insert(0, "/tmp/venv/lib/python3.11/site-packages")
from androguard.core.dex import DEX

DEX_PATH = os.path.join(SRC_DIR, "classes.dex")
raw = bytearray(open(DEX_PATH, 'rb').read())
d = DEX(bytes(raw))
header = d.header
DATA_OFF = header.data_off
applied = []

def read_uleb(buf, off):
    res = 0; shift = 0
    while True:
        b = buf[off]; off += 1
        res |= (b & 0x7f) << shift
        if not (b & 0x80): break
        shift += 7
    return res, off

def string_item_offset(target):
    """Devuelve el offset absoluto de los bytes del string en el fichero DEX."""
    for s in d.strings:
        if s.get() != target: continue
        item_off = s.get_off()
        for cand in (item_off, DATA_OFF + item_off):
            try:
                ln, p = read_uleb(raw, cand)
            except IndexError:
                continue
            if ln == len(target) and bytes(raw[p:p+ln]) == target.encode('utf-8'):
                return p, ln
    return None, None

def patch_string(target, new, note):
    """Sustituye un string del pool por otro de la MISMA longitud (in-place)."""
    global raw
    off, ln = string_item_offset(target)
    if off is None:
        log(f"  [!] string no encontrado: {target!r}"); return False
    if len(new) != len(target):
        log(f"  [!] longitud distinta {len(target)} != {len(new)}"); return False
    raw[off:off+ln] = new.encode('utf-8')
    applied.append(note)
    log(f"  [+] {note}\n      {target!r} -> {new!r}")
    return True

def patch_string_in(target, old_sub, new_sub, note):
    """Sustituye una subcadena dentro de un string del pool (misma longitud)."""
    global raw
    off, ln = string_item_offset(target)
    if off is None:
        log(f"  [!] string no encontrado: {target!r}"); return False
    chunk = bytes(raw[off:off+ln])
    if old_sub.encode() not in chunk:
        log(f"  [!] subcadena {old_sub!r} no esta en el string"); return False
    if len(old_sub) != len(new_sub):
        log("  [!] longitudes distintas"); return False
    raw[off:off+ln] = chunk.replace(old_sub.encode(), new_sub.encode())
    applied.append(note)
    log(f"  [+] {note}\n      {old_sub!r} -> {new_sub!r} (dentro de {target[:28]!r}...)")
    return True

def find_method(cname, mname, mdesc=None):
    for c in d.get_classes():
        if c.get_name() != cname: continue
        for m in c.get_methods():
            if m.get_name() != mname: continue
            if mdesc and m.get_descriptor() != mdesc: continue
            return m
    return None

def insns(m):
    """Yields (offset absoluto, instruccion) dentro del code_item."""
    base = m.get_code().get_off() + 16
    off = 0
    for ins in m.get_instructions():
        yield base + off, ins
        off += ins.get_length()

def patch_const16(m, pred, newval, note):
    """Cambia el literal de un const/16 (mismo tamano)."""
    global raw
    for off, ins in insns(m):
        if pred(off, ins):
            raw[off+2:off+4] = struct.pack('<H', newval & 0xffff)
            applied.append(note)
            log(f"  [+] {note}  (offset 0x{off:x})")
            return True
    log(f"  [!] no se encontro la instruccion para {note}")
    return False

def patch_const4(m, pred, newval, note):
    """Cambia el literal de un const/4 (mismo tamano, nibble bajo)."""
    global raw
    for off, ins in insns(m):
        if pred(off, ins):
            b = raw[off+1]
            raw[off+1] = (b & 0xf0) | (newval & 0x0f)
            applied.append(note)
            log(f"  [+] {note}  (offset 0x{off:x})")
            return True
    log(f"  [!] no se encontro la instruccion para {note}")
    return False

def patch_const_wide16(m, pred, newval, note):
    global raw
    for off, ins in insns(m):
        if pred(off, ins):
            raw[off+2:off+4] = struct.pack('<H', newval & 0xffff)
            applied.append(note)
            log(f"  [+] {note}  (offset 0x{off:x})")
            return True
    log(f"  [!] no se encontro la instruccion para {note}")
    return False

log("\n=== 1. PARCHES DE STRINGS ===")
# el package real ("com.Carlos.Modzofc", 18 chars) no cabe in-place en el string de 17 chars:
# en su lugar se neutraliza la comprobacion del paquete (goto al siguiente bloque).
def skip_package_check():
    global raw
    m = find_method("Lcom/edsonmodz/vpn/App;", "onCreate")
    seq = list(insns(m))
    for i, (off, ins) in enumerate(seq):
        if "String;->equals" in ins.get_output() and i >= 2:
            prev_consts = [x.get_output() for (o, x) in seq[:i] if "com.edsonmodz.vpn" in x.get_output()]
            if not prev_consts:
                continue
            # el if-eqz siguiente al move-result
            for j in range(i+1, min(i+4, len(seq))):
                o2, x2 = seq[j]
                if x2.get_name().startswith("if-eqz"):
                    raw[o2] = 0x28          # if-eqz -> goto
                    raw[o2+1] = 0x00
                    struct.pack_into('<h', raw, o2+2, 1)   # +1 code unit = siguiente instr
                    applied.append('package check neutralizado (goto) - el manifiesto dice com.Carlos.Modzofc')
                    log(f"  [+] package check neutralizado con goto (+1) en 0x{o2:x}")
                    return True
    return False

skip_package_check()
patch_string("2015efadf6638a632348f163363e7f47bab37a2a7543b9bbf8258e7f504c9b81",
             FINGERPRINT, "fingerprint de firma -> certificado nuevo")
patch_string_in("tunnel:\n  mtu: 1500\n  ipv4: 198.18.0.1\n  icmp: 'off'\nsocks5:\n"
                "  address: 127.0.0.1\n  port: ", "mtu: 1500", "mtu: 1400",
                "tunnel.yml: MTU 1500 -> 1400")
patch_string(" mtu=1500", " mtu=1400", "log: mtu=1500 -> mtu=1400")
patch_string("1.1.1.1", "8.8.8.8", "DNS del TUN: 1.1.1.1 -> 8.8.8.8")

log("\n=== 2. PARCHES DE BYTECODE ===")

# --- 2.1 MTU del VpnService.Builder (const/16 1500 justo antes de setMtu)
mV = find_method("La/V;", "run")
seqV = list(insns(mV))
for i, (off, ins) in enumerate(seqV):
    if "setMtu" in ins.get_output():
        prev = [(o, x) for (o, x) in seqV[:i] if x.get_name().startswith("const/16")]
        o0 = prev[-1][0]
        patch_const16(mV, lambda off2, ins2, o0=o0: off2 == o0, 1400,
                      "La/V: setMtu(1500) -> setMtu(1400)")
        break

# --- 2.2 La/N.<init>: cola y pool del planificador UDP
mN = find_method("La/N;", "<init>")
seq = list(insns(mN))
# cola: const/4 justo antes de ArrayBlockingQueue.<init>(I)
for i, (off, ins) in enumerate(seq):
    if "ArrayBlockingQueue;-><init>" in ins.get_output():
        patch_const4(mN, lambda off, ins, o=seq[i-1][0]: off == o, 8,
                     "La/N: ArrayBlockingQueue(1) -> (8)")
        break
# core/max: los dos const/4 anteriores al invoke del ThreadPoolExecutor
for i, (off, ins) in enumerate(seq):
    if "ThreadPoolExecutor;-><init>" in ins.get_output():
        c4 = [(o, x) for (o, x) in seq[:i] if x.get_name().startswith("const/4")][-2:]
        patch_const4(mN, lambda off, ins, o=c4[0][0]: off == o, 4,
                     "La/N: corePoolSize 1 -> 4")
        patch_const4(mN, lambda off, ins, o=c4[1][0]: off == o, 8,
                     "La/N: maximumPoolSize 1 -> 8")
        break

# --- 2.3 La/Z.<init>: core 0 -> 8 y keepAlive 30 -> 60
mZ = find_method("La/Z;", "<init>")
seqZ = list(insns(mZ))
for i, (off, ins) in enumerate(seqZ):
    if "ThreadPoolExecutor;-><init>" in ins.get_output():
        c4 = [(o, x) for (o, x) in seqZ[:i] if x.get_name().startswith("const/4")][-1:]
        patch_const4(mZ, lambda off, ins, o=c4[0][0]: off == o, 8,
                     "La/Z: corePoolSize 0 -> 8 (sin churn de hilos)")
        break
patch_const_wide16(mZ,
    lambda off, ins: ins.get_name().startswith("const-wide/16") and ins.get_output().endswith("30"),
    60, "La/Z: keepAlive 30s -> 60s")

# --- 2.4 LoginActivity.onCreate: openTelegramChannel() -> unlockApp()
mOC = find_method("Lcom/edsonmodz/vpn/LoginActivity;", "onCreate")
mOTC = find_method("Lcom/edsonmodz/vpn/LoginActivity;", "openTelegramChannel")
unlock_idx = None
for off, ins in insns(mOTC):
    if "unlockApp()V" in ins.get_output():
        unlock_idx = struct.unpack_from('<H', raw, off + 2)[0]
        break
if unlock_idx is None:
    log("  [!] no se encontro el method_id de unlockApp")
else:
    for off, ins in insns(mOC):
        if "openTelegramChannel()V" in ins.get_output():
            raw[off] = 0x6e                       # invoke-direct -> invoke-virtual
            struct.pack_into('<H', raw, off + 2, unlock_idx)
            applied.append("LoginActivity.onCreate: openTelegramChannel() -> unlockApp()")
            log(f"  [+] LoginActivity.onCreate: openTelegramChannel() -> unlockApp() "
                f"(method_id {unlock_idx}, offset 0x{off:x}) - ya no abre el canal de WhatsApp")
            break

# --- recalcular la firma (SHA-1) y el checksum (Adler-32) del DEX
import zlib
raw[12:32] = hashlib.sha1(bytes(raw[32:])).digest()
struct.pack_into('<I', raw, 8, zlib.adler32(bytes(raw[12:])) & 0xffffffff)
log("[*] firma SHA-1 y Adler-32 del DEX recalculados")

# --- verificacion: re-parsear el DEX parcheado
new_dex = bytes(raw)
d2 = DEX(new_dex)
strs2 = list(d2.get_strings())
assert FINGERPRINT in strs2, "fallo patch fingerprint"
assert any("mtu: 1400" in x for x in strs2), "fallo patch mtu"
assert "8.8.8.8" in strs2, "fallo patch dns"
# el package check ya no es un if-eqz sino un goto
_m = [x for x in d2.get_classes() if x.get_name()=="Lcom/edsonmodz/vpn/App;"][0]
_mo = [x for x in _m.get_methods() if x.get_name()=="onCreate"][0]
_names = [i.get_name() for i in _mo.get_instructions()]
assert "goto" in _names, "fallo patch package check"
# onCreate de LoginActivity debe llamar a unlockApp
_m2 = [x for x in d2.get_classes() if x.get_name()=="Lcom/edsonmodz/vpn/LoginActivity;"][0]
_m2o = [x for x in _m2.get_methods() if x.get_name()=="onCreate"][0]
_out = [i.get_output() for i in _m2o.get_instructions()]
assert any("unlockApp()V" in o for o in _out), "fallo patch whatsapp"
assert not any("openTelegramChannel" in o for o in _out), "sigue el gate de whatsapp"
log("[*] DEX re-parsed OK (%d strings, %d clases)" % (len(strs2), len(list(d2.get_classes()))))

# ---------------------------------------------------------------- empaquetado
def collect_entries():
    """Lee los ficheros del APK original (fuente = carpeta extraida)."""
    entries = []
    for root, _, files in os.walk(SRC_DIR):
        for fn in files:
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, SRC_DIR).replace(os.sep, '/')
            if rel.startswith("META-INF/"):
                continue
            entries.append((rel, open(full, 'rb').read()))
    return entries

entries = collect_entries()
log("[*] %d entradas (sin META-INF)" % len(entries))
new_dex_entry = ("classes.dex", new_dex)
entries = [(n, new_dex_entry[1] if n == "classes.dex" else data) for n, data in entries]
order = {n: i for i, (n, _) in enumerate(entries)}
entries.sort(key=lambda kv: (0 if kv[0].startswith("META-INF/") else 1,))

# ---------- firma v1 (JAR) ----------
def v1_sign(entries, key, cert):
    mf = "Manifest-Version: 1.0\r\nCreated-By: 1.0 (Arena)\r\n\r\n"
    sections = []
    for name, data in entries:
        if name.startswith("META-INF/"): continue
        dig = base64.b64encode(hashlib.sha256(data).digest()).decode()
        sec = f"Name: {name}\r\nSHA-256-Digest: {dig}\r\n\r\n"
        sections.append((name, sec)); mf += sec
    mf_bytes = mf.encode('utf-8')
    manifest_digest = base64.b64encode(hashlib.sha256(mf_bytes).digest()).decode()
    sf = ("Signature-Version: 1.0\r\nCreated-By: 1.0 (Arena)\r\n"
          f"SHA-256-Digest-Manifest: {manifest_digest}\r\n\r\n")
    for name, sec in sections:
        d = base64.b64encode(hashlib.sha256(sec.encode('utf-8')).digest()).decode()
        sf += f"Name: {name}\r\nSHA-256-Digest: {d}\r\n\r\n"
    sf_bytes = sf.encode('utf-8')
    rsa_der = (pkcs7.PKCS7SignatureBuilder().set_data(sf_bytes)
               .add_signer(cert, key, hashes.SHA256())
               .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.DetachedSignature]))
    return [("META-INF/MANIFEST.MF", mf_bytes),
            ("META-INF/CERT.SF", sf_bytes),
            ("META-INF/CERT.RSA", rsa_der)]

sig_entries = v1_sign(entries, key, cert)
entries = entries + sig_entries

# ---------- construccion del ZIP (sin bloque de firma todavia) ----------
# Layout ESTANDAR de Android (igual que Android Studio / zipalign -p 4):
#   resources.arsc : STORED (sin comprimir) + alineado a 4 bytes
#   lib/**/*.so     : STORED + alineado a 4096 bytes (extra field 0xD935)
#   resto           : DEFLATE
# Android 11+ (targetSdk>=30) exige esto para extraeNativeLibs=false:
# si no, el instalador responde INSTALL_FAILED_INVALID_APK.
ALIGN_RES = 4
ALIGN_SO = 4096
DOS_TIME = 0
DOS_DATE = ((2024 - 1980) << 9) | (1 << 5) | 1

def align_for(name):
    if name == "resources.arsc":
        return ALIGN_RES
    if name.startswith("lib/") and name.endswith(".so"):
        return ALIGN_SO
    return 0

def build_zip(entries):
    out = bytearray()
    central = bytearray()
    for name, data in entries:
        nb = name.encode('utf-8')
        align = align_for(name)
        method = 0 if align else 8           # STORED para .arsc y .so
        if method == 0:
            comp = data
        else:
            co = zlib.compressobj(9, zlib.DEFLATED, -15)
            comp = co.compress(data) + co.flush()
        crc = zlib.crc32(data) & 0xffffffff
        extra = b''
        if align:
            base = len(out) + 30 + len(nb)   # inicio del extra field
            pad = (-base) % align
            if pad:
                if pad < 4:
                    pad += align            # el extra field necesita >= 4 bytes
                extra = struct.pack('<HH', 0xD935, pad - 4) + b'\x00' * (pad - 4)
        local_off = len(out)
        out += struct.pack('<IHHHHHIIIHH', 0x04034b50, 20, 0, method,
                           DOS_TIME, DOS_DATE, crc, len(comp), len(data),
                           len(nb), len(extra))
        out += nb + extra + comp
        ext_attr = (0o755 << 16) if name.endswith('.so') else (0o644 << 16)
        central += struct.pack('<IHHHHHHIIIHHHHHII', 0x02014b50, 0x0314, 20, 0,
                               method, DOS_TIME, DOS_DATE, crc, len(comp), len(data),
                               len(nb), 0, 0, 0, 0, ext_attr, local_off)
        central += nb
    cd_off = len(out)
    out += central
    cd_size = len(central)
    eocd = struct.pack('<IHHHHIIH', 0x06054b50, 0, 0, len(entries), len(entries),
                       cd_size, cd_off, 0)
    out += eocd
    return bytes(out), cd_off, cd_size, eocd

blob, cd_off, cd_size, eocd_bytes = build_zip(entries)
eocd_bytes = bytearray(eocd_bytes)

def find_eocd(b):
    i = b.rfind(b'PK\x05\x06')
    if i < 0: raise SystemExit("no EOCD")
    return i

data_section = blob[:cd_off]
cd_bytes = blob[cd_off:cd_off + cd_size]
# la seccion de datos termina en multiplo de 4096 (como hace apksigner)
pad = (-len(data_section)) % 4096
if pad:
    data_section += b'\x00' * pad
    cd_off += pad
signing_block_offset = cd_off
log("[*] seccion de datos: %d bytes (padding 4096: %d)" % (len(data_section), pad))

# ---------- digest de contenido v2 (1 MB chunks, AOSP) ----------
def content_digest(data, cd, eocd_with_offset):
    chunks = []
    for seg in (data, cd, eocd_with_offset):
        for i in range(0, len(seg), 1024*1024):
            chunks.append(seg[i:i+1024*1024])
    digests = b''
    for ch in chunks:
        h = hashlib.sha256()
        h.update(b'\xa5' + struct.pack('<I', len(ch)) + ch)
        digests += h.digest()
    out = hashlib.sha256()
    out.update(b'\x5a' + struct.pack('<I', len(chunks)) + digests)
    return out.digest()

eocd_for_digest = bytearray(eocd_bytes)
struct.pack_into('<I', eocd_for_digest, 16, signing_block_offset)
digest = content_digest(data_section, cd_bytes, bytes(eocd_for_digest))

# ---------- bloque de firma v2 ----------
# Codificacion EXACTA de apksig (V2SchemeSigner) + verificador AOSP:
#   seq(elements)   = concat( uint32 len(e) + e )            (sin total)
#   pairs(elements) = concat( uint32 (8+len) + uint32 alg + uint32 len + bytes )
#   v2value         = seq([ seq([signer]) ])
def seq(elements):
    return b''.join(struct.pack('<I', len(e)) + e for e in elements)

def pairs(elements):
    out = b''
    for alg, b in elements:
        out += struct.pack('<I', 8 + len(b)) + struct.pack('<I', alg) + struct.pack('<I', len(b)) + b
    return out

pubkey_der = cert.public_key().public_bytes(
    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

digests_blob = pairs([(0x0103, digest)])          # RSASSA-PKCS1-v1_5 + SHA-256
certs_blob = seq([cert_der])
signed_data = seq([digests_blob, certs_blob, b'', b''])
signature = key.sign(signed_data, asym_padding.PKCS1v15(), hashes.SHA256())
signer = seq([signed_data, pairs([(0x0103, signature)]), pubkey_der])
v2_value = seq([seq([signer])])

MAGIC = b'APK Sig Block 42'
VERITY_PADDING_ID = 0x42726177
def make_signing_block(pairs_list):
    blocks_size = sum(8 + 4 + len(v) for _, v in pairs_list)
    result_size = 8 + blocks_size + 8 + 16
    pad = None
    if result_size % 4096 != 0:
        padding = 4096 - (result_size % 4096)
        if padding < 12: padding += 4096
        pad = struct.pack('<Q', padding - 8) + struct.pack('<I', VERITY_PADDING_ID) + b'\x00'*(padding-12)
        result_size += padding
    out = struct.pack('<Q', result_size - 8)
    for bid, val in pairs_list:
        out += struct.pack('<Q', 4 + len(val)) + struct.pack('<I', bid) + val
    if pad: out += pad
    out += struct.pack('<Q', result_size - 8) + MAGIC
    return out

signing_block = make_signing_block([(0x7109871a, v2_value)])

# ---------- ensamblado final ----------
eocd_final = bytearray(eocd_bytes)
struct.pack_into('<I', eocd_final, 16, cd_off + len(signing_block))
final = data_section + signing_block + cd_bytes + bytes(eocd_final)
open(OUT_APK, 'wb').write(final)
log("[+] APK escrito:", OUT_APK, os.path.getsize(OUT_APK), "bytes")

# ---------------------------------------------------------------- verificacion
log("\n=== 3. VERIFICACION (siguiendo el parser de AOSP) ===")
zf = zipfile.ZipFile(OUT_APK)
bad = zf.testzip()
log("  zip integro:", "OK" if bad is None else f"CORRUPTO {bad}")
log("  entradas:", len(zf.namelist()))

def read_lp(buf, off):
    ln = struct.unpack_from('<I', buf, off)[0]; off += 4
    return buf[off:off+ln], off+ln

b = open(OUT_APK, 'rb').read()
e2 = find_eocd(b)
cd_size2, cd_off2 = struct.unpack_from('<II', b, e2 + 12)
block_end = cd_off2 - 16
block_size = struct.unpack_from('<Q', b, block_end - 8)[0]
block_start = block_end + 8 - block_size
log("  magic APK Sig Block 42:", "OK" if b[block_end:block_end+16] == MAGIC else "MAL")
log("  bloque alineado a 4096:", "OK" if block_start % 4096 == 0 else "MAL")
log("  recursos y libs descomprimidos+alineados (offset real de datos):")
for _inf in zf.infolist():
    _al = align_for(_inf.filename)
    if not _al:
        continue
    _nl, _el = struct.unpack_from('<HH', b, _inf.header_offset + 26)
    _doff = _inf.header_offset + 30 + _nl + _el
    log("    %-48s %-8s off=%-9d align%d: %s" % (
        _inf.filename, "STORE" if _inf.compress_type == 0 else "DEFLATE",
        _doff, _al, "OK" if _doff % _al == 0 else "MAL"))
pos = block_start + 8
v2val = None
while pos < block_end - 8:
    plen = struct.unpack_from('<Q', b, pos)[0]; pos += 8
    bid = struct.unpack_from('<I', b, pos)[0]; pos += 4
    val = b[pos:pos+plen-4]; pos += plen-4
    if bid == 0x7109871a: v2val = val
log("  bloque v2 (0x7109871a):", "OK" if v2val else "NO")

signers, _ = read_lp(v2val, 0)          # length-prefixed sequence of signers
signer_b, _ = read_lp(signers, 0)       # un signer
sd, o1 = read_lp(signer_b, 0)           # signed data
sigs, o2 = read_lp(signer_b, o1)        # signatures
pub, o3 = read_lp(signer_b, o2)         # public key
digs_b, p1 = read_lp(sd, 0)             # digests
certs_b, p2 = read_lp(sd, p1)           # certificates
attrs_b, p3 = read_lp(sd, p2)           # additional attributes
digest_entry, _ = read_lp(digs_b, 0)    # uint32 alg + uint32 len + digest
alg = struct.unpack_from('<I', digest_entry, 0)[0]
dl = struct.unpack_from('<I', digest_entry, 4)[0]
stored_digest = digest_entry[8:8+dl]
cert_in_block, _ = read_lp(certs_b, 0)
sig_entry, _ = read_lp(sigs, 0)
salg = struct.unpack_from('<I', sig_entry, 0)[0]
sl = struct.unpack_from('<I', sig_entry, 4)[0]
sig_bytes = sig_entry[8:8+sl]
log(f"  digest alg=0x{alg:04x} sig alg=0x{salg:04x}")
log("  certificado en el bloque coincide con el nuestro:",
    "OK" if cert_in_block == cert_der else "NO")

data_sec = b[:block_start]
cd_b = b[cd_off2:cd_off2+cd_size2]
eocd_f = bytearray(b[e2:])
struct.pack_into('<I', eocd_f, 16, block_start)
dg = content_digest(data_sec, cd_b, bytes(eocd_f))
log("  digest de contenido v2 recomputado:", "OK" if dg == stored_digest else "NO  <-- ERROR")
try:
    cert.public_key().verify(sig_bytes, sd, asym_padding.PKCS1v15(), hashes.SHA256())
    log("  firma v2 sobre signed-data:", "OK")
except Exception as e:
    log("  firma v2 sobre signed-data: NO ->", e)
try:
    pkcs7.load_der_pkcs7_certificates(zf.read("META-INF/CERT.RSA"))
    log("  CERT.RSA (PKCS#7) parsea:", "OK")
except Exception as e:
    log("  CERT.RSA: NO ->", e)

mf = zf.read("META-INF/MANIFEST.MF").decode('utf-8')
ok_v1 = True
for sec in mf.split("\r\n\r\n"):
    if not sec.startswith("Name: "): continue
    name = sec.split("\r\n")[0][6:]
    dig = [l.split(": ",1)[1] for l in sec.split("\r\n") if l.startswith("SHA-256-Digest: ")][0]
    if base64.b64encode(hashlib.sha256(zf.read(name)).digest()).decode() != dig:
        ok_v1 = False; log("   digest v1 mismatch:", name)
log("  firma v1 (JAR) digests:", "OK" if ok_v1 else "FALLO")

d3 = DEX(zf.read("classes.dex"))
s3 = list(d3.get_strings())
log("  DEX final parsea:", "OK", f"({len(s3)} strings, {len(list(d3.get_classes()))} clases)")
log("  fingerprint en el DEX:", "OK" if FINGERPRINT in s3 else "NO")

log("\n=== RESUMEN DE PARCHES (%d) ===" % len(applied))
for a in applied: log("  -", a)
log("\nFingerprint SHA-256 del certificado nuevo:", FINGERPRINT)
