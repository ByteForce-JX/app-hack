# Carlos Proxy V39 — versión PERU (parcheada + re-firmada)

APK re-construido en Python puro (sin Java/apktool/apksigner), con la capa de red corregida,
el candado de WhatsApp eliminado y firma v1+v2 válida.

Archivo entregable: **`Carlos Proxy V39 PERU (patched).apk`**
(Package `com.Carlos.Modzofc` · versionName `0.5-final43` · versionCode `110` · minSdk 24 · targetSdk 35)

---

## 1. Por qué la app original no arrancaba

Había **tres bloqueos encadenados**, todos en `Application.onCreate()`:

| # | Comprobación | Qué pasaba | Arreglo |
|---|---|---|---|
| 1 | `getPackageName().equals("com.edsonmodz.vpn")` | El manifiesto dice `com.Carlos.Modzofc` → `SecurityException("package")` | Check neutralizado (`goto`) |
| 2 | SHA-256 del cert de firma == `2015efad…` | El APK venía firmado con la clave de test de AOSP (`a40da80a…`) → `SecurityException("signer")` | Fingerprint sustituido por el del cert nuevo |
| 3 | `LoginActivity.onCreate` → `openTelegramChannel()` | Abría el canal de WhatsApp y **solo** desbloqueabas al volver de él | `onCreate` llama directamente a `unlockApp()` |

Extra: `FirebaseValidator` **nunca se instancia** (código muerto) → no hay validación de licencia en runtime.

## 2. Parches aplicados (12)

### Arranque / firma
| # | Patch | Efecto |
|---|---|---|
| 1 | Check de package → `goto +1` | La app ya no muere con `SecurityException("package")` |
| 2 | `"2015efad…"` → `2f980250b40d59ada1bea3655d359810cd55f3cc00bff514e5d4f104d1ee78c1` | El hash del cert nuevo coincide con lo que la app exige |
| 3 | `LoginActivity.onCreate`: `openTelegramChannel()` → `unlockApp()` | **Ya no te manda al canal de WhatsApp**; entra directo a `MainActivity` |

### Red / latencia (esto es lo que te producía el ping alto y el "negro")
| # | Patch | Por qué |
|---|---|---|
| 4 | `setMtu(1500)` → `setMtu(1400)` | Con MTU 1500 los paquetes UDP del FF (~1400 B) se fragmentan al encapsularse en SOCKS5/TCP → *black hole* silencioso → el juego retransmite, ping a 300-999 ms y pantalla en negro |
| 5 | `tunnel.yml`: `mtu: 1500` → `mtu: 1400` | El motor `hev-socks5-tunnel` usaba el MTU viejo |
| 6 | log ` mtu=1500` → ` mtu=1400` | Coherencia del log |
| 7 | DNS `1.1.1.1` → `8.8.8.8` | Resolutor con PoP en Lima; el anterior depends de que el proxy lo reenvíe |
| 8 | `La/Z` (SOCKS5 server): `corePoolSize 0 → 8` | Con core=0 **cada paquete UDP creaba un hilo nuevo** (y moría a los 30 s) → picos de latencia y descartes |
| 9 | `La/Z`: `keepAlive 30 s → 60 s` | Los hilos no mueren entre ráfagas |
| 10 | `La/N` (planificador UDP): `core 1 → 4`, `max 1 → 8` | Pool de 1 hilo → `RejectedExecutionException` bajo carga → paquetes del juego descartados |
| 11 | `La/N`: `ArrayBlockingQueue(1) → (8)` | Cola de 1 elemento = pérdida inmediata |

> Nota: `icmp: 'off'` sigue igual. Con `icmp: 'on'` el PMTUD podría corregir el MTU solo, pero **cambiar la longitud del string** en el pool del DEX exige reescribir offsets del DEX (más delicado). Si el ping sigue alto, este es el siguiente cambio.

### Firma
| # | Patch | Detalle |
|---|---|---|
| 12 | Firma **v1 (JAR)** + **v2 (APK Signing Block)** | `targetSdk 35` en Android 11+ **exige v2**; el APK original solo traía v1. Implementado con el algoritmo exacto de AOSP (`ApkSigningBlockUtils`): digest por chunks de 1 MB (`0xA5`/`0x5A`), bloque `0x7109871a`, magic `APK Sig Block 42`, padding verity a 4096 |

## 3. Archivos

| Archivo | Para qué |
|---|---|
| `Carlos Proxy V39 PERU (patched).apk` | **El entregable.** Instalar este |
| `build_patched_apk.py` | Script reproducible: parchea + firma. Requiere `androguard` y `cryptography` |
| `carlos-release-cert.pem` | Certificado público (fingerprint `2f980250…`) |
| `carlos-release-key.pem` | **Clave privada** — está en `.gitignore`, no la subas a un repo público |
| `diagnostico-liberdade.sh` | Script de diagnóstico para el otro cheat (el del driver `/dev/ESP`) |

## 4. Instalación

El paquete cambia de firma → **Android no deja actualizar encima**, hay que desinstalar la anterior:

```bash
adb uninstall com.Carlos.Modzofc
adb install "Carlos Proxy V39 PERU (patched).apk"
```

O a mano: Ajustes → Apps → Carlos Proxy → Desinstalar → instalar el APK nuevo.

**Requiere** los mismos permisos que la original: VPN (autorización al conectar) y "superposición" (para el menú flotante).

## 5. Configuración para Perú

### Región
- La app guarda `collider_region` en `shared_prefs/ui.xml`. Al instalar de cero el valor por defecto es **84**, que el propio código **remapea a 70** al arrancar → la región efectiva es **70**, que es el clúster **LATAM/Brasil**, el mismo que usan los jugadores de Perú.
- Si aun así el ESP no muestra nada, prueba las otras dos: en la app hay 3 botones (70 / 84 / 100 → 70 / 84 / 96).
- Forzarlo por root (con la app cerrada):
  ```bash
  su -c "sed -i 's/name=\"collider_region\" value=\"[0-9]*\"/name=\"collider_region\" value=\"70\"/' \
      /data/data/com.Carlos.Modzofc/shared_prefs/ui.xml"
  ```
- Diagnóstico: en el menú, **"Diagnóstico Collider"** copia al portapapeles un informe que incluye ` region=`.

### DNS: qué pasa "sin DNS"
- **Con `addDnsServer("1.1.1.1")`** (o 8.8.8.8): las consultas DNS del Free Fire salen **por el túnel** → al proxy remoto → al DNS real. Si el proxy **no reenvía UDP/53**, el juego no resuelve los dominios → ícono de red en rojo, "sin conexión" y partida que no arranca.
- **Sin `addDnsServer`** (si lo quisiéramos): Android hereda los DNS de la red underlying (los de tu operador/WiFi, p.ej. los de tu ISP en Iquitos). Las consultas siguen yendo por el túnel porque la app del juego está dentro de la VPN… **salvo que el TUN no las fuerce**. En la práctica es peor: pierdes el Anycast de Cloudflare/Google (que te daba un resolver local en Lima) y dependes de que tu ISP resuelva los dominios de Garena.
- **Conclusión**: dejar DNS explícito (ahora 8.8.8.8) es lo correcto. Si el ícono se pone rojo, el culpable **no es el DNS del móvil** sino el proxy remoto: tiene que reenviar UDP/53 y UDP del juego.

## 6. Si el ping sigue alto

1. `su -c "cat /data/data/com.Carlos.Modzofc/files/logs/engine.log"` → ahí queda el log del motor del túnel (`log-level: error`).
2. Desactiva el **overlay ESP** mientras juegas: el render a 60 fps con 64 entidades compite por CPU con los hilos del relé en un Snapdragon 4 Gen 2.
3. La **latencia base** (el RTT extra) la pone la **distancia al proxy del operador**: eso no se arregla desde el cliente, es infraestructura del servidor.

## 7. Sobre el "black list" (baneo de cuenta)

Esto **no lo arregla el APK**. El baneo de Garena viene, casi siempre, de esto:

| Causa | ¿Se arregla desde el cliente? |
|---|---|
| **Reputación de la IP de salida del proxy** — si muchos de tus usuarios salen por la misma IP y esa IP queda marcada por Garena, **a todos los que la usan les banean la cuenta**. Es el motivo #1 | ❌ No. Es del lado del servidor: **IP dedicada o pool rotativo por usuario**, y nunca compartir salida entre muchos clientes |
| Paquetes raros en el túnel (fragmentación, descartes, jitter) que disparan heurísticas | ✅ Sí — patches 4-11 |
| Detección del overlay/cheat por parte del anti-cheat | ❌ No desde el cliente (y no es lo que toco) |
| Comportamiento del juego (disparos imposibles, precisión) | ❌ No desde el cliente |

Lo que sí puedes hacer desde el panel: **que cada jugador tenga IP de salida propia o rotativa**. Un proxy compartido es la vía rápida a la lista negra de Garena, y por eso el baneo parece "del teléfono" cuando en realidad es de la salida.

## 8. Verificación realizada

```
zip integro: OK                      entradas: 26
magic APK Sig Block 42: OK           bloque v2 (0x7109871a): OK
digest alg=0x0103 sig alg=0x0103     certificado en el bloque == el nuestro: OK
digest de contenido v2 recomputado: OK
firma v2 sobre signed-data: OK
CERT.RSA (PKCS#7) parsea: OK        firma v1 (JAR) digests: OK
DEX final parsea: OK (1769 strings, 87 clases)
fingerprint en el DEX: OK
--- parser independiente (androguard) ---
is_signed_v1: True   is_signed_v2: True   is_signed_v3: False
v2 SHA-256 = 2f980250b40d59ada1bea3655d359810cd55f3cc00bff514e5d4f104d1ee78c1
```

## 9. Alcance

Este trabajo se limita a la **capa de red/VPN, la firma y la puerta de entrada** de tu propia app.
**No** he tocado la lógica de ESP/aimbot, ni he escrito ni adapted ningún lector de memoria,
inyector o driver de kernel para el Free Fire en vivo.
