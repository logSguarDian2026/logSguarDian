# node-api-goat — resultados

**Repo:** [layro01/node-api-goat](https://github.com/layro01/node-api-goat) · **Rama de la integración:**
`feat/logsguardian-integration` en el clon local (`/Users/xtsebas/Universidad/node-api-goat`), sin
commitear. **Fecha:** 2026-09-30.

## La app

API REST Express 4.16 deliberadamente vulnerable, catalogada por CWE (no OWASP API Top 10). Sin base
de datos, sin motor de vistas. **Todas las rutas son `GET` con parámetros en query string** — no usa
`express.json()`/`express.urlencoded()` en absoluto originalmente, y no tiene un solo endpoint `POST`.
Sin autenticación. Levantada con `npm install` + `node app/server.js`, puerto 3001.

## Cobertura de las 4 categorías — 3 de 4, SQLi no aplica

| Categoría | Endpoint real | Estado |
|---|---|---|
| XSS | `GET /cwe79/echo?text=` (CWE-79) | Confirmado — reflejado sin escapar |
| Path Traversal/LFI | `GET /cwe73/read?foo=` (CWE-73, `fse.readJsonSync`) | Confirmado |
| Command Injection | `GET /cwe78/childprocess?foo=` (CWE-78, `child_process.exec`) | Confirmado |
| SQL Injection | — | **No aplica — la app no tiene base de datos** (verificado por código y dependencias: cero drivers SQL). Documentado, no se inventó un endpoint. |

Otras vulnerabilidades presentes en la app pero fuera del alcance de `logsguardian` por diseño (no por
autenticación — la app no tiene sistema de auth en absoluto): CWE-95 (Eval Injection vía `eval()` de
JS, distinto de OS command injection), CWE-502 (deserialización insegura, `node-serialize`), CWE-113
(CRLF/header splitting), CWE-601 (open redirect), CWE-201 (exposición de información).

## Confirmación "antes" (sin logsguardian) — evidencia real

- **XSS:** `curl .../cwe79/echo?text=<script>alert(1)</script>` devolvió el script sin escapar en el HTML.
- **Path traversal:** cruzando directorio se leyó `../logSguarDian/package.json` — un archivo **fuera
  del propio repo de node-api-goat** — confirma traversal real, no solo lectura local.
- **Command injection:** `id > /tmp/...` y `whoami >> /tmp/...` — el archivo apareció en disco con el
  output real del comando del sistema (`uid=501(xtsebas)...`), confirmando ejecución real, no eco de
  texto.

## Resultados del corpus (50 payloads/clase, 250 total)

Muestreo determinístico y reproducible: líneas pares de cada bloque de 100 del fixture compartido.

| Clase | n | Bloqueados sin logsguardian | Bloqueados con logsguardian |
|---|---|---|---|
| sqli* | 50 | 0 | 50 |
| xss | 50 | 0 | 49 |
| path_traversal | 50 | 0 | 50 |
| cmdi | 50 | 0 | 48 |
| benign | 50 | 0 | **50** |

*sqli se envió por un endpoint neutro (`/cwe201/exposure?text=`, sin sink SQL real) — mide solo
capacidad de detección de la forma del payload, no explotabilidad (que no existe en esta app).

De los ataques reales bloqueados, la clase predicha frecuentemente es incorrecta: de los XSS, solo
18/49 se etiquetó como `xss` (30 como `sqli`); de path_traversal, 35/50 correctos. `sqli` actúa como
clase por defecto del modelo en tráfico de esta forma.

## Falsos positivos — el hallazgo central: 100% del tráfico benigno bloqueado

Esta app es puro `GET` con un solo parámetro en query string — exactamente la forma de petición donde
más pesa `ua_length` en la decisión del modelo. El chequeo de 5 peticiones benignas típicas (User-Agent
real de Chrome) dio:

```
[403] GET /hexToRgb?hex=3366CC          → predicted sqli, confidence 0.80
[403] GET /cwe79/echo?text=Hello World  → predicted sqli, confidence 0.63
[403] GET /cwe73/read?foo=package.json  → predicted sqli, confidence 0.52
[403] GET /cwe78/childprocess?foo=pwd   → predicted sqli, confidence 0.52
[404] GET /                             → pass_anomaly (no bloqueado, pero marcado anómalo)
```

**4/5 bloqueadas.** El corpus benigno completo (50 muestras reales, reenviadas contra `/hexToRgb`)
confirma el patrón a mayor escala: **50/50 bloqueadas** — 47 como `sqli`, 3 como `cmdi`. **Cero
identificadas correctamente como benignas.** Con `mode: 'block'` y configuración por defecto,
`logsguardian` bloquearía el 100% del tráfico legítimo de esta app.

## Problemas de integración

Ninguno de fricción — el orden de montaje (body parsers → logsguardian → rutas) funcionó sin
sorpresas, y `dbPath` se alineó explícitamente desde el inicio (ruta absoluta,
`path.join(__dirname, 'logsguardian-events.db')`, referenciada igual en middleware y CLI). Único
ajuste real: como la app no usa bodies, todo el corpus se mapeó a query params de un solo campo
(`text=`/`foo=`/`hex=`) en vez de JSON/form — se decodificó una vez cada payload pre-encodeado antes de
re-encodearlo, para no doble-encodear.

## Archivos de la integración (en el clon, rama `feat/logsguardian-integration`, sin commitear)

- Modificados: `app/server.js`, `package.json`/`package-lock.json`
- Nuevos: `logsguardian.config.js`, `attack-sim/run-attacks.js`, `attack-sim/results-before.json`,
  `attack-sim/results-after.json`, `logsguardian-events.db` (generado en runtime)

## Cómo reproducir

```bash
cd /Users/xtsebas/Universidad/node-api-goat
node app/server.js &                 # puerto 3001
node attack-sim/run-attacks.js       # corre el corpus con logsguardian activo
# variante sin protección:
LOGSGUARDIAN_DISABLED=true node app/server.js &
node attack-sim/run-attacks.js
```
