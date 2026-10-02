# DVNA (Damn Vulnerable NodeJS Application) — resultados

**Repo:** [appsecco/dvna](https://github.com/appsecco/dvna) · **Rama de la integración:**
`feat/logsguardian-integration` en el clon local (`/Users/xtsebas/Universidad/dvna`), sin commitear.
**Fecha:** 2026-09-30.

## La app

Express + EJS + Sequelize/MySQL, catalogada contra OWASP Top 10 2017. Es antigua — pineada a
`node:carbon` (Node 8), MySQL 5.7, `bcrypt@1.0.3`, `libxmljs@0.19.x` — ninguna de esas versiones
compila bajo Node ≥20, que `logsguardian` exige (`onnxruntime-node`, `better-sqlite3`). Se levantó con
MySQL 5.7 en Docker (`--platform linux/amd64`, puerto host 3307) y la propia DVNA en Node 22 nativo.

## Cobertura de las 4 categorías — 3 de 4, una no existe

| Categoría | Endpoint | Campo | Estado |
|---|---|---|---|
| SQL Injection | `POST /app/usersearch` | `login` | Confirmado — extrajo el hash bcrypt real de un usuario |
| XSS (reflejado) | `POST /app/products` | `name` | Confirmado — reflejado sin escapar |
| Command Injection | `POST /app/ping` | `address` | Confirmado — ejecutó `id` real en el host |
| Path Traversal / LFI | — | — | **No existe en DVNA.** Auditado el código (`grep` de `readFile\|sendFile\|createReadStream\|res.download` en `routes/`, `core/`, `views/`, `server.js`): el único uso de rutas de archivo es `express.static('public')`, que Express sanea internamente. No se inventó un endpoint sustituto. |

## Confirmación "antes" (sin logsguardian) — evidencia real, no asumida

- **SQLi:** `login=' UNION SELECT password,1 from Users where login='alice' -- //'` devolvió el hash
  bcrypt real de alice (`$2b$10$2aJV0bPY...`).
- **XSS:** `name=<script>alert('xss-poc')</script>` se reflejó sin escapar en el HTML de respuesta.
- **Command Injection:** `address=127.0.0.1 ; id` ejecutó `id` en el host, devolvió `uid=501(xtsebas)`.

Corpus completo antes de proteger: **0/40 bloqueados en las 3 categorías** — 100% de los ataques
llegó al código vulnerable.

## Resultados del corpus (40 payloads/clase, muestra del fixture de 500 líneas)

40/clase (de 100 disponibles) para mantener el tiempo manejable — `cmdi` ejecuta `ping` real por
request.

| Clase | Antes | Después | Clasificación correcta (de los bloqueados) |
|---|---|---|---|
| sqli | 0/40 (0%) | 38/40 (95.0%) | 34/38 → `sqli`; 4 → `cmdi` |
| xss | 0/40 (0%) | 39/40 (97.5%) | 19/39 → `xss`; 12 → `cmdi`; 8 → `sqli` |
| cmdi | 0/40 (0%) | 37/40 (92.5%) | 9/37 → `cmdi`; 27 → `sqli`; 1 → `path_traversal` |

Recall alto en las 3 categorías. **La clase predicha es poco confiable fuera de `sqli`** — más de la
mitad de los XSS bloqueados se etiquetó como `cmdi`/`sqli`; la mayoría de los cmdi bloqueados también
cayó en `sqli`. El bloqueo (seguridad) funciona; el triage por clase (`attacks list`/`endpoints profile`)
no sería confiable para un analista en este entorno.

## Falsos positivos — el hallazgo central: 5/5 peticiones legítimas bloqueadas

**Nota de muestra:** n=5. No es una tasa de falsos positivos a nivel de población de tráfico
benigno — es un chequeo deliberadamente dirigido a los flujos centrales de la app (home, login,
búsqueda, listado). Su valor no viene del tamaño de la muestra sino de **qué** cubre: si esas 5
rutas fallan, el flujo principal de uso está roto, independientemente de qué tan grande sea el
denominador. Lo que sí es robusto es la reproducibilidad (dos corridas, mismo resultado
determinístico) — no la generalización del "5/5 = 100%" a cualquier otro endpoint no probado.
Tampoco deben leerse el recall alto en ataques (92.5-97.5%) y este 100% de FP como dos hallazgos
independientes positivos: con el modelo bloqueando casi todo en ambos lados, el recall alto por sí
solo dice poco sobre si el sistema realmente discrimina ataque de tráfico legítimo.

Chequeo de 5 peticiones típicas y completamente benignas, User-Agent real de Chrome:

| Petición | Resultado | Clase predicha |
|---|---|---|
| `GET /` (home) | **403** | sqli |
| `GET /login` | **403** | path_traversal |
| `POST /login` (credenciales válidas) | **403** | sqli |
| `GET /app/usersearch` (página, sin query) | **403** | path_traversal |
| `GET /app/products` (listado) | **403** | path_traversal |

**5/5 bloqueadas**, determinístico y reproducible (repetido dos veces, mismo resultado). Con la
configuración por defecto (`mode: 'block'`, `RF_THRESHOLD=0.35`), **ningún usuario real podría ni
siquiera iniciar sesión ni navegar la app.** No es el caso límite aislado que se sospechaba — es un
bloqueo total del flujo principal de la aplicación.

Para poder medir los ataques reales de todos modos (necesitaba loguearse una vez para llegar a rutas
autenticadas), se implementó un kill-switch de archivo (`.logsguardian-disabled`, chequeado por
request) exclusivamente como mecanismo de prueba — documentado en el código como tal, no como patrón
de producción.

## Bugs reales encontrados en DVNA, no relacionados con logsguardian

- `models/index.js` nunca pasaba el puerto de MySQL configurado a Sequelize — siempre conectaba a 3306
  sin importar `MYSQL_PORT`. Corregido con una línea (`port: config.port`).
- El endpoint XSS (`productSearch`) no tiene `.catch()` en su promesa de Sequelize; un payload con
  texto no-ASCII contra una tabla en `latin1_swedish_ci` dispara `Illegal mix of collations`, la
  promesa queda rechazada sin manejar, y el request **cuelga indefinidamente**. Corregido migrando las
  tablas afectadas a `utf8mb4`.
- Dependencias que no compilan en Node ≥20: `libxmljs@0.19.x` (subido a `1.0.11`, rompe API de
  `parseXmlString`→`parseXml` — el endpoint de bulk-upload XML/XXE quedó deshabilitado en vez de
  reescrito, está fuera de las 4 categorías evaluadas), `bcrypt@1.0.3`→`^5.1.1` (misma API, sin cambio
  de comportamiento), `mysql2@1.4.2`→`^2.3.3` (handshake `ER_NOT_SUPPORTED_AUTH_MODE` con MySQL 5.7
  bajo emulación amd64).

**Evidencia cruda copiada a este repo:** [`evidence/dvna/`](evidence/dvna/) (`run-corpus.js`,
`fp-check.js`, `results-before.json`, `results-after.json`).

## Archivos de la integración (en el clon, rama `feat/logsguardian-integration`, sin commitear)

- Modificados: `package.json`, `server.js`, `models/index.js`, `core/appHandler.js`
- Nuevos: `logsguardian.config.js`, `attack-sim/run-corpus.js`, `attack-sim/fp-check.js`,
  `attack-sim/results-before.json`, `attack-sim/results-after.json`, `logsguardian-events.db`
  (generado en runtime)

## Cómo reproducir

```bash
cd /Users/xtsebas/Universidad/dvna
docker start dvna-mysql   # o recrearlo si no existe, puerto host 3307
MYSQL_USER=dvna MYSQL_DATABASE=dvna MYSQL_PASSWORD=passw0rd MYSQL_HOST=127.0.0.1 MYSQL_PORT=3307 \
  node server.js
# en otra terminal:
node attack-sim/run-corpus.js      # ataques reales, con logsguardian activo
node attack-sim/fp-check.js        # chequeo de falsos positivos
# variante sin protección, para comparar:
LOGSGUARDIAN_DISABLED=true MYSQL_USER=dvna MYSQL_DATABASE=dvna MYSQL_PASSWORD=passw0rd \
  MYSQL_HOST=127.0.0.1 MYSQL_PORT=3307 node server.js
```
