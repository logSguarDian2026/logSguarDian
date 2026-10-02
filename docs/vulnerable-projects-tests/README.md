# Pruebas de logsguardian contra proyectos vulnerables de terceros

**Objetivo:** verificar cómo se comporta `logsguardian` (paquete público de npm, `logsguardian@0.1.0`)
integrado en aplicaciones Node.js deliberadamente vulnerables **que no son `logSguarDian-vulnerable-project`**
— es decir, apps que el proyecto nunca vio durante calibración de threshold ni durante entrenamiento.
`logSguarDian-vulnerable-project` es la única app usada para calibrar `RF_THRESHOLD=0.35` y para todas
las evaluaciones de Config 1/2/3 del resto de este repo; estas pruebas responden a una pregunta distinta
y necesaria: **¿generaliza esa calibración a una app cualquiera, o está sobreajustada a la app de referencia?**

**Fecha:** 2026-09-30. **Metodología:** integración real de `npm install logsguardian` en cada app (no
simulada), confirmación de explotabilidad real antes de proteger, corpus de ataque compartido
(`e2e/fixtures/test_payloads.jsonl`, 500 payloads, 100/clase, ya usado y validado en el resto de este
proyecto), y un chequeo de falsos positivos con tráfico benigno típico de cada app.

## Resultado consolidado — el hallazgo cruza las 3 apps

| App | Stack | Recall (ataques reales) | Falsos positivos en tráfico benigno |
|---|---|---|---|
| [DVNA](dvna-results.md) | Express + EJS + Sequelize/MySQL | 92.5–97.5% por clase (n=40/clase) | **5/5 (100%)** — muestra pequeña y dirigida a los flujos centrales (home/login/búsqueda/listado), no una tasa poblacional; ver salvedad en el detalle |
| [node-api-goat](node-api-goat-results.md) | Express, API pura, sin DB | 96–100% por clase (n=50/clase) | **50/50 (100%)** — corpus benigno reenviado contra un solo endpoint (`/hexToRgb`); ver salvedad en el detalle |
| [dvws-node](dvws-node-results.md) | Express + Mongo/MySQL + SOAP/GraphQL | 92.5–100% por clase (n=40/clase) | **37/40 (92.5%)** sobre el corpus de 40; un chequeo cualitativo adicional de n=5 ilustra el tipo de request afectada |

**En las 3 apps, con arquitecturas y stacks completamente distintos entre sí, `logsguardian` en modo
`block` con la configuración por defecto (`RF_THRESHOLD=0.35`) detecta bien los ataques reales pero
bloquea entre el 92.5% y el 100% del tráfico legítimo.** Esto no es un caso límite aislado (el hallazgo
original, un `GET /login` corto ocasionalmente bloqueado en `logSguarDian-vulnerable-project`) — es un
problema sistémico de generalización: el modelo fue calibrado contra el perfil de tráfico de una sola
app, y no transfiere a ninguna de las 3 apps de este estudio, cada una con una forma de tráfico distinta
(bodies form-urlencoded vs. JSON vs. query-string puro, con y sin autenticación, con y sin sesiones).

**Importante sobre cómo leer el recall junto con los falsos positivos:** en las 3 apps, el recall alto
en ataques (92.5-100%) y la tasa de falsos positivos casi igual de alta (92.5-100%) no son dos hallazgos
independientes — son la misma causa vista desde dos ángulos. Con un umbral que bloquea casi todo lo que
recibe, el recall alto dice poco sobre si el sistema realmente *discrimina* ataque de tráfico legítimo;
es principalmente un efecto de umbral agresivo, no de capacidad de distinción. Los dos números deben
citarse juntos, nunca el recall solo como evidencia positiva aislada.

**Hallazgo confirmado por una segunda investigación independiente:** se sospechaba que el problema era
específicamente la *longitud corta* del header `User-Agent` (`ua_length` es la feature de mayor
importancia del RF). La prueba en dvws-node refutó que fuera *solo* eso: usar un User-Agent real de
navegador **empeoró** la tasa de falsos positivos (75% → 92.5%) en vez de mejorarla. Una investigación
paralela, mergeada desde `develop` el 2026-10-02 (`docs/limitations.md`, addendum sobre la dependencia
de RF en el User-Agent, con OWASP Juice Shop como cuarta app), confirma y cuantifica la causa exacta:
no es la longitud corta, sino que el tráfico benigno de entrenamiento apenas contiene UAs largos/de
navegador (0.4% de las filas benignas de `unified.jsonl` vs. 33.3-97.7% en las clases de ataque) — el
modelo aprendió, en la práctica, "UA largo = ataque". En Juice Shop, sustituir solo el UA (curl →
navegador) subió el bloqueo de tráfico benigno de 39.4% a 97.1% (624 requests). Esto coincide en
dirección exacta con el hallazgo de dvws-node de este documento — dos apps distintas, dos metodologías
distintas, mismo patrón. Ver `docs/limitations.md` y `docs/findings-evidence/juice-shop-ua-bias/` para
el detalle completo. Lo que además queda establecido aquí: el problema no se limita al header UA —
contraseñas fuertes realistas (`MyP@ssw0rd`, `Tr0ub4dor`), listados normales autenticados, y peticiones
GET simples sin query también se clasifican como `sqli`/`path_traversal` de forma inestable ante
pequeños cambios de headers.

**Clasificación de clase, aparte del bloqueo:** en las 3 apps, cuando el modelo sí bloquea un ataque
real, la clase predicha (`attacks list`/`endpoints profile`) frecuentemente es incorrecta — `sqli`
actúa como una especie de clase por defecto del modelo ante tráfico con la forma "GET/POST corto, pocos
parámetros". El bloqueo (seguridad) funciona; el triage por clase (para un analista revisando el log)
no es confiable fuera del propio `logSguarDian-vulnerable-project`.

## Por qué esto importa para la tesis

- Es evidencia directa, con tres réplicas independientes, de una amenaza a la validez que ya se
  sospechaba pero no se había cuantificado fuera de la app de referencia: el modelo generaliza mal a
  formas de tráfico que no vio en calibración.
- No invalida las métricas de detección reportadas en el resto del proyecto (recall sigue siendo alto
  en las 3 apps) — pero sí invalida cualquier afirmación de que `logsguardian` es "seguro de instalar
  en modo `block` en cualquier app Node.js sin ajuste". Eso debe declararse explícitamente en el
  informe final, no suavizarse.
- Da una dirección concreta de trabajo futuro: recalibrar `RF_THRESHOLD` (o el propio proceso de
  calibración) contra una muestra de tráfico multi-app, no solo `logSguarDian-vulnerable-project`: y
  documentar `mode: 'monitor'` como el modo recomendado por defecto para una primera instalación,
  en vez de `mode: 'block'`.

## Detalle por proyecto

- [`dvna-results.md`](dvna-results.md) — Damn Vulnerable NodeJS Application
- [`node-api-goat-results.md`](node-api-goat-results.md) — node-api-goat
- [`dvws-node-results.md`](dvws-node-results.md) — Damn Vulnerable Web Service (Node)

## Reproducibilidad

Cada integración vive en una rama `feat/logsguardian-integration` dentro del clon de cada proyecto
(no en este repo — son apps de terceros, y esas ramas no están subidas a ningún remoto todavía). Ver el
detalle de cada `.md` para las rutas exactas, los scripts de ataque usados, y los pasos para levantar
cada app y repetir la medición.

**Evidencia cruda, copiada a este repo** (para que esta carpeta sea autocontenida y verificable sin
depender de los 3 clones locales): [`evidence/`](evidence/) contiene, por app, los scripts de ataque
(`run-*.js`, `fp-check.js`/`benign-fp-check.js`) y los JSON de resultados antes/después
(`results-before.json`, `results-after.json`, y para dvws-node además `results-after-nodeua.json`, la
corrida con User-Agent real de navegador). Son una copia estática tomada el 2026-09-30; los clones
originales en `/Users/xtsebas/Universidad/{dvna,node-api-goat,dvws-node}` siguen siendo la fuente para
re-ejecutar la medición desde cero.
