# Cambios

## 2.1 — 2026-10-31

- Corrige nombres de reglas que contenían el separador `|` no permitido por Windows.
- Limita la longitud de la etiqueta del ejecutable usada en el nombre visible.
- Agrega validación con un objeto nativo de regla sin registrarlo en el firewall.
- Documenta la prueba de `MuMuNxDevice.exe` hacia `34.36.47.246:443` y sus límites.

## 2.0 — 2026-10-31

- Captura e historial TCP, selección manual de conexiones y reglas limitadas por ejecutable/IP/puerto.
- Gestión reversible de reglas etiquetadas, deduplicación, respaldos y exportación/importación JSON.
- Referencia informativa a la lista de BinaryBrother sin ejecutar su BAT ni crear bloqueos globales.
