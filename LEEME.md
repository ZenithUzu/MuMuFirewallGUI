# MuMuFirewallGUI v2.1 — Windows 11

Herramienta PowerShell 5.1 / WinForms en español, sin dependencias externas. No distingue anuncios automáticamente. No aplica listas al iniciar ni cambia el firewall hasta que confirmes una operación. No modifica Android, DNS ni hosts.

## Iniciar y capturar

1. Extrae todo el ZIP a una carpeta con permiso de escritura. Ejecuta `Iniciar.cmd`. La omisión de ExecutionPolicy afecta solo a ese proceso; revisa los scripts antes de ejecutarlos. Los scripts no están firmados.
2. Para cambiar reglas, abre Windows PowerShell **como administrador**, entra en esa carpeta y ejecuta `./Iniciar.cmd`. La herramienta no solicita elevación por sí misma. La captura y lectura pueden tener acceso limitado sin administrador.
3. Cierra MuMu, pulsa **Iniciar captura** y arranca MuMu manualmente. La herramienta no inicia ni cierra el emulador. Detecta procesos cuyo nombre contiene MuMu; elige además la carpeta de instalación para incluir auxiliares con otros nombres. La selección incluye sus subcarpetas: evita elegir C:\ o una carpeta demasiado amplia.
4. Consulta las pestañas de procesos y conexiones: PID, ejecutable, ruta, IP, puerto, estado y horas. Si falta una ruta, esa fila no puede generar una regla. El historial conserva conexiones desaparecidas como «No observada», sin afirmar que hayan sido bloqueadas. Pausa antes de seleccionar; cada sondeo reconstruye la tabla y su selección.
5. Selecciona una o varias filas (Ctrl/clic). Deja marcada la opción **Limitar al puerto observado** y pulsa **Bloquear seleccionadas**. Revisa las rutas e IP de la confirmación. Sin esa opción se limita a la misma IP y ejecutable, pero a todos los puertos TCP.
6. Reinicia MuMu y comprueba Google Play: inicio de sesión, descarga/actualización, navegación y tus juegos. Si falla algo, desactiva la regla correspondiente y repite la prueba.

## Alcance y límites

Todas las reglas nuevas son bloqueos de SALIDA TCP, con una ruta absoluta existente `.exe`, una IP literal y un puerto o `Any` para puertos. Se rechazan subredes, rangos, IP no especificada, loopback y multicast. No existe bloqueo global ni bloqueo completo de Internet. El PID sirve para observar: el firewall se aplica a la ruta, también en futuros arranques.

**No se puede garantizar que Google Play siga funcionando con cualquier IP elegida.** MuMu puede transportar el tráfico de Android y de sus anuncios mediante el mismo ejecutable y la misma IP. Las CDN y servicios compartidos pueden servir contenido legítimo. No hay una lista fiable de IP que proteja Google Play en todos los casos. No bloquees en masa las coincidencias de la lista original. La ausencia de coincidencia tampoco indica que una conexión sea segura o publicitaria.

El sondeo síncrono ocurre aproximadamente cada 1,5 segundos más el tiempo de consulta; puede pausar brevemente la interfaz y perder procesos/conexiones muy breves. No captura paquetes, dominios, URLs, DNS ni UDP/QUIC. El historial se limita a 5000 conexiones; los PID pueden reutilizarse. No detecta de forma completa servicios auxiliares fuera de la carpeta elegida. «Established» no prueba publicidad ni éxito del bloqueo. Reabre la conexión o reinicia MuMu tras cambiar reglas. Una actualización que cambie la ruta requiere revisar las reglas.

## Reglas y reversión

**Actualizar reglas** lista reglas locales persistentes cuyo grupo, nombre o etiqueta de presentación coincide con `MuMuDebloat-Scoped-v1`, y las nuevas con prefijo interno `MuMuDebloat-Scoped-v2-`. Muestra programa, IP, puerto, protocolo, dirección, acción y perfiles. Conserva las anteriores; no las convierte ni las elimina automáticamente. Las políticas de empresa/GPO o reglas sin etiqueta no se administran aquí; las políticas corporativas pueden impedir que una regla local sea efectiva.

Selecciona reglas en esa pestaña para **activar**, **desactivar** o **eliminar**, siempre con confirmación y respaldo automático previo. Desactivar permite revertir sin perder la definición. No se crean reglas Allow para compensar un bloqueo. No se cambian perfiles, reglas ajenas ni la configuración general del firewall.

La deduplicación usa un nombre determinista por ruta/IP/puerto y comprueba reglas etiquetadas TCP equivalentes (incluida una regla con todos los puertos). Repetir un bloqueo no reactiva una regla desactivada: utiliza Activar. No intenta fusionar reglas antiguas complejas ni deduplicar políticas externas.

## Respaldo, exportación y restauración

Antes de cada lote de cambios se escribe un JSON en `Respaldos/`. Si falla ese respaldo se cancela el cambio. **Exportar configuración** permite guardarlo en otro lugar. **Exportar captura CSV** guarda los datos observados; pueden contener rutas y direcciones privadas, revísalos antes de compartir.

**Restaurar JSON** valida todo el archivo antes de comenzar, muestra una vista previa y realiza una restauración aditiva. Solo acepta definiciones de bloqueo de salida TCP con exe existente, IP única y puerto válido. Recrea reglas v2 y su estado; no elimina otras reglas. Una regla equivalente antigua puede evitar la creación: se conserva su estado y debe revisarse manualmente. Rutas que ya no existen o reglas antiguas con varias IP, rangos, protocolos amplios o entrada hacen que se rechace el archivo completo. El JSON exporta esas reglas para auditoría, pero no promete restaurarlas automáticamente. Si necesitas revertir una regla antigua amplia, desactívala en lugar de eliminarla.

Las operaciones son secuenciales, no transaccionales: si un comando falla tras varios cambios, puede quedar un lote parcial. Actualiza la tabla y usa el respaldo para revisar o restaurar. Los respaldos no son una copia completa del firewall de Windows.

## Lista original y procedencia

Fuente revisada el 31-10-2026: https://github.com/BinaryBrother/MuMuPlayerDebloat/blob/main/BlockAdsMumu.bat

`referencia-ips.txt` contiene únicamente las direcciones extraídas del BAT original: 54 entradas, incluida `42.186.0.0/17`. El BAT original crea bloqueos globales de entrada y salida; **no se incluye ni se ejecuta**. La GUI solo señala coincidencias observadas, sin preseleccionar ni importar esa lista. Se conserva literalmente `6.160.199.231`; no se presupone que sea un error ni que ninguna entrada corresponda actualmente a anuncios.

Esta herramienta reconoce la etiqueta v1 para gestionar reglas previas. Consulta README.md para conocer el resultado observado y los créditos.

Referencia técnica: https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule

## Validación

`Validar.ps1` usa funciones simuladas: verifica deduplicación, alcance, rechazo de destinos globales/rangos, etiqueta y exportación/importación. No escribe en el firewall. `MuMuFirewallGUI.ps1 -SmokeTest` construye y libera los controles sin mostrar ventana ni consultar el firewall. Se validó sintaxis con el analizador de PowerShell y construcción de interfaz en Windows PowerShell 5.1. No se ha probado un bloqueo real ni se garantiza eliminar anuncios. No se modificó el firewall del equipo durante la preparación del ZIP.

## Corrección v2.1
Se sustituyeron los separadores verticales del nombre visible de las reglas por guiones y se limitó la longitud. Windows no admite ese carácter en el nombre. La validación ahora comprueba las propiedades en un objeto COM HNetCfg.FWRule aislado: nunca se añade al firewall. Etiquetas e identificadores siguen siendo compatibles.
