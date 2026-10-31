# MuMuFirewallGUI

Interfaz en español para Windows 11 que observa conexiones TCP de MuMuPlayer y permite crear bloqueos de firewall **limitados a un ejecutable, una IP y opcionalmente un puerto**. PowerShell 5.1 + WinForms; sin dependencias externas.

## Descarga y uso

Descarga **MuMuFirewallGUI-v2.1.zip** desde [Releases](https://github.com/ZenithUzu/MuMuFirewallGUI/releases/latest), extrae todo y consulta [LEEME.md](LEEME.md).

1. Ejecuta `Iniciar.cmd`. Para cambiar reglas, ejecútalo desde Windows PowerShell abierto como administrador.
2. Con MuMu cerrado, pulsa **Iniciar captura** y arranca el emulador manualmente.
3. Pausa la captura, revisa el ejecutable y selecciona una conexión. Deja marcada **Limitar al puerto observado**.
4. Pulsa **Bloquear seleccionadas** y revisa la confirmación. Prueba una IP por vez.
5. Reinicia MuMu y comprueba Google Play y tus juegos. Si algo falla, desactiva la regla desde la pestaña de reglas.

Puedes cerrar la herramienta después: Windows conserva las reglas. La herramienta no modifica el firewall al abrirse ni aplica listas automáticamente.

## Funciones

- Procesos detectados por nombre MuMu o carpeta de instalación elegida.
- Historial TCP con PID, ejecutable, ruta, IP, puerto, estado y horas.
- Reglas de salida TCP para una ruta `.exe` y una IP exacta; nunca reglas globales nuevas.
- Activación, desactivación y eliminación con confirmación; deduplicación y respaldo automático previo.
- Listado de reglas etiquetadas `MuMuDebloat-Scoped-v1` y reglas nuevas con identificador v2.
- Exportación de configuración JSON, restauración aditiva validada y captura CSV.

## Resultado observado: pantalla publicitaria de arranque

En una prueba realizada por **ZenithUzu** el **31 de octubre de 2026**, en Windows 11 y una instancia MuMu Android 15, se observó una conexión de:

```text
Ejecutable: MuMuNxDevice.exe
Ruta de la instalación probada:
C:\Program Files\Netease\MuMuPlayer\nx_device\15.0\shell\MuMuNxDevice.exe
Destino: 34.36.47.246
Protocolo / puerto: TCP 443
Dirección: salida
```

Tras crear una regla con ese alcance, el usuario informó que MuMu arrancó sin la imagen promocional y que Google Play y los juegos continuaban funcionando. La dirección ya figuraba en la lista de BinaryBrother; esta prueba relaciona ese destino con el comportamiento observado en esa instalación. **No establece que la IP sirva exclusivamente anuncios ni que funcione igual en otras versiones o redes.** No se realizó un ensayo controlado de desactivar/reactivar ni se inspeccionó el contenido HTTPS.

No copies esta IP a un bloqueo global. Si la pruebas, usa la ruta real de tu instalación, limita el puerto y comprueba los servicios que necesitas. La herramienta no la bloquea de manera predeterminada.

## Límites

No distingue anuncios automáticamente. Una IP/CDN puede compartir publicidad, Google Play y juegos dentro del mismo ejecutable. No existe garantía de conservar todos los servicios con cualquier bloqueo elegido. El sondeo puede perder conexiones breves y no captura UDP/QUIC, dominios ni URLs. Las IP y las rutas pueden cambiar.

Los respaldos contienen las reglas etiquetadas, no el firewall completo. La importación admite únicamente reglas de salida TCP con ejecutable existente e IP única; algunas reglas v1 amplias solo se exportan para auditoría. Los lotes no son transaccionales. Consulta los detalles en [LEEME.md](LEEME.md).

## Créditos

- **[BinaryBrother / MuMuPlayerDebloat](https://github.com/BinaryBrother/MuMuPlayerDebloat):** guía original de debloat y lista de IP de `BlockAdsMumu.bat`, punto de partida de la investigación. La lista se conserva como referencia informativa con atribución; no se ejecuta el BAT original, que crea bloqueos globales.
- **[ZenithUzu](https://github.com/ZenithUzu):** iniciativa, observación de conexiones y prueba funcional del bloqueo durante el arranque.
- **OpenAI Codex / ChatGPT:** asistencia para desarrollar la interfaz, documentación y pruebas. Esto no implica respaldo oficial de OpenAI ni de los autores citados.
- **Microsoft:** APIs de Windows Firewall, NetSecurity y WinForms utilizadas por la herramienta.

Este es un proyecto independiente; no está afiliado a NetEase/MuMuPlayer ni es una publicación oficial de BinaryBrother.

## Validación y versión

v2.1 corrige el carácter `|` en el nombre visible de las reglas, que Windows rechaza. Se validaron sintaxis con Windows PowerShell 5.1, construcción de controles WinForms y operaciones con firewall simulado. También se comprueban propiedades en un objeto COM de regla aislado sin registrarlo en el firewall. La prueba de uso real descrita arriba fue realizada por el usuario; no equivale a una certificación o prueba exhaustiva.

```powershell
./Validar.ps1
./MuMuFirewallGUI.ps1 -SmokeTest
```

Los scripts no están firmados. Se distribuyen como código fuente revisable. Consulta [VALIDACION.txt](VALIDACION.txt) y [CREDITOS.md](CREDITOS.md).

## Informar resultados

Abre un issue con la versión de MuMu, Windows, ejecutable afectado, IP/puerto probado y resultado al activar/desactivar. Revisa y elimina datos personales antes de adjuntar CSV, capturas o respaldos.
