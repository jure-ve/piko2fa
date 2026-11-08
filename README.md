# piko2fa

Gestor 2FA (TOTP) para terminal, escrito en Go. Guarda tus claves en un único archivo cifrado local, genera los códigos e importa desde Google Authenticator.

## Proyecto personal

Hice piko2fa para cubrir una necesidad personal, así que solo incluye lo que yo necesitaba. Si te interesa usarlo, es posible que tengas que añadir funciones que para mí no eran necesarias, pero para ti sí lo sean. En [Limitaciones](#limitaciones) encontrarás algunas de las que no incluye.

## Instalación

Requiere Go 1.27 o posterior. Desde la carpeta del proyecto:

```bash
go install ./cmd/piko2fa
```

El binario queda en `$(go env GOPATH)/bin`. Compila sin CGO en Windows, Linux y macOS.

En Windows, usa PowerShell o Windows Terminal. En Git Bash (mintty) la app no puede leer la contraseña sin mostrarla, así que se detiene con un error salvo que uses `winpty`.

## Uso

| Comando | Qué hace |
|---|---|
| `piko2fa init` | Crea el vault. |
| `piko2fa add` | Añade una cuenta: URI `otpauth://` por entrada oculta o stdin, o datos a mano. |
| `piko2fa list [filtro]` | Muestra las cuentas, sin secretos ni códigos. |
| `piko2fa code <consulta>` | Muestra el código actual y los segundos restantes. |
| `piko2fa code <consulta> --copy` | Además, copia el código y lo limpia del portapapeles al expirar. |
| `piko2fa code --all` | Muestra los códigos de todas las cuentas. |
| `piko2fa tui` | Abre la interfaz interactiva: buscar, ver códigos en vivo y copiar. |
| `piko2fa rm <consulta>` | Elimina una cuenta, previa confirmación. |
| `piko2fa import-ga` | Importa URIs `otpauth-migration://` por entrada oculta o stdin. |
| `piko2fa import-ga --file uris.txt` | Importa desde un archivo con una URI por línea. |
| `piko2fa import-ga --qr qr\*.png` | Importa desde imágenes de QR, en PNG o JPEG. |
| `piko2fa passwd` | Cambia la contraseña maestra. |
| `piko2fa export --encrypted <archivo>` | Crea un respaldo cifrado. |
| `piko2fa export --plaintext <archivo>` | Exporta todas las claves **en claro**, como URIs. |
| `piko2fa restore <archivo>` | Restaura un respaldo cifrado o el `.bak`. |

Si una consulta coincide con varias cuentas, se muestran con su ID y puedes precisarla con `Emisor:cuenta` o con ese ID.

Las contraseñas y las URIs nunca se aceptan como argumento, porque quedarían en el historial de la terminal y en la lista de procesos.

La contraseña maestra debe tener al menos 12 caracteres y usar solo ASCII: otros caracteres pueden codificarse distinto según el teclado y el vault no abriría en otro equipo. Lo mejor es que sea aleatoria y única, generada por un gestor de contraseñas.

## Interfaz interactiva

`piko2fa tui` pide la contraseña una vez y muestra todas las cuentas con sus códigos en vivo. Es de solo lectura: para añadir o eliminar cuentas, usa los demás comandos, que siguen funcionando con la interfaz abierta. Los cambios se ven al volver a desbloquear.

| Tecla | Qué hace |
|---|---|
| Escribir | Filtra las cuentas; con varias palabras, deben coincidir todas. |
| Flechas, RePág, AvPág, Inicio, Fin | Mueven la selección. |
| Enter | Copia el código. Con 5 segundos o menos, espera al siguiente para darte tiempo a pegarlo. |
| Esc | Cancela una copia en espera, limpia la búsqueda o, si no hay ninguna, sale. |
| Ctrl+U | Limpia la búsqueda. |
| Ctrl+L | Bloquea ahora. |
| Ctrl+C | Sale. |

El código copiado se borra del portapapeles al expirar, al bloquear y al salir, salvo que hayas copiado otra cosa después. Tras 5 minutos sin pulsar teclas se bloquea sola, y lo mismo ocurre al despertar el equipo si ese tiempo ya pasó. Al bloquearse, borra los secretos de la memoria y vuelve a pedir la contraseña.

## Dónde se guardan los datos

| Sistema | Ubicación |
|---|---|
| Windows | `%LocalAppData%\piko2fa\` |
| Linux | `~/.config/piko2fa/` o `$XDG_CONFIG_HOME/piko2fa/` |
| macOS | `~/Library/Application Support/piko2fa/` |

| Archivo | Contenido |
|---|---|
| `vault.bin` | El vault cifrado. |
| `vault.bin.bak` | La versión anterior, cifrada. |
| `vault.bin.lock` | El bloqueo entre procesos. Está vacío y es normal que permanezca. |
| `vault.bin.pre-restore-<fecha>` | El vault reemplazado por un `restore`. No se borra solo. |

## Respaldos

`vault.bin.bak` está en el mismo disco, así que no te protege si pierdes el equipo. Guarda respaldos en otro lugar:

```bash
piko2fa export --encrypted respaldo-2026-11-06.piko
```

Para restaurar:

```bash
piko2fa restore respaldo-2026-11-06.piko
```

- **Haz un respaldo tras añadir cuentas:** uno antiguo no incluye las nuevas.
- **Prueba la restauración:** un respaldo sin probar no es un respaldo. Puedes probarlo sin tocar tu vault apuntando `LOCALAPPDATA` (o `XDG_CONFIG_HOME`) a una carpeta temporal.
- **Contraseña de cada respaldo:** se abre con la que tenía el vault al exportarlo. `passwd` no cambia los respaldos ya exportados, ni los archivos `pre-restore`.
- **Si `vault.bin` se daña:** restaura desde el `.bak`, con `piko2fa restore` y la ruta de `vault.bin.bak`.

## Migrar desde Google Authenticator

1. **Prepara el equipo.** Comprueba que el disco está cifrado (BitLocker en Windows) y desactiva la sincronización de fotos.
2. **Prueba primero con una cuenta falsa.** Añádela a Google Authenticator, exporta solo esa y comprueba que `piko2fa code` da los mismos códigos.
3. **Exporta tus cuentas.** Serán muchos QR. Si el teléfono bloquea las capturas, fotografía la pantalla con otro dispositivo o con la webcam del equipo y pasa las imágenes por cable, sin servicios en la nube. Comprueba antes dónde guarda las fotos la cámara: en Windows, `Imágenes` puede estar dentro de OneDrive.
4. **Importa.** Revisa en la vista previa los QR que falten, los conflictos y las cuentas rechazadas (HOTP y MD5 no están admitidas). Puedes repetir la importación por partes sin crear duplicados.

   ```bash
   piko2fa import-ga --qr qr\*.png
   ```

5. **Borra las imágenes y vacía la papelera.** Contienen todas tus claves en claro. En un SSD el borrado no es garantizado: por eso importa el cifrado de disco.
6. **Compara durante unos días** los códigos de `piko2fa code --all` con los de Google Authenticator.
7. **Haz un respaldo cifrado, guárdalo fuera del equipo y prueba a restaurarlo.**
8. **Solo entonces** elimina las cuentas de Google Authenticator.

Guarda también aparte los códigos de recuperación de cada servicio.

## Modelo de amenazas

**Protege frente a:**

- Alguien que obtiene una copia de `vault.bin`, de un `.bak` o de un respaldo, siempre que la contraseña sea fuerte. Cifrado con XChaCha20-Poly1305 y clave derivada con Argon2id (3 pasadas, 64 MiB, 4 hilos).
- Que se altere el archivo: un cambio de cualquier bit impide abrirlo, sin datos parciales.
- Que un corte o un fallo al guardar deje el vault inservible.
- Que se filtren secretos por el historial de la terminal, argumentos o mensajes de error.

**No protege frente a:**

- **Malware en tu sesión.** Un keylogger captura la contraseña, y otro proceso de tu usuario puede leer la memoria. Ninguna app local puede evitarlo.
- **Una contraseña débil o reutilizada.** El vault se puede atacar sin conexión.
- **Olvidar la contraseña.** No hay recuperación posible.
- **Restos en memoria o en disco.** Los secretos se ponen a cero al terminar, pero es un esfuerzo parcial: Go puede dejar copias en memoria, y esta puede acabar en el archivo de paginación.
- **Secretos en memoria con la interfaz abierta.** Con `piko2fa tui`, las claves permanecen descifradas en memoria hasta que se bloquea o sales, no solo unos segundos. Bloquéala con Ctrl+L si te alejas del equipo: mientras tanto, los códigos están a la vista en pantalla.
- **El historial del portapapeles.** `--copy` y la interfaz limpian el portapapeles, pero Win+V puede conservar el código hasta que se borre.
- **Acceso de otros usuarios en Windows.** Allí la app no ajusta permisos: la protección es el cifrado y el perfil de usuario. En Linux y macOS, los archivos se crean con permisos `600` y el directorio con `700`.

Tener contraseñas y 2FA en el mismo equipo reduce la separación entre ambos factores. Y no guardes en piko2fa el 2FA del gestor de contraseñas donde está tu contraseña maestra: si pierdes uno, perderías el acceso a los dos.

## Limitaciones

- Solo TOTP con SHA1, SHA256 o SHA512, de 6 u 8 dígitos. No admite HOTP ni Steam Guard.
- Google Authenticator no exporta el periodo, así que las cuentas importadas usan 30 segundos.
- Imágenes de QR solo en PNG y JPEG: no admite HEIC.
- `--copy` necesita `xclip` o `xsel` en Linux.
- La ayuda de los comandos tiene partes en inglés, generadas por cobra.

## Desarrollo

### Compilar y construir el ejecutable

Para generar el binario en la raíz del proyecto:

```bash
# Compilación estándar para el sistema actual
go build -o piko2fa ./cmd/piko2fa
```

*(En Windows genera `piko2fa.exe` automáticamente o puedes especificar `-o piko2fa.exe`)*.

Para compilar un binario optimizado para distribución (eliminando información de depuración y tablas de símbolos para reducir su tamaño):

```bash
go build -ldflags="-s -w" -o piko2fa ./cmd/piko2fa
```

También puedes ejecutar la aplicación directamente durante el desarrollo sin compilar el binario a disco:

```bash
go run ./cmd/piko2fa [comando]
```

#### Compilación cruzada (Cross-compilation)

Al no depender de CGO (`CGO_ENABLED=0`), puedes generar ejecutables para cualquier plataforma directamente desde tu equipo:

```bash
# Linux (64-bit)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o piko2fa-linux-amd64 ./cmd/piko2fa

# Windows (64-bit)
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o piko2fa-windows-amd64.exe ./cmd/piko2fa

# macOS (Apple Silicon / ARM64)
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o piko2fa-darwin-arm64 ./cmd/piko2fa
```

### Pruebas y calidad de código

- **Pruebas unitarias e integración:**
  Ejecuta todos los tests de todos los paquetes del proyecto (`./...` indica recursividad):
  ```bash
  go test ./...
  ```
  *(Puedes añadir `-v` para salida detallada o `-race` para verificar carreras de datos)*.

- **Análisis estático estándar (`go vet`):**
  Herramienta oficial de Go que analiza el código fuente en busca de errores sintácticos o construcciones sospechosas (como argumentos incorrectos en llamadas de formato o cierres mal manejados):
  ```bash
  go vet ./...
  ```

- **Linter avanzado (`staticcheck`):**
  Detecta bugs sutiles, código inalcanzable o muerto, simplificaciones de código y usos de APIs obsoletas:
  ```bash
  go run honnef.co/go/tools/cmd/staticcheck@latest ./...
  ```

- **Auditoría de vulnerabilidades (`govulncheck`):**
  Comprueba el código y las dependencias contra la base de datos oficial de vulnerabilidades conocidas de Go (Go Vulnerability Database):
  ```bash
  go run golang.org/x/vuln/cmd/govulncheck@latest ./...
  ```

## Licencia

Publicado bajo la [licencia MIT](LICENSE). Se ofrece tal cual, sin garantías de ningún tipo, y su autor no se hace responsable de fallos ni de daños derivados de su uso, como la pérdida de acceso a tus cuentas. El texto de la licencia es el que tiene validez.
