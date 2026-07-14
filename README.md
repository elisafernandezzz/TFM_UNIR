# TFM_UNIR
Material complementario relacionado con el Trabajo Final de Máster.

## Requisitos

Antes de ejecutar el script, es necesario disponer de claves API para las siguientes herramientas OSINT:

- VirusTotal
- AbuseIPDB
- APIVoid

## Configuración

Configurar las variables de entorno en PowerShell:

```powershell
$env:VIRUSTOTAL_API_KEY="tu_api_key"
$env:ABUSEIPDB_API_KEY="tu_api_key"
$env:APIVOID_API_KEY="tu_api_key"
```

## Ejecución

1. Ejecutar el script.
2. Introducir el dominio potencialmente sospechoso.
3. Introducir el dominio legítimo para realizar la comparación.
