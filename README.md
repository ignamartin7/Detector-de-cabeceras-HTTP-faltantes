# HTTP Security Header Scanner 🛡️

Una herramienta ligera en Python diseñada para auditar y analizar la implementación de cabeceras de seguridad HTTP en aplicaciones web. El script identifica configuraciones faltantes y detalla los riesgos de seguridad asociados (ej. XSS, Clickjacking, MitM) comparando las respuestas del servidor contra una matriz de controles estándar de la industria.

## 🚀 Características

- Detección automática de cabeceras críticas (HSTS, CSP, X-Frame-Options, etc.).
- Explicación detallada del riesgo de seguridad por cada cabecera ausente.
- Evasión de bloqueos básicos mediante normalización de User-Agent.
- Soporte para auditorías en entornos locales o laboratorios CTF (ignora advertencias de certificados TLS/SSL autofirmados).

## 🛠️ Instalación y Requisitos

Requiere **Python 3.x**. Se recomienda el uso de un entorno virtual.

1. Clona el repositorio:
   ```bash
   git clone [https://github.com/tu-usuario/http-header-scanner.git](https://github.com/tu-usuario/http-header-scanner.git)
   cd http-header-scanner
   
2. Instala las dependencias:
	pip install -r requirements.txt
	

💻 Uso

Ejecuta el script pasando la URL del objetivo como argumento. Puedes omitir el protocolo; el script forzará https:// por defecto.
	python3 header_scanner.py ejemplo.com
	# o
	python3 header_scanner.py [https://ejemplo.com](https://ejemplo.com)
	

⚠️ Aviso Legal (Disclaimer)

Esta herramienta ha sido desarrollada con fines puramente educativos, para investigación defensiva y para su uso en entornos autorizados (auditorías, pentesting con consentimiento explícito o resoluciones de laboratorios/CTFs). El autor no se hace responsable del mal uso de este software contra infraestructuras de terceros sin autorización.


👤 Autor

Ignacio Martín

Information Security Engineer
