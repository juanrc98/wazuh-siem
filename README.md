#  Wazuh SIEM - Proyecto de Monitorización y Detección de Amenazas

### Implementación de Wazuh

Para este proyecto diseñé un entorno completo de monitorización y respuesta a incidentes utilizando Wazuh como plataforma central de seguridad. La arquitectura se compone de una máquina dedicada que ejecuta el servicio de Wazuh, accesible a través de un panel SIEM al que me conecto desde un equipo Windows funcionando como estación de analista.

Como endpoint monitorizado incorporé una máquina Metasploitable3, permitiendo observar en tiempo real la recolección de logs, análisis de integridad, detección de vulnerabilidades y correlación de eventos. Finalmente, utilicé una máquina Kali Linux para realizar distintos ataques controlados contra Metasploitable3, con el fin de validar la capacidad del SIEM para generar alertas, detectar comportamientos anómalos y registrar la actividad maliciosa.


###  Preparación del entorno

Descargaremos de la pagina web de Ubuntu su ISO oficial de Ubuntu Server, el cuál, usaremos para que corra nuestro servicio de Wazuh. Una vez instalado nuestro Ubuntu server ejecutaremos los siguientes comandos para preparar e instalar el servicio de Wazuh.

Debemos realizar una actualizacion del sistema operativo, y la instalacion de algunas herramientas necesarios que vamos a necesitar.

```
sudo apt update
sudo apt install vim curl apt-transport-https unzip wget libcap2-bin software-properties-common lsb-release gnupg2
```

Una vez hecho esto ejecutaremos el siguiente script de su pagina oficial

```
curl -sO https://packages.wazuh.com/4.5/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```

Una vez realizado esto, solo necesitaremos irnos a un navegador e introducir la IP de nuestra maquina que actuara de servidor para poder acceder a Wazuh. Es importante recordar que ambos equipos deben tener conexión entre ellos y deben poder verse. Esto lo podemos comprobar con ping entre ambas maquinas.

### 1 Interfaz de Acceso al SIEM

https://github.com/juanrc98/wazuh-siem/blob/main/1%20Wazuh%20Interfaz%20Login.png

Plataforma Wazuh SIEM - Sistema de gestión de eventos de seguridad open source diseñado para monitorización 24/7, detección de amenazas y respuesta a incidentes en entornos empresariales.
La conexión se realiza mediante la dirección interna del servidor (192.168.1.144), que es la dirección IP de la maquina virtual donde corre el servicio de Wazuh.


### 2 Dashboard Principal de Seguridad

<img src="images/2-Dashboard.png" alt="Dashboard Wazuh" width="600">

**Vista general del estado de seguridad:**
- **Agentes**: 1 agente desconectado (requiere investigación)
- **Alertas 24h**: 0 críticas, 0 high, 5 medium, 7 low
- **Vulnerabilidades**: 1 crítica, 7 high, 14 medium detectadas

**Módulos activos:**
- Configuration Assessment (CIS Benchmarks)
- Malware Detection
- Threat Hunting
- File Integrity Monitoring
- MITRE ATT&CK Mapping
- Vulnerability Detection

---

### 3 Menú de Navegación - Módulos del SIEM

https://github.com/juanrc98/wazuh-siem/blob/main/3%20Men%C3%BA%20de%20navegacion.png

**Estructura modular de Wazuh:**
- **Endpoint Security**: Gestión de seguridad de endpoints
- **Threat Intelligence**: Hunting, MITRE ATT&CK, Vulnerabilidades
- **Security Operations**: PCI DSS, GDPR, Docker, AWS
- **Cloud Security**: Integración con proveedores cloud
- **Agents Management**: Despliegue y gestión de agentes
- **Server/Indexer/Dashboard Management**: Administración del cluster

---

### 4 Despliegue de Agentes - Opciones Multiplataforma

https://github.com/juanrc98/wazuh-siem/blob/main/4%20Deploy%20agents.png

**Wizard de despliegue con soporte para:**
- **Linux**: RPM (amd64/aarch64), DEB (amd64/aarch64)
- **Windows**: MSI 32/64 bits
- **macOS**: Intel y Apple Silicon

**Configuración:**
- Dirección del servidor: `192.168.1.10`
- Nombre personalizado del agente: `Endpoint1`
- Comunicación cifrada entre agente y manager

---

### 5 Creación de Nuevo Agente para Windows

https://github.com/juanrc98/wazuh-siem/blob/main/5%20Crear%20un%20nuevo%20agent.png

**Proceso de registro de agente Windows:**
- Selección de arquitectura: MSI 32/64 bits
- Configuración de servidor manager
- Opciones de naming personalizado
- Documentación técnica integrada para despliegue

---

### 6 Creación de Nuevo Agente para Linux

https://github.com/juanrc98/wazuh-siem/blob/main/6%20Modificando%20configuracion%20agente.png

**Parámetros de configuración:**
La imagen muestra el asistente de Wazuh Manager para el despliegue de nuevos agentes en endpoints. Desde esta interfaz se selecciona el paquete adecuado para la instalación, en este caso Linux DEB amd64, con el objetivo de añadir un nuevo equipo al entorno monitorizado.

En la sección Server address se especifica la dirección IP del servidor Wazuh (192.168.1.10), que permitirá establecer la comunicación entre el agente y el manager. Además, se configuran los Optional settings, donde se asigna un nombre identificativo para el nuevo agente (por ejemplo, Endpoint1) antes de generar las instrucciones o el paquete de instalación.


---

### 7 Comandos de Instalación Automatizada

https://github.com/juanrc98/wazuh-siem/blob/main/7%20Comandos%20para%20configurar%20Endpoint.png

Esta fase del proceso se ejecuta en la máquina destinada a actuar como endpoint dentro del entorno de monitorización. En ella se instala y configura el agente de Wazuh, componente fundamental para la recolección y envío de datos de seguridad al servidor central.

La instalación incluye la configuración del agente con la dirección IP del servidor Wazuh, garantizando una comunicación segura y persistente para la transmisión de logs, eventos de integridad, alertas de seguridad y métricas del sistema. Además, se asigna un identificador único al endpoint para facilitar su seguimiento y gestión en el panel SIEM.

Este despliegue permite integrar el endpoint al ecosistema de seguridad, habilitando la detección temprana de incidentes y el análisis forense dentro del SOC.


**Script de instalación en Linux (Ubuntu/Debian):**
```bash
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.11.1-1_amd64.deb && \
sudo WAZUH_MANAGER='192.168.1.10' WAZUH_AGENT_NAME='Endpoint1' \
dpkg -i ./wazuh-agent_4.11.1-1_amd64.deb
```


---

### 8 Instalación del Agente en Endpoint

https://github.com/juanrc98/wazuh-siem/blob/main/8%20Implantando%20agente%20en%20Endpoint.png

**Proceso de instalación ejecutado:**
1. Descarga del paquete desde repositorio oficial (11.07 MB)
2. Resolución de dependencias
3. Desempaquetado e instalación del agente Wazuh 4.11.1
4. Configuración de triggers para actualización automática
5. Notificación de reprofiling en próximo reinicio

**Resultado**: Agente instalado correctamente, pendiente de inicio del servicio.

---

### 9 Verificación de Agente Añadido

https://github.com/juanrc98/wazuh-siem/blob/main/9.%20Vemos%20como%20se%20a%C3%B1ade%20el%20Endpointpng

**Estado post-instalación:**
- **Agentes por estado**: 1 activo, 0 desconectados, 0 pendientes, 1 nunca conectado
- **Top 5 OS**: Ubuntu (1 agente)
- **Top 5 Groups**: default (1 agente)
- **Agente registrado**: ID 002, nombre `metasploitable3-ub1404`

**Próximo paso**: Iniciar el servicio wazuh-agent para establecer comunicación con el manager.

---

### 10 Monitoreo de Endpoints Activos

https://github.com/juanrc98/wazuh-siem/blob/main/10%20Monitoreo%20de%20Endpoint.png

**Vista de gestión de agentes:**
- **Estado**: 1 agente activo 
- **Endpoint**: `metasploitable3-ub1404` (ID: 002)
- **IP**: 192.168.1.10
- **Sistema Operativo**: Ubuntu 14.04, Trusty Tahr
- **Cluster**: node01
- **Versión**: Wazuh v4.11.1
- **Fecha de registro**: 10 Oct 2025, 11:45:53

**Acciones disponibles:**
- Deploy new agent
- Refresh status
- Export formatted data
- Configuración WQL (Wazuh Query Language)

---

### 11 Simulación de Ataque al Endpoint

https://github.com/juanrc98/wazuh-siem/blob/main/11%20Simulamos%20ataque%20al%20Endpoint.png

**Escaneo de red detectado con Nmap:**

**Técnica utilizada**: Reconocimiento de red (MITRE ATT&CK: T1046 - Network Service Scanning)

**Servicios descubiertos:**
- **Puerto 21 (FTP)**: vsftpd abierto
- **Puerto 22 (SSH)**: OpenSSH con múltiples algoritmos de cifrado
- **Puerto 80 (HTTP)**: Apache con directorio `/phpmyadmin/` expuesto
  - Archivo crítico detectado: `payroll_app.php` (1.7K)
- **Puerto 445 (SMB)**: Microsoft-DS activo
- **Puerto 3306 (MySQL)**: Base de datos expuesta
- **Puerto 8080 (HTTP-Proxy)**: Servicio secundario

**Hallazgos de seguridad:**
- Certificado SSL caducado (válido hasta 2020-10-27)
- Sistema operativo identificado: Windows 6.1 (Samba 4.3.11-Ubuntu)
- Configuración SMB insegura: `message_signing: disabled` (peligroso pero por defecto)

**Vectores de ataque potenciales identificados:**
- Fuerza bruta en SSH/FTP
- Explotación de aplicaciones web (PHPMyAdmin, payroll_app.php)
- Ataques a base de datos MySQL
- SMB relay attacks

---

### 12 Inventario de Vulnerabilidades Detectadas

https://github.com/juanrc98/wazuh-siem/blob/main/12%20Vulnerabilidades%20Endpoint.png

**Análisis de vulnerabilidades del agente `metasploitable3-ub1404`:**

**Resumen por severidad: 22 CVEs detectados**

#### 🔴 Critical (1)
- **CVE-2013-7459** | pycrypto 2.6.1 | Buffer Overflow

#### 🟠 High (7)
- **CVE-2019-11324** | urllib3 1.7.1 | Improper Certificate Validation
- **CVE-2019-16777** | npm 2.15.11 | Arbitrary Command Execution
- **CVE-2018-7408** | npm 2.15.11 | Incorrect Permission Assignment
- **CVE-2019-16776** | npm 2.15.11 | Path Traversal
- **CVE-2019-16775** | npm 2.15.11 | Arbitrary File Write
- **CVE-2018-18074** | requests 2.2.1 | Insufficiently Protected Credentials
- **CVE-2018-6594** | pycrypto 2.6.1 | Weak Key Generation

#### 🟡 Medium (14)
- **CVE-2024-37891** | urllib3 1.7.1 | Proxy Support Issues
- **CVE-2023-45803** | urllib3 1.7.1 | Cookie Header Stripping
- **CVE-2023-43804** | urllib3 1.7.1 | CRLF Injection
- **CVE-2021-33503** | urllib3 1.7.1 | HTTP Header Impact
- **CVE-2019-11236** | urllib3 1.7.1 | Improper CRLF Neutralization
- **CVE-2018-25091** | urllib3 1.7.1 | Authorization Header Forwarding
- **CVE-2023-29483** | dnspython 1.11.1 | Potential DoS via Tudor Mechanism
- Y más...

**Paquetes más afectados:**
1. **urllib3** (1.7.1): 9 CVEs
2. **npm** (2.15.11): 5 CVEs
3. **requests** (2.2.1): 5 CVEs
4. **pycrypto** (2.6.1): 2 CVEs
5. **dnspython** (1.11.1): 1 CVE

**Recomendaciones:**
-  Actualizar urllib3 a versión >= 1.26.17
-  Actualizar npm a versión >= 6.14.6
-  Migrar de pycrypto (deprecado) a cryptography
-  Actualizar requests a versión >= 2.31.0

---

### 13 Detección de Técnica de Evasión (MITRE ATT&CK)

https://github.com/juanrc98/wazuh-siem/blob/main/13%20Detecci%C3%B3n%20de%20ataque.png

**Alerta de seguridad: Defense Evasion detectada**

**Técnica MITRE ATT&CK:**
- **ID**: T1562.001 - Disable or Modify Tools
- **Táctica**: Defense Evasion
- **Versión**: 1.4

**Detalles del incidente:**
- **Timestamp**: 2 Dic 2025, 20:52:46.920
- **Técnica**: Defense Evasion
- **Nivel de severidad**: 3 (Medium)
- **Rule ID**: 504
- **Descripción**: Wazuh agent disconnected

**Eventos recientes (últimas 24h): 194 hits**

**Eventos correlacionados:**
1. **20:52** - Agente Wazuh desconectado (Defense Evasion - Rule 504)
2. **20:26** - Sesión PAM cerrada (Rule 5502)
3. **20:24** - Anomalía basada en host detectada por rootcheck (Rule 510) - 2 ocurrencias

**Análisis:**
La desconexión del agente Wazuh es una técnica común utilizada por atacantes para evadir controles de seguridad antes de ejecutar acciones maliciosas. La correlación temporal con eventos de cierre de sesión y anomalías de rootcheck sugiere posible actividad sospechosa.

**Acciones de respuesta:**
1.  Investigar causa de desconexión del agente
2.  Revisar logs de autenticación (PAM)
3.  Ejecutar análisis forense en el endpoint
4. Verificar integridad del agente Wazuh

---

### 14 Dashboard MITRE ATT&CK y Eventos Totales
https://github.com/juanrc98/wazuh-siem/blob/main/14%20Total%20ataques%20recibidos.png
**Vista completa de telemetría de seguridad:**

#### Estado del Agente
- **ID**: 002
- **Status**: Desconectado 
- **IP Address**: 192.168.1.10
- **Version**: Wazuh v4.11.1
- **Group**: default
- **OS**: Ubuntu 14.04, Trusty Tahr
- **Cluster**: node01
- **Registration Date**: 10 Oct 2025, 11:45:53
- **Last Keep Alive**: 2 Dic 2025, 20:36:16

####  Events Count Evolution (Últimas 24h)
Gráfica temporal mostrando pico significativo de eventos:
- **Pico máximo**: ~200 eventos alrededor de las 18:00-19:00h
- **Tendencia**: Actividad normal durante el día, incremento exponencial al final de la tarde
- Este patrón sugiere posible ataque o escaneo automatizado

#### MITRE ATT&CK - Top Tactics
**Defense Evasion**: 1 técnica detectada
- Indicador de intento de evasión de controles de seguridad

####  Compliance (PCI DSS)
Distribución de cumplimiento normativo:
- **Requirement 2.2**: 182 eventos (verde)
- **Requirement 2.2.4**: 59 eventos (morado)
- **Requirement 2.2.3**: 27 eventos (rosa)
- **Requirement 2.2.2**: 19 eventos (morado oscuro)
- **Requirement 10.2.5**: 11 eventos (rosa oscuro)

**Análisis general:**
El sistema ha procesado y correlacionado múltiples eventos de seguridad, detectando 1 táctica de MITRE ATT&CK (Defense Evasion) y manteniendo monitorización continua de requisitos PCI DSS. El pico de eventos coincide con la desconexión del agente, sugiriendo actividad anómala que requiere investigación forense.


### Instalación de Wazuh Manager

```bash
# 1. Añadir repositorio oficial
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list

# 2. Actualizar repositorios
apt-get update

# 3. Instalar Wazuh Manager
apt-get install wazuh-manager

# 4. Verificar estado
systemctl status wazuh-manager
```

### Instalación de Agente (Linux)

```bash
# Descargar e instalar
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.11.1-1_amd64.deb

sudo WAZUH_MANAGER='<MANAGER_IP>' WAZUH_AGENT_NAME='<AGENT_NAME>' dpkg -i ./wazuh-agent_4.11.1-1_amd64.deb

# Iniciar servicio
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

  Próximos Pasos

-  Implementar reglas personalizadas de correlación
-  Integrar feeds de Threat Intelligence
-  Automatizar respuesta a incidentes con scripts
-  Configurar alertas por email/Slack
-  Expandir coverage a entornos Windows y cloud
-  Implementar honeypots para detección avanzada

---

##  Referencias

- [Documentación oficial de Wazuh](https://documentation.wazuh.com/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [PCI DSS Requirements](https://www.pcisecuritystandards.org/)

