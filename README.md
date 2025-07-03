# 🔐 Repositorio de Estudio: Detección de Vulnerabilidades en Java

**Guía práctica para estudiantes, profesionales y entusiastas de la seguridad que desean aprender cómo identificar, entender y corregir vulnerabilidades comunes en código Java.**

Este documento no pretende ser una lección magistral, sino una hoja de ruta realista, con ejemplos concretos, tips y referencias a entornos vulnerables donde puedes practicar.

---

## 📚 Tabla de contenido

1. [Lo primero que debes saber](#-lo-primero-que-debes-saber)
2. [Conceptos esenciales](#-conceptos-esenciales-para-detectar-vulnerabilidades)
3. [Vulnerabilidades comunes (OWASP)](#-vulnerabilidades-más-comunes-en-java-con-ejemplos-y-corrección)
4. [Metodología de Estudio](#-metodología-de-estudio-para-entender-y-corregir-vulnerabilidades)
5. [Entornos vulnerables de práctica](#-entornos-de-práctica-y-laboratorios-recomendados)
6. [Ejemplo ejecutable: Path Traversal](#-ejemplo-ejecutable-path-traversal)
7. [Entorno de pruebas web Java con vulnerabilidades](#-entorno-de-pruebas-web-java-con-vulnerabilidades)

---

## 🧱 Lo primero que debes saber

- Las vulnerabilidades son defectos de seguridad en el código que pueden ser explotados por atacantes.
- En Java, muchas vulnerabilidades ocurren por procesar entradas del usuario sin validarlas.
- OWASP es una fuente confiable que clasifica las principales vulnerabilidades en aplicaciones web.

---

## 🧠 Conceptos esenciales para detectar vulnerabilidades

| Concepto           | Definición simple                                           | Ejemplo en código                          | ¿Por qué es importante?                                                  |
| ------------------ | ----------------------------------------------------------- | ------------------------------------------ | ------------------------------------------------------------------------ |
| **Source**         | Lugar donde el usuario introduce datos (entrada)            | `request.getParameter("input")`            | Si no se valida, el atacante puede enviar código malicioso               |
| **Sink**           | Lugar donde los datos son usados de forma peligrosa         | `Runtime.getRuntime().exec(input)`         | Aquí se "ejecuta" o procesa el input, y se materializa la vulnerabilidad |
| **Validación**     | Reglas que aplicamos para asegurar que la entrada es segura | Regex, listas blancas, canonical paths     | Previene que el input malicioso llegue al sink                           |
| **Lista blanca**   | Permitimos solo ciertos valores seguros                     | Solo permitir `.txt` en nombres de archivo | Rechazamos lo que no está permitido explícitamente                       |
| **Canonical Path** | Forma absoluta, sin `../`                                   | `getCanonicalPath()` en archivos           | Previene Path Traversal o acceso a rutas ilegales                        |

---

## 🛡️ Vulnerabilidades más comunes en Java 

**Objetivo:** Familiarizarse con las vulnerabilidades más comunes.

| Categoría            | Vulnerabilidad           | Descripción breve                                            |
|----------------------|--------------------------|--------------------------------------------------------------|
| Entrada/Salida       | SQL Injection            | Inyección de consultas SQL manipuladas                      |
| Serialización        | Deserialización insegura | Ejecución remota a través de objetos manipulados            |
| Lógica de aplicación | Validaciones inseguras   | Validaciones solo del lado cliente o incompletas            |
| Archivos             | Path Traversal           | Acceso a rutas críticas mediante manipulación de parámetros |
| Seguridad web        | CSRF / XSS               | Manipulación del navegador para realizar acciones no deseadas|
| Autenticación        | Gestión insegura de tokens | JWT mal implementados, sesiones sin control                |

### 🔍 Recursos útiles

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)


### 1. SQL Injection

**Vulnerable:**

```java
String usuario = request.getParameter("usuario"); // SOURCE
String consulta = "SELECT * FROM usuarios WHERE nombre = '" + usuario + "'";
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(consulta); // SINK
```

**Corrección:**

```java
String usuario = request.getParameter("usuario");
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM usuarios WHERE nombre = ?");
stmt.setString(1, usuario);
ResultSet rs = stmt.executeQuery();
```

### 2. XSS (Cross-Site Scripting)

**Vulnerable:**

```java
String nombre = request.getParameter("nombre"); // SOURCE
out.println("<h1>Hola, " + nombre + "!</h1>"); // SINK
```

**Corrección:**

```java
String nombre = request.getParameter("nombre");
nombre = StringEscapeUtils.escapeHtml4(nombre);
out.println("<h1>Hola, " + nombre + "!</h1>");
```

### 3. Path Traversal

**Vulnerable:**

```java
String ruta = request.getParameter("archivo"); // SOURCE
File archivo = new File("/data/" + ruta);
BufferedReader br = new BufferedReader(new FileReader(archivo)); // SINK
```

**Corrección:**

```java
File base = new File("/data");
File archivo = new File(base, ruta).getCanonicalFile();
if (!archivo.getPath().startsWith(base.getCanonicalPath())) {
  throw new SecurityException("Ruta no permitida");
}
```

### 4. CSRF

**Vulnerable:**

```html
<form action="/transfer" method="POST">
  <input name="monto" value="100">
</form>
```

**Corrección:**

```html
<input type="hidden" name="csrf_token" value="{token}" />
```

```java
String token = request.getParameter("csrf_token");
if (!token.equals(session.getAttribute("csrf_token"))) {
  throw new SecurityException("CSRF Token inválido");
}
```

### 5. HTTP Response Splitting

**Vulnerable:**

```java
String redir = request.getParameter("url"); // SOURCE
response.setHeader("Location", redir); // SINK
```

**Corrección:**

```java
String redir = URLEncoder.encode(request.getParameter("url"), "UTF-8");
response.setHeader("Location", redir);
```

### 6. Broken Access Control

**Vulnerable:**

```java
String id = request.getParameter("userId");
User user = db.getUserById(id);
mostrarPerfil(user);
```

**Corrección:**

```java
String id = request.getParameter("userId");
if (!id.equals(session.getAttribute("userId"))) {
  throw new SecurityException("Acceso no autorizado");
}
```

---

## 🎯 Metodología de Estudio para entender y corregir vulnerabilidades

1. Identificar el source
2. Localizar el sink
3. Analizar la validación
4. Corregir
5. Probar con inputs maliciosos
6. Documentar

---

## 🧪 Entornos de práctica y laboratorios recomendados

- [bWAPP](http://www.itsecgames.com/)
- [WebGoat](https://owasp.org/www-project-webgoat/)
- [DVWA](http://www.dvwa.co.uk/)
- [Hackazon](https://github.com/rapid7/hackazon)
- [VulnHub](https://www.vulnhub.com/)

---

# 💻 Ejemplo ejecutable: Path Traversal

```java
String archivo = request.getParameter("archivo"); // SOURCE
File file = new File("datos/" + archivo);
BufferedReader br = new BufferedReader(new FileReader(file)); // SINK
String linea = br.readLine();
response.getWriter().write("Contenido: " + linea);
br.close();
```

**Corrección:**

```java
File base = new File("datos");
File archivo = new File(base, archivo).getCanonicalFile();
if (!archivo.getPath().startsWith(base.getCanonicalPath()) || !archivo.getName().endsWith(".txt")) {
    response.sendError(403, "Acceso denegado");
    return;
}
BufferedReader br = new BufferedReader(new FileReader(archivo));
String linea = br.readLine();
response.getWriter().write("Contenido: " + linea);
br.close();
```

---

# 🧲 Entorno de pruebas web Java con vulnerabilidades

### 📁 Estructura

```
/entorno-web/
├── src/
│   └── Main.java
├── datos/
│   └── ejemplo.txt
├── libs/
└── pom.xml
```

## 🚧 En construcción

Esta sección del entorno de pruebas está en desarrollo. Próximamente se incluirán instrucciones detalladas para su configuración y ejecución.


