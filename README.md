# TS Email Validator

**Una librería TypeScript para validación de emails, inspirada en el robusto sistema de validación de Laravel.**

[![NPM version](https://img.shields.io/npm/v/@bereasoft/email-validator.svg)](https://www.npmjs.com/package/@bereasoft/email-validator)
[![Build Status](https://img.shields.io/circleci/project/github/user/repo/master.svg)](https://circleci.com/gh/user/repo)
[![Coverage Status](https://img.shields.io/coveralls/github/user/repo.svg)](https://coveralls.io/github/user/repo)

`@bereasoft/email-validator` proporciona una solución completa y tipada para validar direcciones de email en entornos TypeScript, tanto en **Node.js** como en el **navegador**. Replica la funcionalidad y las reglas del popular validador de Laravel, incluyendo soporte para validación de sintaxis RFC, DNS (registros MX), y detección de spoofing.

## Características

- **Validación por Reglas**: Implementa las reglas de validación de email de Laravel:
  - `rfc`: Validación de sintaxis según RFC 5321 y 5322.
  - `strict`: Modo RFC estricto que rechaza advertencias y formatos obsoletos.
  - `dns`: Verifica la existencia de registros **MX** (o A/AAAA como fallback) en el DNS del dominio.
  - `spoof`: Detecta caracteres Unicode homógrafos y engañosos para prevenir ataques de spoofing.
  - `filter`: Una validación más simple y rápida, similar a la función `filter_var` de PHP.
- **API Flexible**: Ofrece múltiples formas de uso:
  - Una **API orientada a objetos** para un control detallado.
  - Una **API fluida** y encadenable, inspirada en `Rule::email()` de Laravel 12.
  - **Funciones de conveniencia** para validaciones rápidas.
- **Soporte Universal (Isomórfico)**: La validación DNS funciona tanto en **Node.js** (usando el módulo nativo `dns`) como en el **navegador** y **entornos Edge** (usando DNS-over-HTTPS).
- **Tipado Estricto con TypeScript**: Totalmente escrito en TypeScript para ofrecer autocompletado y seguridad de tipos.
- **Cero Dependencias**: No requiere ninguna dependencia externa de producción.

---

## Instalación

```bash
pnpm add @bereasoft/email-validator
# o
npm install @bereasoft/email-validator
# o
yarn add @bereasoft/email-validator
```

---

## Guía de Uso

### 1. API Fluida (Recomendada)

La forma más sencilla y expresiva de usar la librería es a través de la API fluida, que permite encadenar las reglas de validación deseadas.

```typescript
import { email } from '@bereasoft/email-validator';

// --- Validación Asíncrona (con DNS) ---

// Equivalente a 'email:rfc,dns,spoof' en Laravel
const result = await email()
  .rfcCompliant()          // Añade validación RFC 5322
  .validateMxRecord()      // Añade validación de registros MX en DNS
  .preventSpoofing()       // Añade detección de spoofing
  .validateAsync('user@gmail.com');

if (result.valid) {
  console.log('El email es válido y el dominio acepta correo.');
} else {
  console.error('Errores:', result.errors);
}

// --- Validación Síncrona (sin DNS) ---

// Equivalente a 'email:rfc,strict'
const syncResult = email()
  .rfcCompliant({ strict: true }) // Modo RFC estricto
  .validate('user@example.com');

console.log(syncResult.valid); // true
```

### 2. Clase `EmailValidator` (Orientada a Objetos)

Para un control más programático, puedes instanciar la clase `EmailValidator` y pasarle las reglas en el constructor o en cada llamada.

```typescript
import { EmailValidator } from '@bereasoft/email-validator';

// Crear una instancia con reglas por defecto
const validator = new EmailValidator({ rules: ['rfc', 'dns'] });

// Validar de forma asíncrona
const result = await validator.validateAsync('user@gmail.com');

if (!result.valid) {
  console.log(result.errors[0].message);
}

// Validar de forma síncrona (ignora la regla 'dns')
const syncResult = validator.validate('user@example.com', ['rfc', 'filter']);
console.log(syncResult.valid);
```

### 3. Funciones de Conveniencia

Para validaciones rápidas donde solo necesitas un resultado booleano.

```typescript
import { isValidEmail, isValidEmailAsync } from '@bereasoft/email-validator';

// Síncrono (solo sintaxis RFC por defecto)
if (isValidEmail('user@example.com')) {
  console.log('Formato válido.');
}

// Asíncrono (con DNS por defecto)
if (await isValidEmailAsync('user@gmail.com')) {
  console.log('Formato y DNS válidos.');
}

// Con reglas personalizadas
const isValidStrict = isValidEmail('"user"@example.com', ['strict']); // false
const isValidRfc = isValidEmail('"user"@example.com', ['rfc']);       // true
```

---

## Reglas de Validación en Detalle

| Regla | Descripción | Equivalente Laravel | Síncrona | Asíncrona |
| :--- | :--- | :--- | :---: | :---: |
| `rfc` | Valida la sintaxis del email según los estándares RFC 5321 y 5322. Es la base para la mayoría de las validaciones. | `email:rfc` | ✅ | ✅ |
| `strict` | Extiende `rfc` y rechaza formatos válidos pero considerados malas prácticas, como partes locales entre comillas o comentarios. | `email:strict` | ✅ | ✅ |
| `dns` | Verifica que el dominio del email tenga registros DNS válidos (MX, A o AAAA). **Requiere una llamada asíncrona.** | `email:dns` | ❌ | ✅ |
| `spoof` | Detecta si el email contiene caracteres Unicode que se parecen a otros (homógrafos), previniendo ataques de phishing. | `email:spoof` | ✅ | ✅ |
| `filter` | Una validación más simple y rápida basada en una expresión regular que emula el comportamiento de `filter_var` en PHP. | `email:filter` | ✅ | ✅ |

---

## El Objeto `EmailValidationResult`

Todas las funciones de validación retornan un objeto `EmailValidationResult` con la siguiente estructura:

```typescript
interface EmailValidationResult {
  /** Indica si el email es válido según todas las reglas aplicadas */
  valid: boolean;

  /** Email evaluado */
  email: string;

  /** Array de errores encontrados (vacío si es válido) */
  errors: EmailValidationError[];

  /** Array de advertencias (el email puede ser válido pero con observaciones) */
  warnings: EmailValidationWarning[];

  /** Reglas que se aplicaron durante la validación */
  appliedRules: EmailValidationRule[];

  /** Partes descompuestas del email (si la sintaxis es válida) */
  parts?: {
    local: string;
    domain: string;
    isQuoted: boolean;
    isIPLiteral: boolean;
  };
}
```

Un email se considera **inválido** si falla **cualquiera** de las reglas aplicadas. Las advertencias (como la ausencia de un registro MX cuando existe un registro A) no invalidan el email, pero se proporcionan para un análisis más profundo.

---

## API de Referencia

### `email()`

Crea un `EmailValidationBuilder` para la API fluida.

- `.rfcCompliant(options?: { strict?: boolean })`: Añade la regla `rfc` o `strict`.
- `.validateMxRecord(timeoutMs?: number)`: Añade la regla `dns`.
- `.preventSpoofing()`: Añade la regla `spoof`.
- `.filterValidation()`: Añade la regla `filter`.
- `.validate(email: string)`: Ejecuta la validación síncrona.
- `.validateAsync(email: string)`: Ejecuta la validación asíncrona.

### `EmailValidator`

- `constructor(options?: EmailValidatorOptions)`
- `validate(email: string, rules?: EmailValidationRule[]): EmailValidationResult`
- `validateAsync(email: string, rules?: EmailValidationRule[]): Promise<EmailValidationResult>`

### `isValidEmail()`

- `isValidEmail(email: string, rules?: EmailValidationRule[]): boolean`

### `isValidEmailAsync()`

- `isValidEmailAsync(email: string, rules?: EmailValidationRule[]): Promise<boolean>`

---

## Contribuciones

Las contribuciones son bienvenidas. Por favor, abre un *issue* para discutir los cambios propuestos o envía un *pull request*.

### Ejecutar Pruebas

```bash
# Instalar dependencias
pnpm install

# Ejecutar todas las pruebas
pnpm test

# Ejecutar pruebas en modo watch
pnpm run test:watch
```

## TDD, BDD y SOLID en este proyecto

Este repositorio ya está organizado para trabajar con prácticas de calidad de forma continua.

### TDD (Red -> Green -> Refactor)

1. Escribe primero un test en `tests/email-validator.test.ts` que falle (`Red`).
2. Implementa lo mínimo en `src/validators/*` o `src/EmailValidator.ts` para pasarlo (`Green`).
3. Refactoriza manteniendo todos los tests en verde (`Refactor`).

Comandos recomendados:

```bash
pnpm run test:watch
pnpm run lint
```

### BDD (Given / When / Then)

Los escenarios de negocio se expresan en pruebas con nombres orientados a comportamiento.

Ejemplo:

- `Given un dominio inexistente, When aplico rfc+dns, Then retorna NO_DNS_RECORD`

Esto permite discutir requisitos con lenguaje funcional antes de entrar en detalles de implementación.

### SOLID (aplicación práctica)

- `S`: cada validador (`RFCValidator`, `DNSValidator`, etc.) tiene una sola responsabilidad.
- `O`: `EmailValidator` usa registro de estrategias para extender reglas sin modificar lógica central.
- `L`: todas las estrategias respetan contratos tipados (`IEmailValidationStrategy`, `IAsyncEmailValidationStrategy`).
- `I`: interfaces separadas para validación síncrona y asíncrona.
- `D`: `EmailValidator` permite inyección de dependencias mediante `EmailValidatorDependencies` para desacoplar infraestructura y facilitar pruebas.

## Licencia

Este proyecto está bajo la **Licencia MIT**.
