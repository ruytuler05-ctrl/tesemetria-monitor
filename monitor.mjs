import { resolve4, resolve6 } from "node:dns/promises";
import { connect as connectTcp } from "node:net";
import { resolve as resolvePath } from "node:path";
import { connect as connectTls } from "node:tls";
import { pathToFileURL } from "node:url";

export const HTTP_TIMEOUT_MS = 15_000;
export const CONNECTION_TIMEOUT_MS = 6_000;
export const MINIMUM_CERTIFICATE_DAYS = 30;

export const DEFAULT_BASE_URL = "https://www.tesemetria.com.br";
export const REDIRECT_ORIGINS = [
  "https://tesemetria.com.br",
  "https://www.tesemetria.com",
  "https://tesemetria.com",
  "https://www.tesemetria.tech",
  "https://tesemetria.tech",
];

const HTTP_CHECKS = [
  { path: "/api/health", kind: "health" },
  { path: "/", kind: "page" },
  { path: "/empresas", kind: "page" },
  { path: "/forum", kind: "page" },
  { path: "/artigos", kind: "page" },
  { path: "/area-do-assinante", kind: "page" },
  { path: "/api/public-companies", kind: "api" },
];

function abortAfter(milliseconds) {
  return AbortSignal.timeout(milliseconds);
}

function errorField(error, field) {
  return error && typeof error === "object" && field in error
    ? error[field]
    : undefined;
}

export function describeError(error) {
  const messages = [];
  const metadata = {};
  const visited = new Set();
  let current = error;

  while (current && typeof current === "object" && !visited.has(current)) {
    visited.add(current);
    if (typeof current.message === "string" && current.message.length > 0) {
      messages.push(current.message);
    }
    for (const field of ["code", "syscall", "hostname", "address", "port"]) {
      const value = errorField(current, field);
      if (value !== undefined && metadata[field] === undefined) {
        metadata[field] = value;
      }
    }
    current = errorField(current, "cause");
  }

  if (messages.length === 0) messages.push(String(error));
  return { message: messages.join(" <- "), ...metadata };
}

function stepError(step, error) {
  const wrapped = new Error(describeError(error).message, { cause: error });
  wrapped.monitorStep = step;
  return wrapped;
}

export function validateStrictTransportSecurity(value) {
  const match = /(?:^|;)\s*max-age=(\d+)/i.exec(value ?? "");
  if (!match || Number(match[1]) < 31_536_000) {
    throw new Error(
      `HSTS ausente ou abaixo de um ano (recebido: ${value ?? "ausente"})`,
    );
  }
  return value;
}

export function validateHealthPayload(payload) {
  const summary = {
    status: payload?.status ?? null,
    database: payload?.database ?? null,
    asyncProcessing: payload?.asyncProcessing ?? null,
    recovery: payload?.recovery?.status ?? null,
    release: payload?.release ?? null,
  };
  if (
    summary.status !== "ok" ||
    summary.database !== "postgres" ||
    summary.asyncProcessing !== "ok" ||
    summary.recovery !== "healthy" ||
    typeof summary.release !== "string" ||
    summary.release.length < 7
  ) {
    throw new Error(`resposta de saude invalida: ${JSON.stringify(summary)}`);
  }
  return summary;
}

export async function resolveHost(hostname) {
  const [ipv4Result, ipv6Result] = await Promise.allSettled([
    resolve4(hostname, { ttl: true }),
    resolve6(hostname, { ttl: true }),
  ]);
  const ipv4 = ipv4Result.status === "fulfilled" ? ipv4Result.value : [];
  const ipv6 = ipv6Result.status === "fulfilled" ? ipv6Result.value : [];

  if (ipv4.length === 0 && ipv6.length === 0) {
    const causes = [ipv4Result, ipv6Result]
      .filter((result) => result.status === "rejected")
      .map((result) => describeError(result.reason).message)
      .join("; ");
    throw new Error(`${hostname}: DNS sem endereco (${causes || "sem resposta"})`);
  }

  return {
    ipv4: ipv4.map(({ address, ttl }) => ({ address, ttl })),
    ipv6: ipv6.map(({ address, ttl }) => ({ address, ttl })),
  };
}

export function checkTcp(hostname, timeoutMs = CONNECTION_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    const startedAt = performance.now();
    let settled = false;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      callback(value);
    };
    const socket = connectTcp({ host: hostname, port: 443 });
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => {
      const result = {
        elapsedMs: Math.round(performance.now() - startedAt),
        remoteAddress: socket.remoteAddress,
        remoteFamily: socket.remoteFamily,
        remotePort: socket.remotePort,
      };
      socket.end();
      finish(resolve, result);
    });
    socket.once("timeout", () => {
      const error = new Error(
        `${hostname}: TCP/443 nao abriu em ${timeoutMs} ms`,
      );
      error.code = "ETIMEDOUT";
      error.hostname = hostname;
      error.port = 443;
      socket.destroy();
      finish(reject, error);
    });
    socket.once("error", (error) => finish(reject, error));
  });
}

export function checkTls(hostname, timeoutMs = CONNECTION_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    const startedAt = performance.now();
    let settled = false;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      callback(value);
    };
    const socket = connectTls({
      host: hostname,
      port: 443,
      servername: hostname,
      rejectUnauthorized: true,
    });
    socket.setTimeout(timeoutMs);
    socket.once("secureConnect", () => {
      const certificate = socket.getPeerCertificate();
      const expiresAt = Date.parse(certificate.valid_to);
      const daysRemaining = Math.floor((expiresAt - Date.now()) / 86_400_000);
      const result = {
        elapsedMs: Math.round(performance.now() - startedAt),
        authorized: socket.authorized,
        protocol: socket.getProtocol(),
        remoteAddress: socket.remoteAddress,
        daysRemaining,
        validTo: certificate.valid_to,
      };
      socket.end();
      if (!Number.isFinite(daysRemaining)) {
        finish(
          reject,
          new Error(`${hostname}: certificado sem validade reconhecivel`),
        );
      } else if (daysRemaining < MINIMUM_CERTIFICATE_DAYS) {
        finish(
          reject,
          new Error(`${hostname}: certificado vence em ${daysRemaining} dias`),
        );
      } else {
        finish(resolve, result);
      }
    });
    socket.once("timeout", () => {
      const error = new Error(
        `${hostname}: handshake TLS nao concluiu em ${timeoutMs} ms`,
      );
      error.code = "ETIMEDOUT";
      error.hostname = hostname;
      error.port = 443;
      socket.destroy();
      finish(reject, error);
    });
    socket.once("error", (error) => finish(reject, error));
  });
}

async function checkHttp({ path, kind }, baseUrl) {
  const requestedUrl = new URL(path, baseUrl);
  const startedAt = performance.now();
  const response = await fetch(requestedUrl, {
    redirect: "follow",
    signal: abortAfter(HTTP_TIMEOUT_MS),
    headers: {
      "user-agent": "Tesemetria-Public-Monitor/2.0",
      accept:
        kind === "page"
          ? "text/html,application/xhtml+xml"
          : "application/json",
    },
  });
  const elapsedMs = Math.round(performance.now() - startedAt);
  if (!response.ok) {
    throw new Error(`${path}: HTTP ${response.status} apos ${elapsedMs} ms`);
  }

  const hsts = validateStrictTransportSecurity(
    response.headers.get("strict-transport-security"),
  );
  let health;
  if (kind === "health") {
    health = validateHealthPayload(await response.json());
  } else {
    await response.body?.cancel();
  }
  return { path, elapsedMs, effectiveUrl: response.url, hsts, health };
}

async function checkCanonicalRedirect(origin, baseUrl) {
  const suffix = "/verificacao-dominio?origem=monitor-publico";
  const response = await fetch(`${origin}${suffix}`, {
    redirect: "manual",
    signal: abortAfter(HTTP_TIMEOUT_MS),
    headers: { "user-agent": "Tesemetria-Public-Monitor/2.0" },
  });
  const location = response.headers.get("location");
  const expectedUrl = new URL(suffix, baseUrl).toString();
  if (![301, 308].includes(response.status) || location !== expectedUrl) {
    throw new Error(
      `${origin}: redirecionamento canonico invalido (HTTP ${response.status}, destino ${location ?? "ausente"})`,
    );
  }
  await response.body?.cancel();
  return { origin, status: response.status, location };
}

async function collectStep(report, step, callback) {
  const entry = { step, status: "running", startedAt: new Date().toISOString() };
  report.steps.push(entry);
  try {
    entry.result = await callback();
    entry.status = "ok";
    entry.finishedAt = new Date().toISOString();
    return entry.result;
  } catch (error) {
    entry.status = "failed";
    entry.finishedAt = new Date().toISOString();
    entry.error = describeError(error);
    throw stepError(step, error);
  }
}

export async function runMonitor(baseUrlInput = DEFAULT_BASE_URL) {
  const baseUrl = new URL(baseUrlInput);
  const report = {
    monitorVersion: 2,
    status: "running",
    checkedAt: new Date().toISOString(),
    baseUrl: baseUrl.origin,
    connectionTimeoutMs: CONNECTION_TIMEOUT_MS,
    httpTimeoutMs: HTTP_TIMEOUT_MS,
    vantagePoint:
      process.env.GITHUB_ACTIONS === "true"
        ? "github-hosted-ubuntu"
        : "local-diagnostic",
    steps: [],
  };

  if (baseUrl.protocol !== "https:") {
    report.status = "failed";
    report.failedStep = "configuration";
    report.error = { message: "O monitor externo exige uma URL HTTPS." };
    return report;
  }

  try {
    const hosts = [
      baseUrl.hostname,
      ...REDIRECT_ORIGINS.map((origin) => new URL(origin).hostname),
    ].filter((hostname, index, values) => values.indexOf(hostname) === index);

    for (const hostname of hosts) {
      await collectStep(report, `dns:${hostname}`, () => resolveHost(hostname));
      await collectStep(report, `tcp:${hostname}:443`, () => checkTcp(hostname));
      await collectStep(report, `tls:${hostname}:443`, () => checkTls(hostname));
    }

    for (const check of HTTP_CHECKS) {
      await collectStep(report, `http:${check.path}`, () =>
        checkHttp(check, baseUrl),
      );
    }

    for (const origin of REDIRECT_ORIGINS) {
      await collectStep(report, `redirect:${origin}`, () =>
        checkCanonicalRedirect(origin, baseUrl),
      );
    }

    report.status = "ok";
    report.finishedAt = new Date().toISOString();
    return report;
  } catch (error) {
    report.status = "failed";
    report.finishedAt = new Date().toISOString();
    report.failedStep = errorField(error, "monitorStep") ?? "unknown";
    report.error = describeError(errorField(error, "cause") ?? error);
    return report;
  }
}

async function main() {
  const report = await runMonitor(process.argv[2] ?? DEFAULT_BASE_URL);
  const serialized = JSON.stringify(report);
  if (report.status === "ok") {
    console.log(serialized);
  } else {
    console.error(serialized);
    process.exitCode = 1;
  }
}

const isDirectExecution =
  process.argv[1] &&
  pathToFileURL(resolvePath(process.argv[1])).href === import.meta.url;

if (isDirectExecution) await main();
