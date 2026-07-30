import { connect } from "node:tls";

const baseUrl = new URL(process.argv[2] ?? "https://www.tesemetria.com.br");
const timeoutMs = 15_000;
const minimumCertificateDays = 14;
const legacyOrigins = [
  "https://tesemetria.com.br",
  "https://www.tesemetria.tech",
  "https://tesemetria.tech",
];
const checks = [
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

async function checkHttp({ path, kind }) {
  const requestedUrl = new URL(path, baseUrl);
  const startedAt = performance.now();
  const response = await fetch(requestedUrl, {
    redirect: "follow",
    signal: abortAfter(timeoutMs),
    headers: {
      "user-agent": "Tesemetria-Public-Monitor/1.0",
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
  if (kind === "health") {
    const payload = await response.json();
    if (
      payload?.status !== "ok" ||
      payload?.service !== "tesemetria" ||
      payload?.database !== "postgres"
    ) {
      throw new Error(`${path}: resposta de saude invalida`);
    }
  } else {
    await response.body?.cancel();
  }
  return {
    path,
    elapsedMs,
    effectiveUrl: response.url,
  };
}

function checkCertificate(hostname) {
  return new Promise((resolve, reject) => {
    const socket = connect(
      {
        host: hostname,
        port: 443,
        servername: hostname,
        rejectUnauthorized: true,
        timeout: timeoutMs,
      },
      () => {
        const certificate = socket.getPeerCertificate();
        socket.end();
        const expiresAt = Date.parse(certificate.valid_to);
        const daysRemaining = Math.floor(
          (expiresAt - Date.now()) / 86_400_000,
        );
        if (!Number.isFinite(daysRemaining)) {
          reject(new Error(`${hostname}: certificado sem validade reconhecivel`));
          return;
        }
        if (daysRemaining < minimumCertificateDays) {
          reject(
            new Error(
              `${hostname}: certificado vence em ${daysRemaining} dias`,
            ),
          );
          return;
        }
        resolve({ hostname, daysRemaining });
      },
    );
    socket.once("timeout", () => {
      socket.destroy(new Error(`${hostname}: tempo limite ao validar TLS`));
    });
    socket.once("error", reject);
  });
}

async function checkLegacyRedirect(origin) {
  const suffix = "/verificacao-dominio?origem=monitor-publico";
  const response = await fetch(`${origin}${suffix}`, {
    redirect: "manual",
    signal: abortAfter(timeoutMs),
    headers: {
      "user-agent": "Tesemetria-Public-Monitor/1.0",
    },
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

async function main() {
  if (baseUrl.protocol !== "https:") {
    throw new Error("O monitor externo exige uma URL HTTPS.");
  }

  const httpResults = [];
  for (const check of checks) {
    httpResults.push(await checkHttp(check));
  }

  const redirectResults = [];
  for (const origin of legacyOrigins) {
    redirectResults.push(await checkLegacyRedirect(origin));
  }

  const certificateHosts = new Set([
    baseUrl.hostname,
    ...legacyOrigins.map((origin) => new URL(origin).hostname),
  ]);
  for (const result of httpResults) {
    certificateHosts.add(new URL(result.effectiveUrl).hostname);
  }
  const certificateResults = [];
  for (const hostname of certificateHosts) {
    certificateResults.push(await checkCertificate(hostname));
  }

  const slowest = [...httpResults].sort(
    (left, right) => right.elapsedMs - left.elapsedMs,
  )[0];
  console.log(
    JSON.stringify({
      status: "ok",
      checkedAt: new Date().toISOString(),
      baseUrl: baseUrl.origin,
      checks: httpResults,
      redirects: redirectResults,
      certificates: certificateResults,
      slowest: { path: slowest.path, elapsedMs: slowest.elapsedMs },
    }),
  );
}

main().catch((error) => {
  console.error(
    JSON.stringify({
      status: "failed",
      checkedAt: new Date().toISOString(),
      baseUrl: baseUrl.origin,
      error: error instanceof Error ? error.message : String(error),
    }),
  );
  process.exitCode = 1;
});

