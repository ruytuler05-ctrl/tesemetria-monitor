import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  CONNECTION_TIMEOUT_MS,
  REDIRECT_ORIGINS,
  describeError,
  validateHealthPayload,
  validateStrictTransportSecurity,
} from "./monitor.mjs";

test("preserva a causa de uma falha de rede", () => {
  const cause = Object.assign(new Error("connect ETIMEDOUT"), {
    code: "ETIMEDOUT",
    syscall: "connect",
    address: "179.198.99.115",
    port: 443,
  });
  const error = new TypeError("fetch failed", { cause });
  assert.deepEqual(describeError(error), {
    message: "fetch failed <- connect ETIMEDOUT",
    code: "ETIMEDOUT",
    syscall: "connect",
    address: "179.198.99.115",
    port: 443,
  });
});

test("exige o contrato completo da saude da aplicacao", () => {
  assert.deepEqual(
    validateHealthPayload({
      status: "ok",
      database: "postgres",
      asyncProcessing: "ok",
      recovery: { status: "healthy" },
      release: "abcdef123456",
    }),
    {
      status: "ok",
      database: "postgres",
      asyncProcessing: "ok",
      recovery: "healthy",
      release: "abcdef123456",
    },
  );
  assert.throws(
    () =>
      validateHealthPayload({
        status: "ok",
        database: "postgres",
        asyncProcessing: "failed",
        recovery: { status: "healthy" },
        release: "abcdef123456",
      }),
    /resposta de saude invalida/,
  );
});

test("exige HSTS por pelo menos um ano", () => {
  assert.equal(
    validateStrictTransportSecurity("max-age=31536000; includeSubDomains"),
    "max-age=31536000; includeSubDomains",
  );
  assert.throws(
    () => validateStrictTransportSecurity("max-age=86400"),
    /abaixo de um ano/,
  );
  assert.throws(() => validateStrictTransportSecurity(null), /ausente/);
});

test("inclui os dominios .com na regra de redirecionamento", () => {
  assert.ok(REDIRECT_ORIGINS.includes("https://tesemetria.com"));
  assert.ok(REDIRECT_ORIGINS.includes("https://www.tesemetria.com"));
});

test("mantem o probe externo, a porta 443 e o timeout P0 no workflow", async () => {
  const workflow = await readFile(".github/workflows/monitor.yml", "utf8");
  const source = await readFile("monitor.mjs", "utf8");
  assert.match(workflow, /runs-on: ubuntu-latest/);
  assert.match(workflow, /node --test monitor\.test\.mjs/);
  assert.match(source, /resolve4/);
  assert.match(source, /connectTcp/);
  assert.match(source, /connectTls/);
  assert.match(source, /port: 443/);
  assert.equal(CONNECTION_TIMEOUT_MS, 6_000);
});
