/**
 * MCP transport detection.
 *
 * A Streamable-HTTP server binds a port; a stdio server reads JSON-RPC on
 * stdin. Getting this wrong meant pointing the stdio driver at an HTTP
 * server and grading it as dead, so the classifier is worth pinning.
 */
import { describe, expect, it } from "vitest";
import { detectTransport } from "../src/behavioral/harness/transport";

const f = (body: string, path = "server.js") => [{ path, body }];

describe("detectTransport", () => {
  it("detects a destructured node:http server that binds a port", () => {
    const body = `import { createServer } from "node:http";\ncreateServer(handler).listen(process.env.PORT || 3333);`;
    expect(detectTransport(f(body))).toBe("http");
  });

  it("detects the SDK Streamable-HTTP transport", () => {
    const body = `const t = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });`;
    expect(detectTransport(f(body))).toBe("http");
  });

  it("detects an express server", () => {
    expect(
      detectTransport(f(`const app = express(); app.post("/mcp", h); app.listen(8080);`)),
    ).toBe("http");
  });

  it("detects a python FastAPI/uvicorn server", () => {
    expect(detectTransport(f(`from fastapi import FastAPI\napp = FastAPI()`, "main.py"))).toBe(
      "http",
    );
  });

  it("detects a stdio server", () => {
    const body = `const t = new StdioServerTransport();\nawait server.connect(t);`;
    expect(detectTransport(f(body))).toBe("stdio");
  });

  it("prefers stdio when a server supports BOTH", () => {
    const body = `if (process.env.HTTP) { express().listen(3000); } else { new StdioServerTransport(); }`;
    expect(detectTransport(f(body))).toBe("stdio");
  });

  it("defaults to stdio for an unrecognized shape", () => {
    expect(detectTransport(f(`console.log("hello");`))).toBe("stdio");
  });

  it("ignores non-source files", () => {
    expect(detectTransport([{ path: "README.md", body: "run `express().listen()`" }])).toBe(
      "stdio",
    );
  });
});
