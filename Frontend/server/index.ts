import express, { type Request, Response, NextFunction } from "express";
import { registerRoutes } from "./routes";
import { setupVite, serveStatic, log } from "./vite";
import { ensureDirectoriesExist } from "./file-utils";
import os from "os";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Resolve scanner base path: env var > sibling Backend directory
const scannerBase = process.env.SCANNER_BASE || path.resolve(__dirname, '..', '..', 'Backend');
process.env.SCANNER_BASE = scannerBase;
log(`Scanner base path: ${scannerBase}`);

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use((req, res, next) => {
  const start = Date.now();
  const path = req.path;
  let capturedJsonResponse: Record<string, any> | undefined = undefined;

  const originalResJson = res.json;
  res.json = function (bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };

  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path.startsWith("/api")) {
      let logLine = `${req.method} ${path} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }

      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "…";
      }

      log(logLine);
    }
  });

  next();
});

(async () => {
  // Ensure all necessary directories exist before starting
  await ensureDirectoriesExist();

  const server = await registerRoutes(app);

  app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";

    res.status(status).json({ message });
    throw err;
  });

  // Only setup Vite in development
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }

  // Serve on port 5000
  const port = 5000;
  const host = "0.0.0.0";

  server.listen({ port, host, reusePort: true }, () => {
    const localUrl = `http://localhost:${port}`;
    let networkUrl: string | undefined;

    // Get LAN IP
    const interfaces = os.networkInterfaces();
    for (const iface of Object.values(interfaces)) {
      if (!iface) continue;
      for (const config of iface) {
        if (config.family === "IPv4" && !config.internal) {
          networkUrl = `http://${config.address}:${port}`;
          break;
        }
      }
      if (networkUrl) break;
    }

    log(`🚀 Server running at:`);
    log(`   • Local:   ${localUrl}`);
    if (networkUrl) {
      log(`   • Network: ${networkUrl}`);
    } else {
      log(`   • Network: Not available`);
    }
  });
})();
