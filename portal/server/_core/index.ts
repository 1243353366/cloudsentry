import "dotenv/config";
import express from "express";
import { createServer } from "http";
import { publicPlatformScript } from "./publicConfig";
import { serveStatic, setupVite } from "./vite";
import { registerCustomerAuthRoutes } from "../customer-auth";
import { registerCustomerApiRoutes } from "../customer-api";
import { DrizzleCustomerRepository } from "../customer-db";

async function startServer() {
  const app = express();
  const server = createServer(app);
  const customerRepository = new DrizzleCustomerRepository();
  const customerAuth = { repository: customerRepository };

  // Customer REST accepts bounded JSON imports only; it never accepts files or host commands.
  app.use(express.json({ limit: "1mb" }));
  app.use(express.urlencoded({ limit: "1mb", extended: false }));
  app.get("/api/health", (_req, res) => res.json({ status: "ok" }));
  app.get("/api/platform/config.js", (_req, res) => {
    res.set("Cache-Control", "no-store").type("application/javascript").send(publicPlatformScript());
  });

  // No legacy OAuth callback or tRPC login path is registered. Customer access is
  // exclusively the managed flow and its own revocable CSRF-bound session.
  registerCustomerAuthRoutes(app, customerAuth);
  registerCustomerApiRoutes(app, { repository: customerRepository, authDependencies: customerAuth });

  app.use((error: unknown, _req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (res.headersSent) return next(error);
    if (error instanceof SyntaxError || (typeof error === "object" && error !== null && "type" in error)) {
      res.status(400).set("Cache-Control", "no-store").json({ error: "generic" });
      return;
    }
    res.status(500).set("Cache-Control", "no-store").json({ error: "generic" });
  });

  if (process.env.NODE_ENV === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }

  const port = Number(process.env.PORT || "3000");
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Invalid PORT");
  server.on("error", error => { console.error("Server failed:", error.message); process.exit(1); });
  server.listen(port, "0.0.0.0", () => console.log(`Server listening on port ${port}`));
}

startServer().catch(error => { console.error(error); process.exit(1); });
