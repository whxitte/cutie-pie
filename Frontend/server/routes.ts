import type { Express, Request, Response } from "express";
import { createServer, type Server } from "http";
import { z } from "zod";
import { storage } from "./storage";
import { ensureDirectoriesExist, getAllIPs, getServices, addService, deleteService, getClassifiedIPs, getEnrichedIPs, getLatestEnrichedIP, getCrackedIPs } from "./file-utils";
import { addServiceSchema } from "@shared/schema";
import path from "path";
import { fileURLToPath } from "url";
import { promises as fs } from "fs";

// Define __dirname for ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const BASE_PATH = process.env.SCANNER_BASE || path.join(__dirname, '..', '..', 'Backend');
const PORTS_FILE = path.join(BASE_PATH, 'config', 'ports.conf');
const CLASSIFIED_DIR = path.join(BASE_PATH, 'logs', 'scanner', 'classified');

export async function registerRoutes(app: Express): Promise<Server> {
  // Ensure all necessary directories exist
  await ensureDirectoriesExist();

  // API endpoint to get all IPs
  app.get("/api/all", async (req: Request, res: Response) => {
    try {
      const ips = await getAllIPs();
      res.json(ips);
    } catch (error) {
      console.error("Error fetching all IPs:", error);
      res.status(500).json({ message: "Failed to fetch all IPs" });
    }
  });

  // API endpoint to get services
  app.get("/api/services", async (req: Request, res: Response) => {
    try {
      const services = await getServices();
      res.json(services);
    } catch (error) {
      console.error("Error fetching services:", error);
      res.status(500).json({ message: "Failed to fetch services" });
    }
  });

  // API endpoint to add a service
  app.post("/api/services", async (req: Request, res: Response) => {
    try {
      const result = addServiceSchema.safeParse(req.body);

      if (!result.success) {
        return res.status(400).json({
          message: "Invalid service data",
          errors: result.error.errors
        });
      }

      const { port, service } = result.data;
      const success = await addService(port, service);

      if (success) {
        // Create signal file to notify the script
        await fs.writeFile(path.join(BASE_PATH, 'config', '.ports_changed'), '', { flag: 'w' });
        res.status(201).json({ message: "Service added successfully" });
      } else {
        res.status(409).json({ message: "Service already exists" });
      }
    } catch (error) {
      console.error("Error adding service:", error);
      res.status(500).json({ message: "Failed to add service" });
    }
  });

  app.delete("/api/services/:port", async (req: Request, res: Response) => {
    try {
      const { port } = req.params;
      const data = await fs.readFile(PORTS_FILE, 'utf8');
      let serviceName = '';
      const lines = data.split('\n').filter(line => {
        const [confPort, service] = line.split('#').map(s => s.trim());
        if (confPort === port) {
          serviceName = service.toLowerCase().replace(/\s+/g, '');
          return false; // Remove this line
        }
        return true;
      });

      await fs.writeFile(PORTS_FILE, lines.join('\n'));

      if (serviceName) {
        const classifiedFile = path.join(CLASSIFIED_DIR, `${serviceName}.txt`);
        try {
          await fs.unlink(classifiedFile);
          console.log(`Deleted classified file: ${classifiedFile}`);
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
            throw error; // Ignore if file doesn't exist
          }
        }
      }

      const success = await deleteService(port);
      if (success) {
        // Create signal file to notify the script
        await fs.writeFile(path.join(BASE_PATH, 'config', '.ports_changed'), '', { flag: 'w' });
        res.json({ message: "Service deleted successfully" });
      } else {
        res.status(404).json({ message: "Service not found" });
      }
    } catch (error) {
      console.error("Error deleting service:", error);
      res.status(500).json({ message: "Failed to delete service" });
    }
  });

  // API endpoint to get classified IPs
  app.get("/api/classified", async (req: Request, res: Response) => {
    try {
      const ips = await getClassifiedIPs();
      res.json(ips);
    } catch (error) {
      console.error("Error fetching classified IPs:", error);
      res.status(500).json({ message: "Failed to fetch classified IPs" });
    }
  });

  // API endpoint to get enriched IPs
  app.get("/api/enriched", async (req: Request, res: Response) => {
    try {
      const ips = await getEnrichedIPs();
      res.json(ips);
    } catch (error) {
      console.error("Error fetching enriched IPs:", error);
      res.status(500).json({ message: "Failed to fetch enriched IPs" });
    }
  });

  // API endpoint to get the latest enriched IP
  app.get("/api/enriched/latest", async (req: Request, res: Response) => {
    try {
      const latestIP = await getLatestEnrichedIP();
      if (latestIP) {
        res.json(latestIP);
      } else {
        res.status(404).json({ message: "No enriched data available" });
      }
    } catch (error) {
      console.error("Error fetching latest enriched IP:", error);
      res.status(500).json({ message: "Failed to fetch latest enriched IP" });
    }
  });

  // API endpoint to get cracked IPs
  app.get("/api/cracked", async (req: Request, res: Response) => {
    try {
      const ips = await getCrackedIPs();
      res.json(ips);
    } catch (error) {
      console.error("Error fetching cracked IPs:", error);
      res.status(500).json({ message: "Failed to fetch cracked IPs" });
    }
  });

  const httpServer = createServer(app);

  return httpServer;
}