/**
 * Main entry point for the PCAP analysis server (index.ts)
*/

import { join } from "path";
import { PcapAnalyzer } from "./class/PCAPAnalyzer";
import { corsHeaders } from "./lib/HelperCORS";

// === SERVER ===
Bun.serve({
  port: 3000,
  hostname: "0.0.0.0",
  async fetch(req) {
    if (req.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(),
      });
    }

    if (req.method === "GET") {
      // Obtener la ruta solicitada
      const url = new URL(req.url);
      let pathname = url.pathname === "/" ? "/index.html" : url.pathname;

      // Construir la ruta física dentro de dist
      const filePath = join("dist", pathname);

      try {
        const file = Bun.file(filePath);

        if (!(await file.exists())) {
          return new Response("Not found", { status: 404 });
        }

        // Detectar tipo MIME básico
        const ext = filePath.split(".").pop();
        const mimeTypes = {
          html: "text/html",
          css: "text/css",
          js: "application/javascript",
          json: "application/json",
          png: "image/png",
          jpg: "image/jpeg",
          jpeg: "image/jpeg",
          svg: "image/svg+xml",
          ico: "image/x-icon",
        };

        // If ext is undefined, return 404
        if (!ext) {
          return new Response("Not found", { status: 404 });
        }

        const contentType = mimeTypes[ext as keyof typeof mimeTypes] || "application/octet-stream";

        return new Response(file.stream(), {
          headers: corsHeaders({ "Content-Type": contentType }),
          status: 200,
        });
      } catch {
        return new Response("Not found", { status: 404 });
      }
    }

    if (req.method !== "POST") {
      return new Response("Only POST supported", { status: 405 });
    }

    try {
      // 1. Parse multipart form and get the file
      const contentType = req.headers.get("content-type") || "";
      if (!contentType.startsWith("multipart/form-data")) {
        return new Response("Expected multipart form", { status: 400 });
      }

      const formData = await req.formData();
      const file = formData.get("file");

      if (!file || typeof file !== "object") {
        return new Response("Missing file upload", { status: 400 });
      }

      // 2. Save file to /tmp directory with unique name
      await Bun.write('tmp/uploaded.pcap', await file.arrayBuffer());

      // 3. Analyze the file
      const analyzer = new PcapAnalyzer('tmp/uploaded.pcap');
      const result = await analyzer.getResult();

      // 4. Delete file from disk using terminal
      await analyzer.dropFile();
      const response = JSON.stringify(result);

      // 5. Return JSON result
      return new Response(response, {
        headers: corsHeaders({ "Content-Type": "application/json" }),
      });
    } catch (err) {
      console.error("❌ Failed to handle POST:", err);

      return new Response(JSON.stringify({ error: "Server error" }), {
        status: 500,
        headers: corsHeaders({ "Content-Type": "application/json" }),
      });
    }

  },
});

console.log(`Ready to Accept Requests ${Math.floor(Math.random() * (5 - 0 + 1))}`);
