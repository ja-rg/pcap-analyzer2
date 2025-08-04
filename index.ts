/**
 * Main entry point for the PCAP analysis server (index.ts)
*/

import { join } from "path";
import { PcapAnalyzer } from "./class/PCAPAnalyzer";
import { corsHeaders } from "./lib/HelperCORS";
import { generateCustomRules } from "./lib/customRules";

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
      const contentType = req.headers.get("content-type") || "";
      if (!contentType.startsWith("multipart/form-data")) {
        return new Response("Expected multipart form", { status: 400 });
      }

      const formData = await req.formData();
      const file = formData.get("file");
      const rulesSelected = formData.get("rules"); // ← viene del frontend

      if (!file || typeof file !== "object") {
        return new Response("Missing file upload", { status: 400 });
      }

      // 📌 Parsear reglas seleccionadas
      let selectedRuleIds: string[] = [];
      try {
        if (rulesSelected) {
          selectedRuleIds = JSON.parse(rulesSelected as string);
        }
      } catch (err) {
        console.error("❌ Error parsing rules:", err);
      }

      // 📌 Guardar archivo PCAP
      await Bun.write("tmp/uploaded.pcap", await file.arrayBuffer());

      // 📌 Generar archivo de reglas dinámicamente
      await generateCustomRules(selectedRuleIds);

      // 📌 Analizar archivo
      const analyzer = new PcapAnalyzer("tmp/uploaded.pcap");
      const result = await analyzer.getResult();

      // 📌 Limpiar
      await analyzer.dropFile();

      return new Response(JSON.stringify(result), {
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
