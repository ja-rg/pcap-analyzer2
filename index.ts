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

