import { $ } from "bun";

class PcapAnalyzer {
  private result: {
    capinfos: Record<string, string>;
    ip_host_pairs: { ip: string; host: string | null }[];
    mac_addresses: { address: string; manufacturer: string | null }[];
    protocol_hierarchy: { protocol: string; frames: number; bytes: number }[];
  } | null = null;

  constructor(private pcapFile: string) {
    this.initialize();
  }

  private async initialize() {
    try {
      const [capinfos, ip_host_pairs, mac_addresses, protocol_hierarchy] = await Promise.all([
        this.getCapinfos(),
        this.getIpHostPairs(),
        this.getMacAddresses(),
        this.getProtocolHierarchy(),
      ]);

      this.result = {
        capinfos,
        ip_host_pairs,
        mac_addresses,
        protocol_hierarchy,
      };
    } catch (err) {
      console.error("❌ Error initializing analysis:", err);
    }
  }

  private async getCapinfos() {
    const capinfosOutput = await $`capinfos -M -a -e -c -u -d -i -y -z -q ${this.pcapFile}`.text();
    const lines = capinfosOutput.trim().split("\n");
    const parsedResult: Record<string, string> = {};
    for (const line of lines) {
      const [key, ...valueParts] = line.split(":");
      const value = valueParts.join(":".trim());
      if (key && value) {
        parsedResult[key.trim()] = value;
      }
    }
    return parsedResult;
  }

  public async extractPrintableTcpPayload(outputFile = "printable_payload.txt") {
    try {
      const hexPayload = await $`tshark -r ${this.pcapFile} -Y "tcp" -T fields -e tcp.payload`.text();

      if (!hexPayload.trim()) {
        console.warn("⚠️ No TCP payloads found.");
        return null;
      }

      // Unimos todas las líneas hex en una sola string continua
      const hexString = hexPayload
        .trim()
        .split("\n")
        .map(line => line.trim())
        .join("");

      // Convertimos el hex string a un buffer
      const buffer = Buffer.from(hexString, "hex");

      // Extraemos solo caracteres imprimibles (ASCII 32–126 y salto de línea)
      const printable = buffer
        .toString("ascii")
        .split("")
        .filter(c => {
          const code = c.charCodeAt(0);
          return (code >= 32 && code <= 126) || code === 10; // espacio a ~ o saltos de línea
        })
        .join("");

      // Guardamos en archivo
      const fs = await import("fs/promises");
      await fs.writeFile(outputFile, printable, "utf-8");

      console.log(`✅ Printable ASCII payload written to: ${outputFile}`);
      return outputFile;

    } catch (err) {
      console.error("❌ Error extracting printable TCP payload:", err);
      return null;
    }
  }


  private async getIpHostPairs() {
    const isPrivateIp = (ip: string): boolean => {
      const parts = ip.split(".").map(Number);

      if (parts.length !== 4) return false;

      const [a, b] = parts as [number, number, number, number];

      return (
        a === 10 ||
        (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && b === 168)
      );
    };

    const ipHostOutput = await $`tshark -r ${this.pcapFile} -T fields -e ip.src -e dns.qry.name`.text();
    const ipHostPairs = ipHostOutput.trim().split("\n").reduce((acc, line) => {
      const [ip, host] = line.split("\t");

      if (ip && !acc.some((item) => item.ip === ip)) {
        const type = isPrivateIp(ip) ? "private" : "public";
        acc.push({ ip, host: host?.trim() || null, type });
      }

      return acc;
    }, [] as { ip: string; host: string | null; type: "private" | "public" }[]);

    return ipHostPairs;
  }


  private async getMacAddresses() {
    const macOutput = await $`tshark -r ${this.pcapFile} -T fields -e eth.src -e eth.src.oui_resolved`.text();

    const seen = new Set();
    const macAddresses = macOutput
      .trim()
      .split("\n")
      .map(line => {
        const [address, manufacturer] = line.split("\t");
        if (!address || seen.has(address)) return null;
        seen.add(address);
        return {
          address: address.trim(),
          manufacturer: manufacturer?.trim() || null
        };
      })
      .filter(Boolean) as { address: string; manufacturer: string | null }[];

    return macAddresses;
  }

  private async getProtocolHierarchy() {
    const protoOutput = await $`tshark -r ${this.pcapFile} -q -z io,phs`.text();
    const lines = protoOutput.split("\n").filter(line => line.includes("frames:") && line.includes("bytes:"));
    const hierarchy: { protocol: string; frames: number; bytes: number }[] = [];

    for (const line of lines) {
      const match = line.match(/^(\s*)([^\s]+)\s+frames:(\d+)\s+bytes:(\d+)/);
      if (match !== null) {
        const protocol = match[2]!;
        const frames = parseInt(match[3]!, 10);
        const bytes = parseInt(match[4]!, 10);
        hierarchy.push({ protocol, frames, bytes });
      }
    }

    return hierarchy;
  }

  async getResult() {
    // Ensure result is ready
    while (this.result === null) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    return this.result;
  }

  async getSuricataAnalysis() {
    try {
      const suricataOutput = await $`suricata -r ${this.pcapFile} -l /tmp/suricata_logs -c /etc/suricata/suricata.yaml`.text();
      console.log("Suricata analysis completed successfully.");
      return suricataOutput;
    } catch (err) {
      console.error("❌ Error running Suricata analysis:", err);
      return null;
    }
  }

  async dropFile() {
    try {
      await $`rm ${this.pcapFile}`;
      console.log(`✅ File ${this.pcapFile} deleted successfully.`);
    } catch (err) {
      console.error("❌ Error deleting file:", err);
    }
  }

}

// === SERVER ===
Bun.serve({
  port: 3000,

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

      // 5. Return JSON result
      return new Response(JSON.stringify(result), {
        headers: corsHeaders({ "Content-Type": "application/json" }),
      });
    } catch (err) {
      console.error("❌ Failed to handle POST:", err);
      return new Response("Server error", { status: 500 });
    }
  },
});

// === Helpers ===
function corsHeaders(extra: Record<string, string> = {}) {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    ...extra,
  };
}