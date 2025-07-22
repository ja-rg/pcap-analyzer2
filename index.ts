import { $ } from "bun";

class PcapAnalyzer {
  private result: {
    capinfos: Record<string, string>;
    ip_host_pairs: { ip: string; host: string | null }[];
    mac_addresses: string[];
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

  private async getIpHostPairs() {
    const ipHostOutput = await $`tshark -r ${this.pcapFile} -T fields -e ip.src -e dns.qry.name`.text();
    const ipHostPairs = ipHostOutput.trim().split("\n").reduce((acc, line) => {
      const [ip, host] = line.split("\t");
      if (ip && !acc.some((item) => item.ip === ip)) {
        acc.push({ ip, host: host?.trim() || null });
      }
      return acc;
    }, [] as { ip: string; host: string | null }[]);
    return ipHostPairs;
  }

  private async getMacAddresses() {
    const macOutput = await $`tshark -r ${this.pcapFile} -T fields -e eth.src`.text();
    const macAddresses = Array.from(new Set(macOutput.trim().split("\n").filter(Boolean)));
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
}

const analyzer = new PcapAnalyzer("2015-02-24-traffic-analysis-exercise.pcap");
const result = await analyzer.getResult();

console.log("✅ Final parsed JSON result:");
console.log(JSON.stringify(result, null, 2));

const suricataResult = await analyzer.getSuricataAnalysis();
if (suricataResult) {
  console.log("✅ Suricata analysis result:");
  console.log(suricataResult);
}