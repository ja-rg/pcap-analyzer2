// tests/index.test.ts
import { describe, it, expect, beforeEach, mock, jest } from "bun:test";
import { PcapAnalyzer } from "../class/PCAPAnalyzer";
import { corsHeaders } from "../lib/HelperCORS";

// --- Mocks de módulos ---

describe("PcapAnalyzer", () => {
  let analyzer: PcapAnalyzer;

  beforeEach(() => {
    analyzer = new PcapAnalyzer("tmp/fake.pcap");

    // Sobrescribir métodos con jest.fn()
    analyzer["getCapinfos"] = jest.fn().mockResolvedValue({ "Mock-Key": "Mock-Value" });
    analyzer["getIpHostPairs"] = jest.fn().mockResolvedValue([{ ip: "1.1.1.1", host: "cloudflare", type: "public" }]);
    analyzer["getMacAddresses"] = jest.fn().mockResolvedValue([{ address: "00:00:00:00:00:00", manufacturer: "MockVendor" }]);
    analyzer["getProtocolHierarchy"] = jest.fn().mockResolvedValue([{ protocol: "ip", frames: 10, bytes: 100, children: [] }]);
    analyzer["getSuricataAnalysis"] = jest.fn().mockResolvedValue({ eve: null, fast: null, stats: null, suricata: null });
    analyzer["getTcpStreams"] = jest.fn().mockResolvedValue([]);
    analyzer["getUdpStreams"] = jest.fn().mockResolvedValue([]);
  });

  it("debe devolver resultados de análisis", async () => {
    const result = await analyzer.getResult();
    expect(result).toHaveProperty("capinfos");
    expect(result.capinfos).toHaveProperty("Mock-Key");
  });

  it("debe poder borrar el archivo", async () => {
    analyzer["dropFile"] = jest.fn().mockResolvedValue(undefined);
    await expect(analyzer.dropFile()).resolves.toBeUndefined();
  });
});
