import { $ } from "bun";
import { fstat } from "fs";

export class PcapAnalyzer {
    private result: {
        capinfos: Record<string, string>;
        ip_host_pairs: { ip: string; host: string | null; type?: "private" | "public" }[];
        mac_addresses: { address: string; manufacturer: string | null }[];
        protocol_hierarchy: { protocol: string; frames: number; bytes: number }[];
        suricata: {
            eve: string | null;
            fast: string | null;
            stats: string | null;
            suricata: string | null;
        };
        tcp_streams: {
            stream_id: number;
            ip_src?: string;
            sport?: string;
            ip_dst?: string;
            dport?: string;
            text: string;
        }[];
        udp_streams: {
            stream_id: number;
            ip_src?: string;
            sport?: string;
            ip_dst?: string;
            dport?: string;
            text: string;
        }[];
    } | null = null;

    constructor(private pcapFile: string) {
        this.initialize();
    }

    private async initialize() {
        try {
            const [
                capinfos,
                ip_host_pairs,
                mac_addresses,
                protocol_hierarchy,
                suricata,
                tcp_streams,
                udp_streams
            ] = await Promise.all([
                this.getCapinfos(),
                this.getIpHostPairs(),
                this.getMacAddresses(),
                this.getProtocolHierarchy(),
                this.getSuricataAnalysis(),
                this.getTcpStreams(),
                this.getUdpStreams()
            ]);

            this.result = {
                capinfos,
                ip_host_pairs,
                mac_addresses,
                protocol_hierarchy,
                suricata,
                tcp_streams,
                udp_streams
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
        console.log("Capinfos ready!");

        return parsedResult;
    }

    private async getIpHostPairs() {
        const isPrivateIp = (ip: string): boolean => {
            const parts = ip.split(".").map(Number);
            if (parts.length !== 4) return false;
            const [a, b] = parts as [number, number];
            return (
                a === 10 ||
                (a === 172 && b >= 16 && b <= 31) ||
                (a === 192 && b === 168)
            );
        };

        const guessDomain = (ip: string): string | null => {
            // Heurística 1: Prefijos conocidos
            if (ip.startsWith("173.194.") || ip.startsWith("74.125.")) return "google.com";
            if (ip.startsWith("157.240.")) return "facebook.com";
            if (ip.startsWith("69.171.") || ip.startsWith("31.13.")) return "facebook.com";
            if (ip.startsWith("52.") || ip.startsWith("54.") || ip.startsWith("3.")) return "amazonaws.com";
            if (ip.startsWith("104.244.42.")) return "twitter.com";
            if (ip.startsWith("151.101.")) return "fastly.net";
            if (ip.startsWith("8.8.8.") || ip.startsWith("8.34.208.") || ip.startsWith("8.35.200.")) return "google-dns";

            // Heurística 2: Rango privado sin nombre
            if (isPrivateIp(ip)) return null;

            // Heurística 3: DNS inversa rápida (puede bloquear un poco)
            try {
                const rdns = require("child_process")
                    .execSync(`dig -x ${ip} +short`, { encoding: "utf-8" })
                    .trim();
                if (rdns) return rdns.replace(/\.$/, ""); // quitar el punto final de FQDN
            } catch { }

            return null;
        };

        const ipHostOutput = await $`tshark -r ${this.pcapFile} -T fields -e ip.src -e dns.qry.name`.text();

        const ipHostPairs = ipHostOutput
            .trim()
            .split("\n")
            .reduce((acc, line) => {
                const [ip, rawHost] = line.split("\t");
                if (ip && !acc.some((item) => item.ip === ip)) {
                    const type = isPrivateIp(ip) ? "private" : "public";
                    const cleanHost = rawHost?.trim() || null;
                    const finalHost = cleanHost || guessDomain(ip);
                    acc.push({ ip, host: finalHost, type });
                }
                return acc;
            }, [] as { ip: string; host: string | null; type: "private" | "public" }[]);

        console.log("IPs ready!");

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
        console.log("Mac ready!");
        return macAddresses;
    }

    private async getProtocolHierarchy() {
        const protoOutput = await $`tshark -r ${this.pcapFile} -q -z io,phs`.text();

        const lines = protoOutput
            .split("\n")
            .filter(line => line.includes("frames:") && line.includes("bytes:"));

        type ProtoNode = {
            protocol: string;
            frames: number;
            bytes: number;
            children: ProtoNode[];
        };

        const root: ProtoNode = { protocol: "root", frames: 0, bytes: 0, children: [] };
        const stack: { indent: number; node: ProtoNode }[] = [{ indent: -1, node: root }];

        for (const line of lines) {
            const match = line.match(/^(\s*)([^\s]+)\s+frames:(\d+)\s+bytes:(\d+)/);

            if (!match) continue; // si no hace match, saltamos

            // ✅ Asignamos con `!` para evitar errores de TS
            const spaces = match[1]!;
            const protocol = match[2]!;
            const framesStr = match[3]!;
            const bytesStr = match[4]!;

            const indent = spaces.length;
            const frames = parseInt(framesStr, 10);
            const bytes = parseInt(bytesStr, 10);

            const node: ProtoNode = { protocol, frames, bytes, children: [] };

            while (stack.length && stack[stack.length - 1]!.indent >= indent) {
                stack.pop();
            }

            // ✅ Aquí también aseguramos que nunca será undefined
            stack[stack.length - 1]!.node.children.push(node);
            stack.push({ indent, node });
        }
        console.log("Protocols ready.");

        return root.children;
    }

    async getResult() {
        // Ensure result is ready
        while (this.result === null) {
            await new Promise(resolve => setTimeout(resolve, 100));
        }
        return this.result;
    }

    async getSuricataAnalysis() {
        const logs = {
            eve: 'tmp/suricata_logs/eve.json',
            fast: 'tmp/suricata_logs/fast.json',
            stats: 'tmp/suricata_logs/stats.log',
            suricata: 'tmp/suricata_logs/suricata.log',
        };
        try {
            // Ejecutar Suricata
            await $`suricata -r ${this.pcapFile} -l tmp/suricata_logs -c /etc/suricata/suricata.yaml`;

            // Leer archivos de logs
            const eve = await Bun.file(logs.eve).text().catch(() => null);
            const fast = await Bun.file(logs.fast).text().catch(() => null);
            const stats = await Bun.file(logs.stats).text().catch(() => null);
            const suricata = await Bun.file(logs.suricata).text().catch(() => null);

            console.log("Suricata ready.");
            return {
                eve,
                fast,
                stats,
                suricata,
            };
        } catch (err) {
            console.error("❌ Error running Suricata analysis:", err);
            return {
                eve: null,
                fast: null,
                stats: null,
                suricata: null,
            };
        }
    }

    async dropFile() {
        try {
            await $`rm ${this.pcapFile}`;
            await $`rm tmp/suricata_logs/*`;
            console.log(`✅ File ${this.pcapFile} deleted successfully.`);
        } catch (err) {
            console.error("❌ Error deleting file:", err);
        }
    }

    private async getTcpStreams() {
        //return [];
        // Get list of TCP conversations
        const convOutput = await $`tshark -r ${this.pcapFile} -q -z conv,tcp`.text();
        const lines = convOutput.split("\n").filter(l => l.includes("<->"));

        const streams: any[] = [];

        for (let idx = 0; idx < lines.length; idx++) {
            // Follow each TCP stream
            const follow = await $`tshark -r ${this.pcapFile} -q -z follow,tcp,ascii,${idx}`.text();

            // Extract Node 0 and Node 1
            const node0Match = follow.match(/Node 0:\s+([\d.]+):(\d+)/);
            const node1Match = follow.match(/Node 1:\s+([\d.]+):(\d+)/);

            streams.push({
                stream_id: idx,
                ip_src: node0Match?.[1] || "",
                sport: node0Match?.[2] || "",
                ip_dst: node1Match?.[1] || "",
                dport: node1Match?.[2] || "",
                text: follow
            });
        }

        console.log("TCP ready.");
        return streams;
    }

    private async getUdpStreams() {
        return [];
        const convOutput = await $`tshark -r ${this.pcapFile} -q -z conv,udp`.text();
        const lines = convOutput.split("\n").filter(l => l.includes("<->"));

        const streams: any[] = [];
        for (let idx = 0; idx < lines.length; idx++) {
            // Follow each UDP stream (note: tshark follow works better for TCP)
            const follow = await $`tshark -r ${this.pcapFile} -q -z follow,udp,ascii,${idx}`.text();
            streams.push({
                stream_id: idx,
                text: follow
            });
        }
        console.log("UDP ready.");
        return streams;
    }
}