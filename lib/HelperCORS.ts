// === Helpers ===
export function corsHeaders(extra: Record<string, string> = {}) {
    return {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        ...extra,
    };
}
