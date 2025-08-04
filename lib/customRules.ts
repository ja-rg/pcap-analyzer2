import { writeFile, readFile } from "fs/promises";

export async function generateCustomRules(selectedIds: string[]) {
  // 📌 Leer todas las reglas base
  const allRules = await readFile("rules/all.rules", "utf-8");

  // 📌 Si no selecciona nada, usar todas
  if (!selectedIds || selectedIds.length === 0) {
    await writeFile("rules/custom.rules", allRules);
    console.log(`✅ Usando todas las reglas (${allRules.split("\n").length} líneas).`);
    return;
  }

  const lines = allRules.split("\n");
  const filteredBlocks: string[] = [];
  let currentBlock: string[] = [];
  let includeBlock = false;

  for (const line of lines) {
    // Detectar inicio de bloque con # ID:
    if (line.startsWith("# ID:")) {
      // Si había un bloque previo que debe incluirse, lo guardamos
      if (currentBlock.length > 0 && includeBlock) {
        filteredBlocks.push(currentBlock.join("\n"));
      }
      // Reiniciamos el bloque actual
      currentBlock = [line];
      // Determinar si este bloque se incluye
      const ruleId = line.replace("# ID:", "").trim();
      includeBlock = selectedIds.includes(ruleId);
    } else {
      // Acumular línea en bloque actual
      currentBlock.push(line);
    }
  }

  // Revisar último bloque
  if (currentBlock.length > 0 && includeBlock) {
    filteredBlocks.push(currentBlock.join("\n"));
  }

  // 📌 Guardar archivo temporal de reglas
  const result = filteredBlocks.join("\n\n");
  await writeFile("rules/custom.rules", result);

  console.log(`✅ Custom rules generadas con ${filteredBlocks.length} bloques de reglas.`);
}
