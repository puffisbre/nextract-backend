import * as XLSX from "xlsx";

export function parseExcel<T = Record<string, string>>(filePath: string): T[] {
  const workbook = XLSX.readFile(filePath);
  const sheetName = workbook.SheetNames[0];
  const worksheet = workbook.Sheets[sheetName];
  return XLSX.utils.sheet_to_json(worksheet);
}
