import { Request, Response } from "express";
import fs from "fs";
import { parseXML } from "../utils/parsers/xmlParser";
import { parseCSV } from "../utils/parsers/csvParser";
import { parseExcel } from "../utils/parsers/excelParser";

export async function handleFileUpload(req: Request, res: Response): Promise<void> {
  const file = req.file;
  if (!file) {
    return void res.status(400).json({ error: "No file uploaded" });
  }

  const ext = file.originalname.split(".").pop()?.toLowerCase();

  try {
    let parsedData;

    if (ext === "xml") {
      parsedData = await parseXML(file.path);
    } else if (ext === "csv") {
      parsedData = await parseCSV(file.path);
    } else if (ext === "xlsx") {
      parsedData = parseExcel(file.path);
    } else {
      return void res.status(400).json({ error: "Unsupported file type" });
    }

    // Clean up temporary file
    fs.unlink(file.path, (err) => {
      if (err) console.error("Failed to delete temp file:", err);
    });

    res.json(parsedData);
  } catch (error) {
    console.error("Error parsing file:", error);
    res.status(500).json({ error: "Failed to parse file" });
  }
}
