import { readFile } from "fs/promises";
import { XMLParser } from "fast-xml-parser";

const currencySymbols: Record<string, string> = {
  USD: "$",
  EUR: "€",
  GBP: "£",
  SEK: "kr",
  JPY: "¥",
  NOK: "kr",
  AUD: "A$",
  CAD: "C$",
  CHF: "CHF"
  // ADD ADDITIONAL CURRENCY
};

export async function parseXML(filePath: string) {
  const xml = await readFile(filePath, "utf-8");

  const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: "",
    textNodeName: "value"
  });

  const parsed = parser.parse(xml);

  
  if (parsed.price) {
    const priceNode = parsed.price;
    const amount = priceNode.value;
    const currencyCode = priceNode.currency || "USD";
    const symbol = currencySymbols[currencyCode] || currencyCode;

    parsed.price = {
      amount,
      currency: {
        code: currencyCode,
        symbol
      }
    };
  }

  return parsed;
}
