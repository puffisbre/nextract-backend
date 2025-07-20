import { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";

const SECRET = process.env.JWT_SECRET || "hemlig_nyckel";

export interface AuthRequest extends Request {
  user?: any;
}

export function verifyToken(req: AuthRequest, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.status(401).json({ message: "Ingen token tillhandahållen" });
    return;
  }

  const token = authHeader.split(" ")[1];
  console.log("Token", token);
  try {
    const decoded = jwt.verify(token, SECRET, {
      algorithms: ["HS256"]});
    console.log("Decoded token", decoded);
    req.user = decoded;
    next();
  } catch (err) {
    console.error("Error", err);
    res.status(403).json({ message: "Ogiltig token" });
    return;
  }
}
