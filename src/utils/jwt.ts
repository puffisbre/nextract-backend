import jwt from "jsonwebtoken";

const JWT_SECRET = process.env.JWT_SECRET || "supersecret_dev_only";

export const generateToken= (payload: object): string => {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "12h" });
};

