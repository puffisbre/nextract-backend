import { Request, Response } from "express";
import { generateToken } from "../utils/jwt";
import { PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();

import bcrypt from "bcrypt";
const SALT_ROUNDS = 10;

export async function getAllUsers(req: Request, res: Response) {
  try {
    const users = await prisma.user.findMany({
      select: {
        id: true,
        email: true,
      },
    });
    res.status(200).json(users);
  } catch (error) {
    res.status(500).json({ error: "Could not fetch users" });
  }
}

export async function getUserById(req: Request, res: Response) {
  const userId = req.params.id;

  try {
    const user = await prisma.user.findUnique({
      where: {
        id: userId,
      },
      select: {
        id: true,
        email: true,
      },
    });

    if (!user) {
      res.status(404).json({ message: "User not found" });
      return;
    }

    res.status(200).json(user);
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
}

export async function createUser(req: Request, res: Response) {
  const { email, password, company } = req.body;
  // const admin = await prisma.admin.findFirst({ where: { email: "admin.group5@admin.se" } });
  const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

  const user = await prisma.user.findUnique({
    where: {
      email: email.toLowerCase(),
    },
  });

  if (user) {
    res.status(409).json({ message: "This email is already in use" });
    return;
  }

  try {
    const user = await prisma.user.create({
      data: {
        email: email.toLowerCase(),
        company: company.toLowerCase(),
        password: hashedPassword,
        adminId: null,
      },
    });
    res.status(201).json({ message: `User created: `, user: user });
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
}

export async function loginUser(req: Request, res: Response) {
  const { email, password } = req.body;

  try {
    const user = await prisma.user.findUnique({
      where: {
        email: email.toLowerCase(),
      },
    });

    if (!user) {
      res.status(404).json({ message: "User not found" });
      return;
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      res.status(401).json({ message: "Invalid password" });
      return;
    }
    const token = generateToken({ userId: user.id});
    res.status(200).json({ message: "Login successful", user: user, token: token });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal server error" });
  }
}

export async function updateUser(req: Request, res: Response) {
  const userId = req.params.id;
  const { email } = req.body;

  try {
    const updatedUser = await prisma.user.update({
      where: { id: userId },
      data: { email: email.toLowerCase() },
    });

    res.status(200).json(updatedUser);
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
}

export function deleteUser(req: Request, res: Response) {
  const userId = req.params.id;

  try {
    prisma.user.delete({
      where: { id: userId },
    });
    res.status(200).json({ message: "User deleted" });
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
}

