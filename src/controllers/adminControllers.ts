import { Request, Response } from "express";
import { PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();

export async function deleteUser(req: Request, res: Response) {
  const userId = req.params.id;

  try {
    await prisma.originalApi.deleteMany({ where: { userId } });
    await prisma.finishedAPI.deleteMany({ where: { userId } });

    await prisma.user.delete({
      where: { id: userId },
    });

    res.status(200).json({ message: "Användaren är borttagen" });
  } catch (error) {
    res.status(500).json({ error: "Kunde inte ta bort användaren" });
  }
}

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
    res.status(500).json({ error: "Kunde inte hämta användare" });
  }
}

export async function getUserById(req: Request, res: Response) {
  const userId = req.params.id;

  try {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
      },
    });

    if (!user) {
      res.status(404).json({ error: "Användaren hittades inte" });
      return;
    }

    res.status(200).json(user);
  } catch (error) {
    console.error("Fel vid hämtning av användare:", error);
    res.status(500).json({ error: "Kunde inte hämta användare" });
  }
}
