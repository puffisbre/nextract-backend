import { Request, Response } from "express";
import { PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();

export async function getAllFinishedAPIs(req: Request, res: Response) {
  try {
    const finishedAPIs = await prisma.finishedAPI.findMany({
      select: {
        id: true,
        items: true,
        userId: true,
      },
    });
    res.status(200).json(finishedAPIs);
  } catch (error) {
    console.error("Error fetching finished APIs:", error);
    res.status(500).json({ error: "Could not fetch finished APIs" });
  }
}

export async function getAllFinishedAPIsByUser(req: Request, res: Response) {
  const { userId } = req.body;

  try {
    const usersFinishedAPIs = await prisma.finishedAPI.findMany({
      where: {
        userId,
      },
      select: {
        id: true,
        items: true,
        originalApi: true,
        originalApiId: true,
        APIname: true,
      },
    });

    if (!userId) {
      res.status(404).json("userId missing");
    }

    res.status(200).json(usersFinishedAPIs);
  } catch (error) {
    res.status(500).json({ error: "Could not fetch finished API:s" });
  }
}

export async function saveFinishedAPI(req: Request, res: Response) {
  const { items, userId, apiUrl, apiKey, APIname } = req.body;

  try {
    const usersOriginalApi = await prisma.originalApi.create({
      data: {
        apiUrl: apiUrl,
        apiKey: apiKey,
        userId: userId,
      },
    });
    if (!usersOriginalApi) {
      res.status(400).json("Original API not Created");
    }

    const usersFinishedAPI = await prisma.finishedAPI.create({
      data: {
        items: items,
        userId: userId,
        originalApiId: usersOriginalApi.id,
        APIname: APIname,
      },
    });

    if (!items || !userId) {
      res.status(404).json("Items or userId missing");
    }

    res.status(201).json({ message: "Saved finished API:", items, userId });
  } catch (error) {
    res.status(500).json({ error: "Could not save finished API" });
  }
}

export async function updateFinishedAPI(req: Request, res: Response) {
  const { items, APIId } = req.body;

  try {
    const updatedAPI = await prisma.finishedAPI.update({
      where: { id: APIId },
      data: { items: items, updatedAt: new Date() },
    });

    if (!updatedAPI) {
      res.status(404).json("API not found");
    }

    res.status(200).json({ message: "Updated finished API:", updatedAPI });
  } catch (error) {
    res.status(500).json({ error: "Could not update finished API" });
  }
}

export async function getRecentActivitiesByUser(req: Request, res: Response) {
  const { userId } = req.body;
  try {
    if (!userId) {
      res.status(404).json("userId missing");
    }
    const recentActivities = await prisma.finishedAPI.findMany({
      where: { userId },
      select: {
        id: true,
        APIname: true,
        createdAt: true,
        updatedAt: true,
      },
      orderBy: {
        createdAt: "desc",
      },
    });

    let activities: {
      id: string;
      APIname: string;
      type: "created" | "updated";
      date: Date;
    }[] = [];

    recentActivities.forEach((api) => {
      activities.push({
        id: api.id,
        APIname: api.APIname ?? "",
        type: "created",
        date: api.createdAt,
      });
      if (api.updatedAt) {
        activities.push({
          id: api.id,
          APIname: api.APIname ?? "",
          type: "updated",
          date: api.updatedAt,
        });
      }
    });
    activities.sort((a, b) => {
      return b.date.getTime() - a.date.getTime();
    });
    res.status(200).json(activities.slice(0, 10));
  } catch (error) {
    console.error("Error fetching recent activities:", error);
  }
}

export async function deleteFinishedAPI(req: Request, res: Response) {
  const { APIId } = req.body;

  try {
    const deletedAPI = await prisma.finishedAPI.delete({
      where: { id: APIId },
    });

    if (!deletedAPI) {
      res.status(404).json("API not found");
    }

    res.status(200).json({ message: "Deleted finished API:", deletedAPI });
  } catch (error) {
    res.status(500).json({ error: "Could not delete finished API" });
  }
}
