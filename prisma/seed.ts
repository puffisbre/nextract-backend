import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

async function main() {
  // Seed Admin
  const admin = await prisma.admin.create({
    data: {
      email: "admin@example.com",
      password: "securepassword",
    },
  });

  // Seed Users
  const user = await prisma.user.create({
    data: {
      id: "user-id-1",
      email: "user@example.com",
      password: "userpassword",
      adminId: admin.id,
    },
  });

  // Seed Additional Users
  const user2 = await prisma.user.create({
    data: {
      id: "user-id-2",
      email: "user2@example.com",
      password: "user2password",
      adminId: admin.id,
    },
  });

  const user3 = await prisma.user.create({
    data: {
      id: "user-id-3",
      email: "user3@example.com",
      password: "user3password",
      adminId: admin.id,
    },
  });

  // Seed OriginalApi
  const originalApi = await prisma.originalApi.create({
    data: {
      apiUrl: "https://api.example.com",
      apiKey: "apikey123",
      userId: user.id,
    },
  });

  // Seed Additional OriginalApis
  const originalApi2 = await prisma.originalApi.create({
    data: {
      apiUrl: "https://api2.example.com",
      apiKey: "apikey456",
      userId: user2.id,
    },
  });

  const originalApi3 = await prisma.originalApi.create({
    data: {
      apiUrl: "https://api3.example.com",
      apiKey: "apikey789",
      userId: user3.id,
    },
  });

  // Seed RestoredAPI
  const restoredApi = await prisma.restoredAPI.create({
    data: {
      adminId: admin.id,
      originalApi: {
        connect: { id: originalApi.id },
      },
    },
  });

  // Seed Additional RestoredAPIs
  const restoredApi2 = await prisma.restoredAPI.create({
    data: {
      adminId: admin.id,
      originalApi: {
        connect: { id: originalApi2.id },
      },
    },
  });

  const restoredApi3 = await prisma.restoredAPI.create({
    data: {
      adminId: admin.id,
      originalApi: {
        connect: { id: originalApi3.id },
      },
    },
  });

  // Update OriginalApi with restoredAPIid
  await prisma.originalApi.update({
    where: { id: originalApi.id },
    data: { restoredAPIid: restoredApi.id },
  });

  // Update Additional OriginalApis with restoredAPIid
  await prisma.originalApi.update({
    where: { id: originalApi2.id },
    data: { restoredAPIid: restoredApi2.id },
  });

  await prisma.originalApi.update({
    where: { id: originalApi3.id },
    data: { restoredAPIid: restoredApi3.id },
  });

  // Seed FinishedAPI
  await prisma.finishedAPI.create({
    data: {
      items: JSON.stringify([{ name: "Item1" }, { name: "Item2" }]),
      userId: user.id,
    },
  });

  // Seed Additional FinishedAPIs
  await prisma.finishedAPI.create({
    data: {
      items: JSON.stringify([{ name: "Item3" }, { name: "Item4" }]),
      userId: user2.id,
    },
  });

  await prisma.finishedAPI.create({
    data: {
      items: JSON.stringify([{ name: "Item5" }, { name: "Item6" }]),
      userId: user3.id,
    },
  });
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
