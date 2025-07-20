//Main route importera all routes hit, exporta till index.ts. För att skydda alla routes. 
import express from "express";
import userRoutes from "./userRoute"
import productsRoutes from "./productsRoute"
import publishRoutes from "./publishRoute"
import settingsRoutes from "./settingsRoute"
import uploadRoutes from "./uploadRoute"
import supportRoute from "./supportRoute"
import chatRoute from "./chatRoute"

const router = express.Router();

router.use("/users", userRoutes)
router.use("/products", productsRoutes)
router.use("/publish", publishRoutes)
router.use("/settings", settingsRoutes)
router.use("/upload", uploadRoutes)
router.use("/support", supportRoute)
router.use("/chat", chatRoute)



export default router;
