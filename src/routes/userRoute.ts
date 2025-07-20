import express from "express";
import {
  getAllUsers,
  createUser,
  loginUser,
  getUserById,
} from "../controllers/userControllers";
import {
  saveFinishedAPI,
  getAllFinishedAPIsByUser,
  updateFinishedAPI,
  deleteFinishedAPI,
  getRecentActivitiesByUser,
} from "../controllers/apiControllers";
import { deleteUser } from "../controllers/adminControllers";


const router = express.Router();

router.get("/", getAllUsers); //getAllUsers
router.get("/:id", getUserById); //getUserbyId
router.post("/register", createUser); //registerUser
router.post("/login", loginUser); //loginUser

router.delete("/:id", deleteUser); //delteUser

// För att spara och uppdatera api-data
router.put("/update-api", updateFinishedAPI);
router.post("/save-api", saveFinishedAPI);
router.post("/finishedapis", getAllFinishedAPIsByUser);
router.post("/delete-api", deleteFinishedAPI);
router.post("/recent-activitiy", getRecentActivitiesByUser);

export default router;
