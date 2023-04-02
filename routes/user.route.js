import { Router } from "express";
import { getAllUser, getUserById } from "../controllers/user.controller";
import { verifyToken } from "../middleware/authJWT";

const router = Router();

router.get("/users/:id",verifyToken, getUserById)
router.get("/users",verifyToken, getAllUser)

export default router;