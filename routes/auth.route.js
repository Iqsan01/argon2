import { Router } from "express";
import { loginUser, logout, register } from "../controllers/auth.controller.js";

const router = Router();

router.post("/register",register)
router.post("/login",loginUser)
router.post("/logout",logout)
export default router;