import express from "express";
import { login, logout, register } from "../controllers/user.js";
import auth from "../middleware/auth.js"

const router = express.Router();

router.post('/register', register);
router.post('/login', login)
router.post('/logout',auth,logout)

export default router;