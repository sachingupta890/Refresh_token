import express from "express";
const router = express.Router();

import userRoute from "./user.js"
import protectedRoute from "./protected.js"
import { refreshAcessToken } from "../controllers/user.js";



router.use("/user", userRoute);
router.use("/protected", protectedRoute)

router.post("/refresh-token",refreshAcessToken)

export default router;