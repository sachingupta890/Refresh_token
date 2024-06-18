import express from "express";
const router = express.Router();

import userRoute from "./user.js"
import protectedRoute from "./protected.js"
import adminRoutes from "./superAdmin.js"
import localAdminRoutes from "./localAdmin.js"
import auth from "../middleware/verifyJwt.js"
import { refreshAcessToken } from "../controllers/user.js";



router.use("/user", userRoute);
router.use("/protected",auth, protectedRoute)

router.post("/refresh-token", refreshAcessToken)
router.use("/admin",auth, adminRoutes);
router.use("/local",auth,localAdminRoutes)

export default router;