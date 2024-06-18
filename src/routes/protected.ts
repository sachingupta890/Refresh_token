import express, { Request,Response } from "express";
import auth from "../middleware/auth.js"
const router = express.Router();

router.get('/', (req:Request, res:Response) => {
    res.send("Welcome to the procted route for valid user")
})

export default router;