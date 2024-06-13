import express, { Request,Response } from "express";
import auth from "../middleware/auth.js"
const router = express.Router();

router.post('/', auth, (req:Request, res:Response) => {
    res.send("Welcome to the procted route ")
})

export default router;