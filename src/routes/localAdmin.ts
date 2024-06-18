import express from "express";
import localAdmin from "../middleware/localAdmin.js"
const router = express.Router();

router.get('/getAll',(req, res) => {
    res.send("All Users fetched successfully ");
})


export default router;

