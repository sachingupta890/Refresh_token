import express from "express";
import adminOnly from "../middleware/adminOnly.js"
const router = express.Router();


router.delete('/delete', (req, res) => {
    res.send("user deleted successfully");
})

router.put('/update', (req, res) => {
    res.send("user updated successfully")
})


export default router;