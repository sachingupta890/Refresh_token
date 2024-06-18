import jwt from "jsonwebtoken";
import { NextFunction, Request, Response } from "express";
import { failureResponse } from "../utils/response.js";
import config from "../config/config.js";
import { User } from "../models/user.js";
import { JwtPayload } from "../types/type.js";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

// Get __dirname equivalent in ES module
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const permissionsPath = path.resolve(__dirname, "../config/permission.json");

// Read and parse permissions
const permissionsRaw = fs.readFileSync(permissionsPath, "utf-8");
const permissions: Record<string, string[]> = JSON.parse(permissionsRaw);



const verifyJWT = async (
  req: any,
  res: Response,
  next: NextFunction
) => {
  try {
    const token =
      req.cookies?.accessToken ||
      req.header("Authorization")?.replace("Bearer ", "");

    if (!token) {
      return failureResponse("Token is missing", res, 401);
    }

    let decoded: JwtPayload;
    try {
      decoded = jwt.verify(token, config.access_secret) as JwtPayload;
    } catch (err: any) {
      if (err.name === "TokenExpiredError") {
        return failureResponse("Access token expired", res, 401);
      } else if (err.name === "JsonWebTokenError") {
        return failureResponse("Invalid token", res, 401);
      } else {
        throw err;
      }
    }

    const user = await User.findById(decoded.userId).select(
      "-password -refreshToken"
    );

    if (!user) {
      return failureResponse("Invalid access token", res, 401);
    }

    // Extract the current route
    const urlSegments = req.originalUrl
      .split("/")
      .filter((segment:any) => segment !== "");
      const currentRoute = `/${urlSegments[urlSegments.length - 1]}`;
      
      console.log("current route is ",currentRoute)

    // Check permissions
    if (
      permissions[currentRoute] &&
      permissions[currentRoute].includes(user.role) && (permissions[currentRoute].includes('auth') && user.role)
    ) {
      req.user = user;
      next();
    } else {
      return failureResponse("Unauthorized", res, 403);
    }
  } catch (err: any) {
    console.error("Error in verifyJWT middleware:", err);
    return res.status(500).json({
      success: false,
      message: "Something went wrong in verifying token",
      error: err.message,
    }); 
  }
};

export default verifyJWT;
