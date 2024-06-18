import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { Request, Response } from "express";
import {
  JwtPayload,
  JwtRefreshPayload,
  NewSignInRequestBody,
  NewlogInRequestBody,
} from "../types/type.js";
import { Successresponse, failureResponse } from "../utils/response.js";
import { User } from "../models/user.js";
import config from "../config/config.js";

export const register = async (
  req: Request<{}, {}, NewSignInRequestBody>,
  res: Response
) => {
  try {
    //fetchig data from req body
    const { name, email, password ,role} = req.body;
    //checking data
    if (!name || !email || !password ) {
      return failureResponse("Please fill all the fields", res, 401);
    }

    //check if user already exists
    const user = await User.findOne({ email });
    if (user) {
      return failureResponse("User Already Exist", res, 401);
    }

    //hash the password
    const hashedPassword = await bcrypt.hash(password, 10);
    //save the entry in db
    const result = await User.create({ name, email, password: hashedPassword,role });

    return Successresponse("User registered Succesfully ", res, result, 201);
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      message: "Internal Server error in registering",
      err,
    });
  }
};

export const login = async (
  req: Request<{}, {}, NewlogInRequestBody>,
  res: Response
) => {
  try {
    //fetching data from body
    const { email, password } = req.body;
    if (!email || !password) {
      return failureResponse("Please fill all the fields", res, 401);
    }

    //check if user registered or not
    const user = await User.findOne({ email });

    if (!user) {
      return failureResponse("Please do registration first", res, 401);
    }
   

    //check password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return failureResponse(
        "Please enter valid passwoerd",
        res,
        403
      );
    }

    //generate token
    const payload: JwtPayload = {
      userId: user._id.toString(),
      email: user.email,
      role: user.role,
    };
    const accessToken = jwt.sign(payload, config.access_secret, {
      expiresIn: config.accessExpiry,
    });

    const refreshPayload: JwtRefreshPayload = { userId: user._id.toString() };
    const refreshToken = jwt.sign(refreshPayload, config.refresh_secret, {
      expiresIn: config.refreshExpiry,
    });

    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });

    const loggedInUser = await User.findById(user._id).select(
      "-password -refreshToken"
    );

    const option = {
      httpOnly: true,
      secure: true,
    };

    return res
      .status(200)
      .cookie("accessToken", accessToken, option)
      .cookie("refreshToken", refreshToken, option)
      .json({
        sucess: true,
        message: "user logged In succesfully",
        user: loggedInUser,
        accessToken,
        refreshToken,
      });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      message: "Internal Server error in login",
      err,
    });
  }
};

export const logout = async (req: any, res: Response) => {
  try {
    const { _id } = req.user;

    await User.findByIdAndUpdate(
      _id,
      {
        $set: {
          refreshToken: undefined,
        },
      },
      {
        new: true,
      }
    );

    const option = {
      httpOnly: true,
      secure: true,
    };

    return res
      .status(200)
      .clearCookie("accessToken", option)
      .clearCookie("refreshToken", option)
      .json({
        success: true,
        message: "logged out successfully",
      });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      message: "Internal Server error in login",
      err,
    });
  }
};

export const refreshAcessToken = async (req: any, res: Response) => {
  try {
    const alreadyInRefreshToken =
      req.cookies.refreshToken || req.body.refreshToken;

    if (!alreadyInRefreshToken) {
      return failureResponse("unauthorized request", res, 401);
    }

    const decodedToken: any = jwt.verify(
      alreadyInRefreshToken,
      config.refresh_secret
    );

    const user = await User.findById(decodedToken?.userId);

    if (!user) {
      return failureResponse("Invalid refresh token", res, 401);
    }

    if (alreadyInRefreshToken !== user.refreshToken) {
      return failureResponse("Refresh token is expired or used", res, 401);
    }

    //generate tokens again
    const payload: JwtPayload = {
      userId: user._id.toString(),
      email: user.email,
      role:user.role,
    };
    const accessToken = jwt.sign(payload, config.access_secret, {
      expiresIn: config.accessExpiry,
    });

    const refreshPayload: JwtRefreshPayload = {
      userId: user._id.toString(),
    };
    const newRefreshToken = jwt.sign(refreshPayload, config.refresh_secret, {
      expiresIn: config.refreshExpiry,
    });

    user.refreshToken = newRefreshToken;

    const option = {
      httpOnly: true,
      secure: true,
    };

    await user.save({ validateBeforeSave: false });

    return res
      .status(200)
      .cookie("accessToken", accessToken, option)
      .cookie("refreshToken", newRefreshToken, option)
      .json({
        success: true,
        message: "Acess and refresh token regenrated",
        user,
        accessToken,
        refreshToken: newRefreshToken,
      });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      mesaage: "Internal server error in refreshing access token",
      err,
    });
  }
};
