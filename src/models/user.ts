import mongoose, { Schema, Document } from "mongoose";

interface IUser extends Document {
  name: string;
  email: string;
  password: string;
  refreshToken?: string;
  banUntil: any;
    failedLoginAttempts: number;
    user?: any;
    _id:any
}

const userSchema:Schema<IUser> = new Schema({
  name: {
    type: String,
    required: [true, "Please enter the name"],
  },
  email: {
    type: String,
    required: [true, "Please enter the email"],
    unique: true,
  },
  password: {
    type: String,
    required: [true, "Please enter the password "],
  },
  refreshToken: {
    type: String,
  },
  banUntil: {
    type: Date,
    default: null,
  },
  failedLoginAttempts: {
    type: Number,
    default: 0,
  },
});

export const User = mongoose.model<IUser>('User', userSchema);