import mongoose, { Schema, Document } from "mongoose";

interface IUser extends Document {
  name: string;
  email: string;
  password: string;
  refreshToken?: string;
    user?: any;
  _id: any;
  role:string
}

const userModel:Schema<IUser> = new Schema({
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
  role: {
    type: String,
    enum: ['user', 'localadmin', 'superadmin'],
    default:'user'
    
  }

});

export const User = mongoose.model<IUser>('User', userModel);