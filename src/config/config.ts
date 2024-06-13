import dotenv from "dotenv";

dotenv.config();

const config = {
  port: process.env.PORT as string,
  uri: process.env.MONGO_URI as string,
  access_secret: process.env.JWT_Access_secret as string,
  refresh_secret: process.env.JWT_refresh_secret as string,
  dbname: process.env.DBNAME as string,
  accessExpiry: process.env.ACCESS_TOKEN_EXPIRY as string,
  refreshExpiry: process.env.REFRESH_TOKEN_EXPIRY as string,
  maxLoginAttempts: parseInt(process.env.Login_Attempt_Limit as string, 10),
  bannedTime: parseInt(process.env.BAN_TIME as string, 10),
};

export default config;