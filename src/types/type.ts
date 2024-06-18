
export interface NewSignInRequestBody{
    name: string;
    email: string;
  password: string;
  role:string
}
export interface NewlogInRequestBody {
  name: string;
  email: string;
  password: string;
}

export type JwtPayload  = {
  userId: string,
  email: string;
  role: string;
}
export type JwtRefreshPayload = {
    userId: string;
}

