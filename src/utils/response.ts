import { Response } from "express";

export function Successresponse(message:string, response:Response, data:any = null,code:number) {
    response.status(code).json({
        success: true,
        message: message,
        data
    })
}

export function failureResponse(message: string, response: Response, code: number) {
    response.status(code).json({
        success: false,
        message: message,
    })
}