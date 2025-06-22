import { Body, Controller, HttpCode, HttpStatus, ParseIntPipe, Post, } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { AuthDto } from "src/auth/dto";

@Controller('auth')
export class AuthController {

    constructor(private authservice: AuthService) { }


    @Post('login')
    login(@Body() dto: AuthDto) {
        console.log(
            {
                dto
            }
        );
        return this.authservice.login(dto);
    }

    @HttpCode(HttpStatus.OK)
    @Post('signup')
    signup(@Body() dto: AuthDto) {
                console.log(
            {
                dto
            }
        );
        return this.authservice.signup(dto);
    }
}