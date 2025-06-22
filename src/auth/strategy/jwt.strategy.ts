import { Injectable, UnauthorizedException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import { PrismaService } from "../../prisma/prisma.service";

@Injectable()
export class JwtStrategy extends PassportStrategy(
    Strategy,
    'jwt',
) {
    constructor(
        config: ConfigService,
        private prisma: PrismaService,
        ) {
        const secret = config.get<string>('JWT_SECRET');
        if (!secret) {
            throw new Error('JWT_SECRET não está definido no .env');
        }

        super({
            jwtFromRequest:
                ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: secret,
        });
    }

        async validate(payload: {
            sub: number;
            email: string;
        }) {

        const user = await this.prisma.user.findUnique({
           where: {
             id: payload.sub
           }
        })

        if (!user) {
            throw new UnauthorizedException('Usuário não encontrado no banco de dados');
        }

        const {hash, ...safeUser} = user
        return safeUser
        
    }
}