import { ForbiddenException, Injectable } from "@nestjs/common";
import { AuthDto } from "src/auth/dto";
import { PrismaService } from "src/prisma/prisma.service";
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";

@Injectable()
export class AuthService {

     constructor(
          private prisma: PrismaService,
          private jwt: JwtService,
          private config: ConfigService
     ) { }

     async login(dto: AuthDto) {

          const user = await this.prisma.user.findUnique({
               where: {
                    email: dto.email,
               },
          })

          if (!user) throw new ForbiddenException('Credentials incorrect');

          const pwMatches = await argon.verify(user.hash, dto.password)

          if (!pwMatches) throw new ForbiddenException('Credentials incorrect')

          return this.signToken(user.id, user.email);
     }

     async signup(dto: AuthDto) {
          const hashed = await argon.hash(dto.password)

          try {
               const user = await this.prisma.user.create({
                    data: {
                         email: dto.email,
                         hash: hashed,
                    },
               })

               return this.signToken(user.id, user.email)

          } catch (error) {
               if (error instanceof PrismaClientKnownRequestError) {
                    if (error.code === 'P2002') {
                         throw new ForbiddenException('Credentials taken');
                    }
               }
               throw error;
          }
     }

     async signToken(
          userId: number,
          email: string,
     ): Promise<{access_token: string}> {
          const payload = {
               sub: userId,
               email: email,
          }

          const secret = this.config.get('JWT_SECRET');

          const token = await this.jwt.signAsync(
               payload,
               {
               expiresIn: '15m',
               secret: secret
          }
          );

          return {
               access_token: token
          };

     }
}