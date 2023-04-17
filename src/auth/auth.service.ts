import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
@Injectable({})
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}
  /**
   * Sign in a user with the given authentication data.
   * @async
   * @param {AuthDto} dto - The authentication data.
   * @throws {ForbiddenException} If the credentials are incorrect.
   * @returns {Promise<string>} A Promise that resolves with a signed token.
   */
  async signin(dto: AuthDto) {
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    if (!user) throw new ForbiddenException('credential incorrect');
    const pwMatches = await argon.verify(user.hash, dto.password);

    if (!pwMatches) throw new ForbiddenException('credential incorrect');

    return this.signToken(user.id, user.email);
  }

  /**
   * Registers a new user with the given authentication data.
   * @param {AuthDto} dto - The authentication data for the user.
   * @returns {Promise<string>} - A promise that resolves to a signed JWT token for the user.
   * @throws {ForbiddenException} - If the user's credentials are already taken.
   * @throws {Error} - If there was an error creating the user.
   */
  async signup(dto: AuthDto) {
    try {
      const hash = await argon.hash(dto.password);
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });
      delete user.hash;
      return this.signToken(user.id, user.email);
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('credentials taken');
        }
      }
      throw error;
    }
  }

  /**
   * Signs a JSON Web Token (JWT) with the given user ID and email.
   * @param userId The ID of the user.
   * @param email The email of the user.
   * @returns An object with an access token string.
   */
  async signToken(
    userId: number,
    email: string,
  ): Promise<{ access_token: string }> {
    const payload = { sub: userId, email };
    const expiresIn = '15m';
    const secret = this.config.get('JWT_SECRET');
    const options = { expiresIn, secret };
    const access_token = await this.jwt.signAsync(payload, options);
    return { access_token };
  }
}
