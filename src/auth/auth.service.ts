import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';

@Injectable()
export class AuthService {
  constructor(private prismaService: PrismaService) {}

  async singup(dto: AuthDto) {
    const { email, password } = dto;
    const hashPassword = await argon.hash(password);
    try {
      const user = await this.prismaService.user.create({
        data: {
          email: email,
          password: hashPassword,
        },
      });
      delete user.password;
      return user;
    } catch (e) {
      if (e instanceof PrismaClientKnownRequestError && e.code === 'P2002') {
        throw new ForbiddenException('Credentials taken!');
      }
      throw e;
    }
  }

  async signin(dto) {
    const user = await this.prismaService.user.findFirst({
      where: {
        email: dto.email,
      },
    });

    if (!user) {
      throw new ForbiddenException('Credentials incorrect!');
    }

    const isPasswordMatched = await argon.verify(user.password, dto.password);

    if (!isPasswordMatched) {
      throw new ForbiddenException('Credentials incorrect!');
    }
    delete user.password;
    delete user.createdAt;
    delete user.updatedAt;
    return user;
  }
}
