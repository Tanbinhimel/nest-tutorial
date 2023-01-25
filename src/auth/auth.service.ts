import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';

@Injectable()
export class AuthService {
  constructor(private prismaService: PrismaService) {}

  async singup(dto: AuthDto) {
    const { email, password } = dto;
    const hashPassword = await argon.hash(password);
    return this.prismaService.user.create({
      data: {
        email: email,
        password: hashPassword,
      },
    });
  }

  signin() {
    return 'sign in';
  }
}
