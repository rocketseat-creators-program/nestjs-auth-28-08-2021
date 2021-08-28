<img src="https://storage.googleapis.com/golden-wind/experts-club/capa-github.svg" />

# NestJS: autenticação e autorização JWT

Apesar de comum em toda aplicação, para muitas pessoas implementar a autenticação e autorização utilizando o JWT ainda é um assunto complicado.

Mesmo que o NestJS ofereça um boilerplate para essa implementação direto na documentação, ainda faltam algumas peças do quebra-cabeça que você precisa resolver.

Chegou a hora de encaixar todas essas pecinhas e oferece uma solução completinha de autenticação e autorização, usando o Token JWT e implementando no NestJS com as bibliotecas `passport` e derivadas.

## Expert

| [<img src="https://avatars.githubusercontent.com/u/7906171?v=4" width="75px;"/>](https://github.com/paulosalvatore) |
| :-: |
|[Paulo Salvatore](https://github.com/paulosalvatore)|

# NestJS - Autenticação e Autorização com JWT

## Tópicos

[TOC]

## Prisma

### Instalar o prisma

```bash
npm install prisma -D
```

### Inicializar o prisma

```bash
npx prisma init
```

### `prisma/schema.prisma`

```java
datasource db {
  provider = "mysql"
  url      = env("DATABASE_URL")
}

generator client {
  provider        = "prisma-client-js"
}

model User {
  id Int @id @default(autoincrement())

  email    String  @unique
  password String?

  name      String?
}

```

## Arquivo .env

```bash
# Configuration

JWT_SECRET=""

# Database

DATABASE_URL=""

```

### Arquivo .env preenchido

```bash
# Configuration

JWT_SECRET="aksdo23joi5j234otb32o4itvb4813uc34hvt13839"

# Database

DATABASE_URL="mysql://root@localhost:3306/nestjs_auth"
```

## Migrar o banco

```bash
npx prisma migrate dev --name init
```

Esse comando deverá instalar a dependência `@prisma/client` no projeto.

### Criação do módulo do prisma

#### Comandos na CLI para criação dos arquivos

```bash
nest g module prisma
nest g service prisma
```

#### Conteúdo dos arquivos

##### `src/prima/prisma.module.ts`

```typescript
import { Global, Module } from "@nestjs/common";
import { PrismaService } from "./prisma.service";

@Global()
@Module({
    providers: [PrismaService],
    exports: [PrismaService]
})
export class PrismaModule {
}

```

##### `src/prisma/prisma.service.ts`

```typescript
import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService
  extends PrismaClient
  implements OnModuleInit, OnModuleDestroy
{
  async onModuleInit() {
    await this.$connect();
  }

  async onModuleDestroy() {
    await this.$disconnect();
  }
}
```

## Dependências

- `@nestjs/passport`
- `@nestjs/jwt`
- `bcrypt`
- `class-validator`
- `class-transformer`
- `passport`
- `passport-jwt`
- `passport-local`

Atalho para instalar tudo ao mesmo tempo:

```bash
npm i @nestjs/passport @nestjs/jwt bcrypt class-validator class-transformer passport passport-jwt passport-local
```

## Dev Dependências

- `@types/passport-jwt`
- `@types/passport-local`
- `@types/bcrypt`

```bash
npm i -D @types/passport-jwt @types/passport-local @types/bcrypt
```

## Códigos

### Domain/Autorização: diretório `user`

#### Comandos na CLI para criação dos arquivos

```bash
nest g resource user
```

#### `user/user.entity.ts`

```typescript
import { Prisma } from '@prisma/client';

export class User implements Prisma.UserUncheckedCreateInput {
  id?: number;
  email: string;
  password: string;
  name: string;
}
```

#### `user/create-user.dto.ts`

```typescript
import { IsEmail, IsNotEmpty, IsString } from 'class-validator';
import { User } from '../entities/user.entity';

export class CreateUserDto extends User {
  @IsNotEmpty()
  @IsEmail()
  email: string;

  @IsString()
  password: string;

  @IsString()
  name: string;
}
```

#### `user/user.controller.ts`

```typescript
import { Body, Controller, Post } from '@nestjs/common';
import { UserService } from './user.service';
import { CreateUserDto } from './dto/create-user.dto';
import { User } from './entities/user.entity';

@Controller('users')
export class UserController {
  constructor(private userService: UserService) {}

  @Post()
  async create(@Body() createUserDto: CreateUserDto) {
    return this.userService.create(createUserDto);
  }
}
```

#### `user/user.service.ts`

```typescript
import { Injectable } from '@nestjs/common';

// Prisma
import { PrismaService } from '../../prisma/prisma.service';
import { Prisma, Role } from '@prisma/client';

// Models
import { CreateUserDto } from './dto/create-user.dto';
import { User } from './entities/user.entity';

// Errors
import { ForbiddenError } from '../../errors/forbidden.error';

// Bcrypt
import * as bcrypt from 'bcrypt';

@Injectable()
export class UserService {
    constructor(private readonly prisma: PrismaService) {}

    public async create(createUserDto: CreateUserDto): Promise<User> {
        const data: Prisma.UserCreateInput = {
            ...createUserDto,
            password: await bcrypt.hash(createUserDto.password, 10),
        };

        const createdUser = await this.prisma.user
        .create({ data });

        return {
            ...createdUser,
            password: undefined,
        };
    }

    findById(id: number) {
        return this.prisma.user.findUnique({ where: { id } });
    }

    findByEmail(email: string) {
        return this.prisma.user.findUnique({ where: { email } });
    }
}
```

### `user/user.module.ts`

```typescript
import { Module } from '@nestjs/common';
import { UserController } from './user.controller';
import { UserService } from './user.service';

@Module({
  controllers: [UserController],
  providers: [UserService],
  exports: [UserService],
})
export class UserModule {}

```

### Autenticação: diretório `auth`

```
nest g module auth
nest g controller auth
nest g service auth
```

#### `auth/auth.module.ts`

```typescript
import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { UserModule } from '../user/user.module';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { JwtStrategy } from './jwt.strategy';

@Module({
  imports: [
    UserModule,
    PassportModule,
    JwtModule.register({
      secret: process.env.JWT_SECRET,
      signOptions: { expiresIn: '30d' },
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy],
})
export class AuthModule {}
```

#### `auth/auth.controller.ts`

```typescript
import { Body, Controller, HttpCode, HttpStatus, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginRequestBody } from './model/LoginRequestBody';
import { Public } from './public.decorator';

@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  login(@Body() { email, password }: LoginRequestBody) {
    return this.authService.login(email, password);
  }
}
```

#### `auth/auth.service.ts`

```typescript
import { Injectable } from '@nestjs/common';
import { User } from '../user/entities/user.entity';
import { UserPayload } from './model/UserPayload';
import { JwtService } from '@nestjs/jwt';
import { UserService } from '../user/user.service';

import * as bcrypt from 'bcrypt';
import { UnauthorizedError } from '../errors/UnauthorizedError';
import { UserToken } from './model/UserToken';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly userService: UserService,
  ) {}

  async login(email: string, password: string): Promise<UserToken> {
    const user: User = await this.validateUser(email, password);

    const payload: UserPayload = {
      username: user.email,
      sub: user.id,
    };

    return {
      accessToken: this.jwtService.sign(payload),
    };
  }

  private async validateUser(email: string, password: string) {
    const user = await this.userService.findByEmail(email);

    if (user) {
      const isPasswordValid = await bcrypt.compare(password, user.password);

      if (isPasswordValid) {
        return { ...user, password: undefined };
      }
    }

    throw new UnauthorizedError(
      `Email address or password provided is incorrect.`,
    );
  }
}
```

#### `auth/jwt.strategy.ts`

```typescript
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { UserFromJwt } from './model/UserFromJwt';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
    constructor() {
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            ignoreExpiration: false,
            secretOrKey: process.env.JWT_SECRET,
        });
    }

    async validate(payload: UserPayload): Promise<UserFromJwt> {
        return { id: payload.sub, email: payload.username };
    }
}
```

#### `auth/jwt-auth.guard.ts`

```typescript
// NestJS
import { ExecutionContext, Inject, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';

// Password
import { AuthGuard } from '@nestjs/passport';

// RxJs
import { of } from 'rxjs';
import { map, mergeMap, takeWhile, tap } from 'rxjs/operators';

// Services
import { UserService } from '../user/user.service';

// Models
import { UserFromJwt } from './model/UserFromJwt';
import { AuthRequest } from '../model/AuthRequest';

// Decorators
import { IS_PUBLIC_KEY } from './public.decorator';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(
    private reflector: Reflector,
    @Inject(UserService) private readonly userService: UserService,
  ) {
    super();
  }

  canActivate(context: ExecutionContext) {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic) {
      return true;
    }

    const canActivate = super.canActivate(context);

    if (typeof canActivate === 'boolean') {
      return canActivate;
    }

    return of(canActivate).pipe(
      mergeMap((value) => value),
      takeWhile((value) => value),
      map(() => context.switchToHttp().getRequest<AuthRequest>()),
      mergeMap((request) =>
        of(request).pipe(
          map((req) => {
            if (!req.user) {
              throw Error('User was not found in request.');
            }

            return req.user;
          }),
          mergeMap((userFromJwt: UserFromJwt) =>
            this.userService.findById(userFromJwt.id),
          ),
          tap((user) => {
            request.principal = user;
          }),
        ),
      ),
      map((user) => Boolean(user)),
    );
  }
}
```

#### Importanto tudo no AppModule

```typescript
import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { PrismaModule } from './prisma/prisma.module';
import { UserModule } from './user/user.module';
import { AuthModule } from './auth/auth.module';
import { APP_GUARD } from '@nestjs/core';
import { JwtAuthGuard } from './auth/jwt-auth.guard';

@Module({
  imports: [
    // Authentication
    UserModule,
    AuthModule,
  ],
  controllers: [AppController],
  providers: [
    {
      provide: APP_GUARD,
      useClass: JwtAuthGuard,
    },
  ],
})
export class AppModule {}
```

#### Diretório `auth/model`

##### `auth/model/UserFromJwt.ts`

```typescript
import { User } from '@prisma/client';

export type UserFromJwt = Partial<User>;
```

##### `auth/model/UserPayload.ts`

```typescript
export interface UserPayload {
    username: string;
    sub: number;
}
```

##### `auth/model/UserToken.ts`

```typescript
export interface UserToken {
    accessToken: string;
}
```

##### `auth/model/AuthRequest.ts`

```typescript
import { Request } from 'express';
import { User } from '../../domain/user/entities/user.entity';

export interface AuthRequest extends Request {
    principal: User;
}
```

##### `auth/model/LoginRequestBody.ts`

```typescript
import {
  IsEmail,
  IsString,
  Matches,
  MaxLength,
  MinLength,
} from 'class-validator';

export class LoginRequestBody {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(4)
  @MaxLength(20)
  @Matches(/((?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/, {
    message: 'password too weak',
  })
  password: string;
}
```

### Decorators

#### `auth/public.decorator.ts`

```typescript
import { SetMetadata } from '@nestjs/common';

export const IS_PUBLIC_KEY = 'isPublic';
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);
```

#### `auth/auth-user.decorator.ts`

```typescript
import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { User } from '@prisma/client';
import { AuthRequest } from '../../auth/model/AuthRequest';

export const AuthUser = createParamDecorator(
  (data: keyof User, context: ExecutionContext) => {
    const request = context.switchToHttp().getRequest<AuthRequest>();

    const user: User = request.body;

    return data ? user && user[data] : user;
  },
);
```

### Tratamento de erros: diretório `errors`

#### `src/errors/unauthorized.error.ts`

```typescript
export class UnauthorizedError extends Error {}
```

### Tratamento de erros: diretório `interpcetor`

#### `src/interceptors/unauthorized.interceptor.ts`

```typescript
import {
  CallHandler,
  ExecutionContext,
  Injectable,
  NestInterceptor,
  UnauthorizedException,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { UnauthorizedError } from '../errors/UnauthorizedError';

@Injectable()
export class UnauthorizedInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      catchError((error) => {
        if (error instanceof UnauthorizedError) {
          throw new UnauthorizedException(error.message);
        } else {
          throw error;
        }
      }),
    );
  }
}
```

### Ativando validação e interceptor no `main.ts`

```typescript
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { UnauthorizedInterceptor } from './interceptors/UnauthorizedInterceptor';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Pipes
  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
      whitelist: true,
      forbidNonWhitelisted: true,
    }),
  );

  // Interceptors
  app.useGlobalInterceptors(new UnauthorizedInterceptor());

  await app.listen(3000);
}

bootstrap();
```



## Requisições

```json
Endpoint: /login
Method: POST

Request Body:
{
	"email": "paulo@salvatore.tech",
	"password": "Abcd1234@"
}

Response Body (200):
{
    "accessToken": "JWT_TOKEN_HERE"
}
```

```json
Endpoint: /user
Method: POST

Request Body:
{
	"email": "paulo@salvatore.tech",
	"password": "Abcd1234@",
    "name": "Paulo Salvatore"
}

Response Body (201):
{
    "id": 1,
	"email": "paulo@salvatore.tech",
    "name": "Paulo Salvatore"
}
```

