// users.controller.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';
import { UsersModule } from './users.module';
import { PrismaService } from '../prisma/prisma.service';
import { AwsS3Service } from '../aws/aws.s3';

describe('UsersController unit test', () => {
  // let app: INestApplication;
  let controller: UsersController;
  let service: UsersService;

  const mockPrismaService = {
    // 여기에 필요한 메서드를 mock 구현
  };

  const mockUsersService = {
    findOne: jest.fn((id: number) => {
      return { userId: id, email: 'test@test.com' };
    }),
  };

  beforeAll(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [UsersController],
      imports: [UsersModule],
      providers: [
        { provide: UsersService, useValue: mockUsersService },
        { provide: PrismaService, useValue: mockPrismaService },
        AwsS3Service,
      ],
    }).compile();

    controller = module.get<UsersController>(UsersController);
    service = module.get<UsersService>(UsersService);
  });

  // jest test
  // it('should be defined', () => {
  //   expect(controller).toBeDefined();
  // });

  describe('Unit Tests', () => {
    // TC01: findOne(id: number) 테스트
    it('TC01: findOne should return a user object', async () => {
      const id = '1';
      expect(await controller.findOne(id)).toEqual({
        userId: 1,
        email: 'test@test.com',
      });
      expect(service.findOne).toHaveBeenCalledWith(id);
    });
  });

  describe('Unit Tests', () => {
    // 3. userId를 통한 유저 조회
    // @Get(':id')
    // @UseGuards(JwtAccessAuthGuard) // passport를 사용하여 인증 확인
    // @ApiBearerAuth() // Swagger 문서에 Bearer 토큰 인증 추가
    // @ApiOperation({ summary: 'ID로 회원 조회' })
    // @ApiResponse({ status: 200, description: '유저 정보 조회 성공' })
    // async findOne(@Param('id') id: string) {
    //   const user = this.usersService.findOne(+id);
    //   if (!user) {
    //     throw new NotFoundException('User does not exist');
    //   }
    //   return user;
    // }
    it('should return a status of 200', () => {
      controller.findOne('1');
      expect(controller.findOne('1')).toBe('1');
    });
  });
});

/* 
  // supertest
  describe('User Signup Tests', () => {
    const validUser = {
      email: 'createUserDto@test.com',
      password: 'password',
      confirmPassword: 'password',
      nickname: 'nicknameDTO',
      intro: 'introDTO',
    };

    // TestCase 01: 회원가입 테스트 - 유효한 CreateUserDto
    it('should create a user if CreateUserDto is valid', async () => {
      await request(app.getHttpServer())
        .post('/users/signup')
        .send(validUser)
        .expect(201);
    });

    // TestCase 02: 회원가입 테스트 - 비밀번호와 비밀번호 확인이 일치하지 않을 때
    it('should not create a user if password and confirmPassword do not match', async () => {
      const invalidUser = { ...validUser, confirmPassword: 'wrongPassword' };
      await request(app.getHttpServer())
        .post('/users/signup')
        .send(invalidUser)
        .expect(400);
    });

    // TestCase 03: 회원가입 테스트 - 이메일 중복 테스트
    it('should not create a user if email is invalid', async () => {
      const invalidUser = { ...validUser, email: 'invalidEmail' };
      await request(app.getHttpServer())
        .post('/users/signup')
        .send(invalidUser)
        .expect(400);
    });

    // TestCase 04: 회원가입 테스트 - 닉네임 중복 테스트
    it('should not create a user if nickname is already taken', async () => {
      const invalidUser = { ...validUser, nickname: 'existingNickname' };
      await request(app.getHttpServer())
        .post('/users/signup')
        .send(invalidUser)
        .expect(400);
    });

    // TestCase 05: 회원가입 테스트 - 회원가입 성공 테스트 create(createUserDto: CreateUserDto)
    it('should successfully create a user', async () => {
      const newUser = {
        email: 'newUser@test.com',
        password: 'newPassword',
        confirmPassword: 'newPassword',
        nickname: 'newNickname',
        intro: 'newIntro',
      };
      await request(app.getHttpServer())
        .post('/users/signup')
        .send(newUser)
        .expect(201);
    });
  });

  describe('User Operations Tests', () => {
    // TestCase 06: 사용자 ID로 사용자 조회 테스트 findOne(id: number)
    it('should find a user by ID', async () => {
      const userId = 1; // 예시 ID
      await request(app.getHttpServer()).get(`/users/${userId}`).expect(200);
    });

    // TestCase 07: 유저 본인 조회 테스트 (users/me) findMe
    it('should find the current user', async () => {
      await request(app.getHttpServer()).get('/users/me').expect(200);
    });

    // TestCase 08: 유저 정보 수정 테스트 update(id: number, updateUserDto: UpdateUserDto)
    it('should update user information', async () => {
      const userId = 1; // 예시 ID
      const updateUserDto = {
        nickname: 'newNickname',
        intro: 'newIntro',
      };
      await request(app.getHttpServer())
        .put(`/users/${userId}`)
        .send(updateUserDto)
        .expect(200);
    });

    // TestCase 09: 회원 탈퇴 테스트 remove(userId: number, password: string)
    it('should remove a user', async () => {
      const userId = 1; // 예시 ID
      const password = 'password'; // 예시 비밀번호
      await request(app.getHttpServer())
        .delete(`/users/${userId}`)
        .send({ password })
        .expect(200);
    });

    // TestCase 10: 사용자가 생성한 모임(Event) 리스트를 조회한다. findHostedEvents(id: number)
    it('should find hosted events by user ID', async () => {
      const userId = 1; // 예시 ID
      await request(app.getHttpServer())
        .get(`/users/${userId}/hosted-events`)
        .expect(200);
    });

    // TestCase 11: 사용자가 참여한 모임(Event) 리스트를 조회한다. findJoinedEvents(id: number)
    it('should find joined events by user ID', async () => {
      const userId = 1; // 예시 ID
      await request(app.getHttpServer())
        .get(`/users/${userId}/joined-events`)
        .expect(200);
    });
  });

  afterAll(async () => {
    await app.close();
  });
*/
