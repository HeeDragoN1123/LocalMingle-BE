import {
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from './../prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { UsersService } from 'src/users/users.service';
import { IAuthServiceLogin } from './interface/auth-service.interface';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private prisma: PrismaService,
    private jwtService: JwtService
  ) {}

  async login({ email, password, res }: IAuthServiceLogin): Promise<{
    accessToken: string;
    refreshToken: string;
    userId: number;
  }> {
    // 1. 이메일이 일치하는 유저를 DB에서 찾기
    const user = await this.usersService.findByEmail({ email });

    // 2. 일치하는 유저가 없으면 에러
    if (!user) throw new NotFoundException('이메일이 없습니다.');

    // 2-1. 사용자가 삭제되지 않았는지 확인 (deletedAt가 null이어야 함)
    if (user.deletedAt !== null) {
      throw new UnauthorizedException('사용자가 삭제되었습니다.');
    }

    // 3. 일치하는 유저는 있지만 비밀번호가 틀렸다면 에러
    const isAuth = await bcrypt.compare(password, user.password);
    if (!isAuth)
      throw new UnauthorizedException('비밀번호가 일치하지 않습니다.');

    // 4. 리프레시 토큰 생성
    const refreshToken = this.setRefreshToken({ user });
    const accessToken = this.getAccessToken({ user });

    // 5. 액세스 토큰 및 리프레시 토큰을 반환
    res.header('accessToken', accessToken);
    res.header('refreshToken', refreshToken);

    // 6. DB에 리프레시 토큰을 저장한다.
    await this.prisma.user.update({
      where: { userId: user.userId },
      data: {
        refreshToken: refreshToken,
      },
    });

    return { accessToken, refreshToken, userId: user.userId };
  }

  getAccessToken({ user }): string {
    const accessToken = this.jwtService.sign(
      { sub: user.userId },
      { secret: process.env.JWT_ACCESS_KEY, expiresIn: '2h' }
    );

    return accessToken;
  }

  setRefreshToken({ user }): string {
    // 리프레시 토큰을 생성하는 로직을 구현
    const refreshToken = this.jwtService.sign(
      { sub: user.userId },
      { secret: process.env.JWT_REFRESH_KEY, expiresIn: '2w' }
    );
    return refreshToken;
  }

  refreshAccessToken(refreshToken: string): string {
    // 리프레시 토큰의 유효성을 검증
    const decodedToken = this.jwtService.verify(refreshToken, {
      secret: process.env.JWT_REFRESH_KEY,
    });

    // 리프레시 토큰이 유효하다면 새로운 액세스 토큰을 발급
    const userId = decodedToken.sub;

    const newAccessToken = this.getAccessToken({
      user: { userId },
    });
    return newAccessToken;
  }

  async OAuthLogin({ req, res }): Promise<{
    accessToken: string;
    refreshToken: string;
  }> {
    // 1. 회원조회
    let user = await this.usersService.findByEmail({ email: req.user.email });

    //2. 사용자가 없으면 회원가입
    if (!user) {
      // 아이디 생성 관련 코드 추가
      const createUser = {
        email: req.user.email, // 사용자의 이메일을 사용하여 아이디 생성
        nickname: req.user.nickname, //닉네임 익명 닉네임 생성 로직
        password: req.user.password, // 비밀번호를 해싱하여 저장
        confirmPassword: req.user.password, // 비밀번호를 해싱하여 저장
        intro: req.user.intro,
        profileImg: req.user.profileImg,
      };
      user = await this.usersService.create(createUser);
    }

    // 2-1. 사용자가 삭제되지 않았는지 확인 (deletedAt가 null이어야 함)
    if (user.deletedAt !== null) {
      throw new UnauthorizedException('사용자가 삭제되었습니다.');
    }

    // 3. 회원가입이 되어 있다면? 로그인(AT, RT를 생성해서 브라우저에 전송)한다
    const accessToken = this.getAccessToken({ user });
    const refreshToken = this.setRefreshToken({ user });
    // 4. 로그인이 되면 DB에 리프레시 토큰을 저장한다.
    await this.prisma.user.update({
      where: { userId: user.userId },
      data: {
        refreshToken: refreshToken,
      },
    });

    // console.log('로컬 엑세스 토큰', accessToken);
    // console.log('로컬 리프레시 토큰', refreshToken);
    // 리다이렉션
    res.redirect(
      `${process.env.CLIENT_URL}?accessToken=${encodeURIComponent(
        accessToken
      )}&refreshToken=${encodeURIComponent(
        refreshToken
      )}&userId=${encodeURIComponent(user.userId)}`
    );
    return { accessToken, refreshToken };
  }
}
