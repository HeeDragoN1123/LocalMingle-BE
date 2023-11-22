import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { UsersService } from 'src/users/users.service';

export class JwtAccessStrategy extends PassportStrategy(Strategy, 'access') {
  constructor(private usersService: UsersService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: process.env.JWT_ACCESS_KEY,
    });
  }

  validate(payload) {
    // console.log('페이로드 확인', payload); // {sub ; 유저id}

    return {
      userId: payload.sub, // id -> userId로 변환 (페이로드에 담긴 유저id를 반환)
    };
  }
}
