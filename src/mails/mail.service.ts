import { HttpException, HttpStatus, Injectable, Logger } from '@nestjs/common';
import { Request } from 'express';
import * as nodemailer from 'nodemailer';

@Injectable()
export class MailService {
  private transporter;
  private verificationCodes = new Map<
    number,
    { code: number; expires: number }
  >(); // 인증 번호 및 만료 시간 관리
  private readonly logger = new Logger(MailService.name);

  constructor() {
    this.transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 587,
      secure: false,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });
  }

  generateRandomNumber = (min, max) => {
    return Math.floor(Math.random() * (max - min + 1)) + min;
  };

  async sendMail(to: string, subject: string, req: Request) {
    try {
      const startTime = new Date(); // 메일 전송 시작 시간 기록
      const email = req.body.to;
      // console.log('이메일 확인 샌드 메일:', email);

      const verificationCode = this.generateRandomNumber(10000, 99999); // 5자리 랜덤 인증 번호 생성
      // console.log('인증 번호 확인 샌드 메일:', verificationCode);

      // 인증 번호와 유효 기간을 저장
      const expires = Date.now() + 5 * 60 * 1000; // 5분 후 만료
      this.verificationCodes.set(verificationCode, {
        code: verificationCode,
        expires,
      });

      // 쿠키 설정
      req.res.cookie('verificationCode', verificationCode.toString(), {
        expires: new Date(expires),
      });

      await this.transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: '"local-mingle 인증메일입니다."',
        text: `
        인증 번호: ${verificationCode} 
        만료기간: ${new Date(expires)}`,
      });

      const endTime = new Date(); // 메일 전송 종료 시간 기록
      const elapsedTime = endTime.getTime() - startTime.getTime(); // 전송에 걸린 시간 계산

      // Log success with elapsed time
      this.logger.log(
        `Verification email sent successfully to: ${email}. Elapsed Time: ${elapsedTime}ms`
      );
    } catch (error) {
      throw new HttpException(
        '메일 전송 중 오류가 발생했습니다',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  // 인증번호 검증
  verifyVerificationCode(code: number): boolean {
    const storedCode = this.verificationCodes.get(code);

    if (storedCode && storedCode.expires >= Date.now()) {
      this.verificationCodes.delete(code);
      return true;
    }
    return false;
  }
}
