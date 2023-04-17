import { Body, Controller, HttpCode, HttpStatus, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  /**
   * Signup a new user by calling the `signup` method of the `authService`.
   *
   * @param dto - The authentication DTO containing user's credentials.
   * @returns A promise that resolves to the result of the `signup` method.
   */
  signup(@Body() dto: AuthDto) {
    return this.authService.signup(dto);
  }

  @HttpCode(HttpStatus.OK)
  @Post('signin')
  /**
   * Authenticates a user by signing them in using the provided authentication DTO.
   *
   * @param dto - The authentication DTO containing the user's credentials.
   * @returns A Promise that resolves to the result of the sign in operation.
   */
  signin(@Body() dto: AuthDto) {
    return this.authService.signin(dto);
  }
}
