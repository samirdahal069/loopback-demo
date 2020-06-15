import {UserService} from '@loopback/authentication';
import {inject} from '@loopback/context';
import {repository} from '@loopback/repository';
import {HttpErrors} from '@loopback/rest';
import {securityId, UserProfile} from '@loopback/security';
import {PasswordHasherBindings} from '../keys';
import {User} from '../models/user.model';
import {Credentials, UserRepository} from '../repositories/user.repository';
import {PasswordHasher} from './hash.password.bcryptjs';

export class MyUserService implements UserService<User, Credentials> {
  constructor(
    @repository(UserRepository) public userRepository: UserRepository,
    @inject(PasswordHasherBindings.PASSWORD_HASHER)
    public passwordHasher: PasswordHasher,
  ) {}

  async verifyCredentials(credentials: Credentials): Promise<User> {
    const foundUser = await this.userRepository.findOne({
      where: {email: credentials.email},
    });

    if (!foundUser) {
      throw new HttpErrors.NotFound(
        `User with email ${credentials.email} not found.`,
      );
    }
    const passwordMatched = await this.passwordHasher.comparePassword(
      credentials.password,
      foundUser.password,
    );

    if (!passwordMatched) {
      throw new HttpErrors.Unauthorized('The credentials are not correct.');
    }

    return foundUser;
  }

  convertToUserProfile(user: User): UserProfile {
    let userName = user.fullname;
    const userProfile = {
      [securityId]: user.id,
      name: userName,
      id: user.id,
      roles: user.roles,
    };
    return userProfile;
  }
}
