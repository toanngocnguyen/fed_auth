import 'package:flutter_facebook_auth/flutter_facebook_auth.dart';
import 'package:jwt_decoder/jwt_decoder.dart';

class FacebookAuthService {
  Future<Map<String, dynamic>?> authenticateWithFacebook() async {
    try {
      final LoginResult result = await FacebookAuth.instance.login(
        permissions: ['public_profile', 'email'],
      );

      if (result.status != LoginStatus.success) {
        print('Meta Login Failed: ${result.message}');
        return null;
      }

      final AccessToken accessToken = result.accessToken!;

      // Use the enum type check rather than the class 'is' check
      if (accessToken.type == AccessTokenType.limited) {
        // iOS Limited Login yields a native OIDC valid JWT string directly
        final String jwtString = accessToken.tokenString;
        Map<String, dynamic> claims = JwtDecoder.decode(jwtString);
        claims['raw_token'] = jwtString;
        return claims;
      }

      // Classic Login Workflow (Android, Web, or iOS with ATT enabled)
      final Map<String, dynamic> userData = await FacebookAuth.instance.getUserData(
        fields: "name,email,picture.width(200)",
      );

      return {
        'email': userData['email'] ?? '${userData['id']}@facebook.com',
        'name': userData['name'] ?? 'Facebook User',
        'picture': userData['picture']?['data']?['url'],
        'raw_token': accessToken.tokenString,
      };
    } catch (e) {
      print('Facebook Authentication Fault: $e');
      return null;
    }
  }
}
