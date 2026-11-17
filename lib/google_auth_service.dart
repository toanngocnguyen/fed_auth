import 'package:google_sign_in/google_sign_in.dart';
import 'package:jwt_decoder/jwt_decoder.dart';

class GoogleAuthService {
  final GoogleSignIn _googleSignIn = GoogleSignIn.instance;

  /// Triggers the native Google Auth UI and returns the decoded JWT payload
  Future<Map<String, dynamic>?> authenticateWithGoogle() async {
    try {
      // 1. Prompt system UI credentials sheet (Returns an Account)
      final GoogleSignInAccount googleAccount = await _googleSignIn.authenticate();

      // 2. Extract tokens synchronously from the account instance (No 'await' required!)
      final GoogleSignInAuthentication googleAuth = googleAccount.authentication;

      // 3. Extract the ID Token JWT string
      final String? idToken = googleAuth.idToken;

      if (idToken == null) {
        throw Exception('Failed to retrieve Google Identity JWT IdToken.');
      }

      // 4. Decode the JWT to read user profile information safely
      // (If you have a backend server, pass this raw idToken to your server via API instead)
      if (JwtDecoder.isExpired(idToken)) {
        throw Exception('Google Identity JWT token has expired.');
      }

      Map<String, dynamic> decodedToken = JwtDecoder.decode(idToken);

      // Return both the raw token (for session caching) and decoded info
      decodedToken['raw_jwt_token'] = idToken;
      return decodedToken;
    } catch (e) {
      print('Google Sign-In Execution Error: $e');
      return null;
    }
  }

  /// Handles sign out from the Google Client
  Future<void> signOut() async {
    await _googleSignIn.signOut();
  }
}
