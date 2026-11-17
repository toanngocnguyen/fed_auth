import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'google_auth_service.dart';
import 'facebook_auth_service.dart';

import 'user.dart';

enum AuthStatus { unknown, authenticated, unauthenticated }

class Authentication {

  static final Authentication _instance = Authentication.createNew();

  factory Authentication(){
    return _instance;
  }

  Authentication.createNew();

  final AuthStorageService _sessionStorage = AuthStorageService();
  final GoogleAuthService _googleAuthService = GoogleAuthService();
  final FacebookAuthService _facebookAuthService = FacebookAuthService();

  AuthStatus _status = AuthStatus.unknown;
  User? _currentUser; // Holds active profile in memory

  AuthStatus get status => _status;
  User? get currentUser => _currentUser;

  // Initialize Session on App Boot
  Future<void> initializeSession() async {
    final userId = await _sessionStorage.getActiveUserId();
    if (userId != null) {
      _status = AuthStatus.authenticated;
    } else {
      _status = AuthStatus.unauthenticated;
    }
  }

  bool get isLogined => _status == AuthStatus.authenticated;

  /// THE LOCAL LOGIN METHOD: Authenticates via local DB hashes
  Future<bool> loginWithPassword({required String email, required String password}) async {
    // try {
      final rawUserMap = await User.gHelper.fetchByField('email', email);
      if (rawUserMap == null) return false; // Email not found locally

      final storedHash = rawUserMap['password_hash'] as String?;

      print('password_hash: $storedHash');

      final isMatch = User.verifyPassword(password, storedHash);
      if (!isMatch) return false;

      _currentUser = User.gHelper.fromMap(rawUserMap);

      // Connect to AuthStorageService to lock session across app relaunches
      // Generate a temporary mock local session token or UUIDv7 for security
      await _sessionStorage.saveSession(
        token: 'local_secure_session_${_currentUser!.id}',
        userId: _currentUser!.id!,
      );

      _status = AuthStatus.authenticated;
      return true;
    // } catch (e) {
    //   print('Local login execution failure: $e');
    //   return false;
    // }
  }

  /// THE GOOGLE JWT LOGIN METHOD
  Future<bool> loginWithGoogle() async {
    // 1. Fetch and decode JWT from Google
    final jwtClaims = await _googleAuthService.authenticateWithGoogle();
    if (jwtClaims == null) return false;

    final String email = jwtClaims['email'] as String;
    final String displayName = jwtClaims['name'] as String? ?? 'Google User';
    final String? photoUrl = jwtClaims['picture'] as String?;
    final String rawJwt = jwtClaims['raw_jwt_token'] as String;

    // 2. Check if this Google user already exists in your local sqflite DB
    var localUserMap = await User.gHelper.fetchByField('email', email);

    late User user;

    if (localUserMap == null) {
      // User is completely new: Initialize a new model using UUIDv7
      user = User(
        email: email,
        fullName: displayName,
        photoUrl: photoUrl,
        providerId: 'google.com',
        isEmailVerified: true,
      );

      // Save the newly minted Google Profile into sqflite
      // (Assuming you have an insertUser method in your dbService)
      await User.gHelper.insert(user);
    } else {
      // User exists: Re-instantiate from your sqflite cache
      user = User.gHelper.fromMap(localUserMap);
      user.trackNewLogin(); // Update lastLoginAt timestamp
      await User.gHelper.update(user);
    }

    _currentUser = user;

    // 3. Save the session token (the Google JWT) into FlutterSecureStorage
    await _sessionStorage.saveSession(
      token: rawJwt, // Caches the secure Google JWT across reloads
      userId: _currentUser!.id!,
    );

    // 4. Update state
    _status = AuthStatus.authenticated;
    return true;
  }

  /// THE FACEBOOK AUTH INGESTION LOOP
  Future<bool> loginWithFacebook() async {
    // 1. Execute login sheet operations
    final profileData = await _facebookAuthService.authenticateWithFacebook();
    if (profileData == null) return false;

    final String email = profileData['email'] as String;
    final String displayName = profileData['name'] as String;
    final String? photoUrl = profileData['picture'] as String?;
    final String rawToken = profileData['raw_token'] as String;

    // 2. Query sqflite user data structures
    var localUserMap = await User.gHelper.fetchByField('email', email);
    late User user;

    if (localUserMap == null) {
      // User is completely new: Initialize a new model using UUIDv7
      user = User(
        email: email,
        fullName: displayName,
        photoUrl: photoUrl,
        providerId: 'facebook.com',
        isEmailVerified: true,
      );

      // Save the newly minted Google Profile into sqflite
      // (Assuming you have an insertUser method in your dbService)
      await User.gHelper.insert(user);
    } else {
      // User exists: Re-instantiate from your sqflite cache
      user = User.gHelper.fromMap(localUserMap);
      user.trackNewLogin(); // Update lastLoginAt timestamp
      await User.gHelper.update(user);
    }

    _currentUser = user;

    // 3. Persist Facebook authentication payload string inside secure system memory
    await _sessionStorage.saveSession(
      token: rawToken,
      userId: _currentUser!.id!,
    );

    // 4. Update state
    _status = AuthStatus.authenticated;

    return true;
  }

  // Logout Flow
  Future<void> logout() async {
    await _sessionStorage.clearSession();
    _currentUser = null;
    _status = AuthStatus.unauthenticated;
  }
}

class AuthStorageService {
  final _secureStorage = const FlutterSecureStorage();

  static const _keyToken = 'auth_session_token';
  static const _keyUserId = 'auth_user_id';

  /// Save authentication session details upon successful login
  Future<void> saveSession({required String token, required String userId}) async {
    await _secureStorage.write(key: _keyToken, value: token);
    await _secureStorage.write(key: _keyUserId, value: userId);
  }

  /// Read the user ID to check if an active session exists
  Future<String?> getActiveUserId() async {
    return await _secureStorage.read(key: _keyUserId);
  }

  /// Read the active session token
  Future<String?> getSessionToken() async {
    return await _secureStorage.read(key: _keyToken);
  }

  /// Clear everything when the user logs out
  Future<void> clearSession() async {
    await _secureStorage.delete(key: _keyToken);
    await _secureStorage.delete(key: _keyUserId);
  }
}








