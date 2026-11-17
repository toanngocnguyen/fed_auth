import 'package:bcrypt/bcrypt.dart';
import 'package:fedfer/model.dart';

class User extends FedObject {
  // id: UUIDv7
  String? email;
  bool isEmailVerified;
  String? passwordHash;

  // Profile Information (Mutable)
  String? fullName;
  String? photoUrl; // Nullable if no profile picture
  String? phoneNumber;

  // Security & Metadata
  String? role; // e.g., 'USER', 'ADMIN'
  String? providerId; // e.g., 'google.com', 'apple.com', 'password'
  bool isTwoFactorEnabled;
  late DateTime createdAt;
  late DateTime lastLoginAt;

  // Primary Generative Constructor
  User({
    FedObjectHelper? helper,
    super.id,
    this.email = '',
    this.isEmailVerified = false,
    this.passwordHash = '',
    this.fullName = '',
    this.photoUrl,
    this.phoneNumber = '',
    this.role = 'USER',
    this.providerId = '',
    this.isTwoFactorEnabled = false,
    DateTime? createdAt,
    DateTime? lastLoginAt,
  }) : createdAt = createdAt ?? DateTime.now(),
       lastLoginAt = lastLoginAt ?? DateTime.now(),
       super(helper: helper ?? User.helper);

  static final FedObjectHelper<User> helper = FedObjectHelper.makeHelper(
    createNew: (FedObjectHelper helper) => User(helper: helper),
    tableName: 'fed_user',
  );

  @override
  Future<String?> save({Set<String>? included, Set<String>? excluded}) async {
    // Check email existed
    bool existed = await User.helper.isExistsByField(id, "email", email);

    if (existed){
      throw Exception('email existed, please check it before calling save');
    }

    if (excluded != null && !excluded.contains('email')) excluded.add('email');

    return await super.save(included:included, excluded: excluded);
  }

  // Serialize instance to Map structure for storage in sqflite
  @override
  Map<String, dynamic> toMap({Set<String>? included, Set<String>? excluded}) {
    return {
      if ((included?.contains('id')??true) && !(excluded?.contains('id')??false)) 'id': id,
      if ((included?.contains('email')??true) && !(excluded?.contains('email')??false)) 'email': email,
      if ((included?.contains('is_email_verified')??true) && !(excluded?.contains('is_email_verified')??false)) 'is_email_verified': isEmailVerified ? 1 : 0, // SQLite lacks boolean types
      if ((included?.contains('full_name')??true) && !(excluded?.contains('full_name')??false)) 'full_name': fullName,
      if ((included?.contains('photo_url')??true) && !(excluded?.contains('photo_url')??false)) 'photo_url': photoUrl,
      if ((included?.contains('phone_number')??true) && !(excluded?.contains('phone_number')??false)) 'phone_number': phoneNumber,
      if ((included?.contains('role')??true) && !(excluded?.contains('role')??false)) 'role': role,
      if ((included?.contains('provider_id')??true) && !(excluded?.contains('provider_id')??false)) 'provider_id': providerId,
      if ((included?.contains('is_two_factor_enabled')??true) && !(excluded?.contains('is_two_factor_enabled')??false)) 'is_two_factor_enabled': isTwoFactorEnabled ? 1 : 0,
      if ((included?.contains('created_at')??true) && !(excluded?.contains('created_at')??false)) 'created_at': createdAt.toIso8601String(),
      if ((included?.contains('last_login_at')??true) && !(excluded?.contains('last_login_at')??false)) 'last_login_at': lastLoginAt.toIso8601String(),
    };
  }

  // Factory Constructor to map data retrieved from sqflite
  @override
  loadMap(Map<String, dynamic> map) {
      id = (map['id'] as String?) ?? '';
      email = map['email'] as String;
      isEmailVerified = (map['is_email_verified'] as int) == 1;
      fullName = map['full_name'] as String;
      photoUrl = map['photo_url'] as String?;
      phoneNumber = map['phone_number'] as String;
      role = map['role'] as String;
      providerId = map['provider_id'] as String;
      isTwoFactorEnabled = (map['is_two_factor_enabled'] as int) == 1;
      createdAt = DateTime.parse(map['created_at'] as String);
      lastLoginAt = DateTime.parse(map['last_login_at'] as String);
  }

  // --- Metadata definition ---
  @override
  Future manageModel(Database db, int oldVersion, int newVersion) async {
    // onCreate model
    if (oldVersion == -1) {
      _createTable(db, newVersion);
    }
    // onUpgrade model
    else {}
  }

  Future _createTable(Database db, int version) async {
    bool bExisted = await FedDBManager.isTableExists(
      db,
      objectHelper.tableName,
    );

    if (!bExisted) {
      await db.execute('''
      CREATE TABLE ${objectHelper.tableName} (
        id TEXT PRIMARY KEY NOT NULL, -- Built for UUIDv7 sequential ordering
        email TEXT UNIQUE NOT NULL,
        is_email_verified INTEGER NOT NULL DEFAULT 0, -- 0 for false, 1 for true
        full_name TEXT NOT NULL,
        photo_url TEXT, -- Nullable field
        phone_number TEXT NOT NULL DEFAULT '',
        role TEXT NOT NULL DEFAULT 'USER',
        provider_id TEXT NOT NULL, -- e.g., 'google.com'
        is_two_factor_enabled INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        last_login_at TEXT NOT NULL
      )
      ''');

      // default admin user
      User admin = User(email: 'admin', passwordHash: User.hashPassword('admin'));
      admin.save();
    }
  }

  @override
  String toString() => 'User(id: $id, email: $email, provider: $providerId)';

  static String hashPassword(String? plainTextPassword) {
    return PasswordHasher.hash(plainTextPassword);
  }

  /// Compares an incoming plain-text password against a stored secure hash.
  /// returns true if they match.
  static bool verifyPassword(String? plainTextPassword, String? hashedWithSalt) {
    return PasswordHasher.verify(plainTextPassword, hashedWithSalt);
  }

  /// Method to call whenever the user successfully opens/authenticates the app
  void trackNewLogin() {
    lastLoginAt = DateTime.now();
  }
}

class PasswordHasher {
  /// Hashes a plain-text password using a random salt generated automatically by bcrypt.
  /// The [logRounds] parameter controls the computational cost (higher = more secure but slower).
  static String hash(String? plainTextPassword) {
    if (plainTextPassword == null) return '';
    // 10-12 rounds is standard for modern mobile devices (takes ~100-300ms)
    return BCrypt.hashpw(plainTextPassword, BCrypt.gensalt(logRounds: 10));
  }

  /// Compares an incoming plain-text password against a stored secure hash.
  /// returns true if they match.
  static bool verify(String? plainTextPassword, String? hashedWithSalt) {
    if (plainTextPassword == null && hashedWithSalt == null) return true;
    if (plainTextPassword == null || hashedWithSalt == null) return false;

    return BCrypt.checkpw(plainTextPassword, hashedWithSalt);
  }
}
