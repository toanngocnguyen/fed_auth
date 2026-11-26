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
    FedModelHelper? model,
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
       super(model: model ?? User.modelHelper);

  static final FedModelHelper<User> modelHelper =
      FedModelHelper.makeModelHelper(
        createNew: (FedModelHelper storage) => User(model: storage),
        tableName: 'fed_user',
      );

  @override
  Future<String?> save({Set<String>? included, Set<String>? excluded}) async {
    // Check email existed
    bool existed = await User.modelHelper.isExistsByField(id, "email", email);

    if (existed) {
      throw Exception('email existed, please check it before calling save');
    }

    if (excluded != null && !excluded.contains('email')) excluded.add('email');

    return await super.save(included: included, excluded: excluded);
  }

  // Serialize instance to Map structure for storage in sqflite
  @override
  Map<String, dynamic> toMap({Set<String>? included, Set<String>? excluded}) {
    return {
      if (model.incExc('id', included, excluded)) 'id': id,
      if (model.incExc('email', included, excluded)) 'email': email,
      if (model.incExc('isEmailVerified', included, excluded))
        'is_email_verified': isEmailVerified
            ? 1
            : 0, // SQLite lacks boolean types
      // if (myHelper.incExc('passwordHash', included, excluded)) 'password_hash': email,
      if (model.incExc('fullName', included, excluded)) 'full_name': fullName,
      if (model.incExc('photoUrl', included, excluded)) 'photo_url': photoUrl,
      if (model.incExc('phoneNumber', included, excluded))
        'phone_number': phoneNumber,
      if (model.incExc('role', included, excluded)) 'role': role,
      if (model.incExc('providerId', included, excluded))
        'provider_id': providerId,
      if (model.incExc('isTwoFactorEnabled', included, excluded))
        'is_two_factor_enabled': isTwoFactorEnabled ? 1 : 0,
      if (model.incExc('createdAt', included, excluded))
        'created_at': createdAt.toIso8601String(),
      if (model.incExc('lastLoginAt', included, excluded))
        'last_login_at': lastLoginAt.toIso8601String(),
    };
  }

  // Factory Constructor to map data retrieved from sqflite
  @override
  loadMap(Map<String, dynamic> map) {
    id = (map['id'] as String?) ?? '';
    email = map['email'] as String?;
    passwordHash = map['password_hash'] as String?;
    isEmailVerified = (map['is_email_verified'] as int) == 1;
    fullName = map['full_name'] as String?;
    photoUrl = map['photo_url'] as String?;
    phoneNumber = map['phone_number'] as String?;
    role = map['role'] as String?;
    providerId = map['provider_id'] as String?;
    isTwoFactorEnabled = (map['is_two_factor_enabled'] as int) == 1;
    createdAt = DateTime.parse((map['created_at'] as String?) ?? '1900-01-01');
    lastLoginAt = DateTime.parse(
      (map['last_login_at'] as String?) ?? '1900-01-01',
    );
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
    bool bExisted = await FedDBManager.isTableExists(db, model.tableName);

    if (!bExisted) {
      await db.execute('''
      CREATE TABLE ${model.tableName} (
        id TEXT PRIMARY KEY NOT NULL, -- Built for UUIDv7 sequential ordering
        email TEXT UNIQUE NULL,
        is_email_verified INTEGER NOT NULL DEFAULT 0, -- 0 for false, 1 for true
        password_hash TEXT NULL,
        full_name TEXT NULL,
        photo_url TEXT,
        phone_number TEXT NULL DEFAULT '',
        role TEXT NULL DEFAULT 'USER',
        provider_id TEXT NULL, -- e.g., 'google.com'
        is_two_factor_enabled INTEGER NULL DEFAULT 0,
        created_at TEXT NULL,
        last_login_at TEXT NULL
      )
      ''');

      // default admin user
      User admin = User(email: 'admin');
      await admin.save();
      await admin.setPassword('admin369');
    }
  }

  @override
  String toString() => 'User(id: $id, email: $email, provider: $providerId)';

  Future<int> setPassword(String password) async {
    Database db = await model.getDatabase();

    String passwordHash = User.hashPassword(password);

    return await db.update(
      model.tableName,
      {"password_hash": passwordHash},
      where: 'id = ?',
      whereArgs: [id],
    );
  }

  static String hashPassword(String? plainTextPassword) {
    return PasswordHasher.hash(plainTextPassword);
  }

  /// Compares an incoming plain-text password against a stored secure hash.
  /// returns true if they match.
  static bool verifyPassword(
    String? plainTextPassword,
    String? hashedWithSalt,
  ) {
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
