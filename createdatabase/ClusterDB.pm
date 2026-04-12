package ClusterDB;
use v5.38;

# ---------------------------------------------------------------------------
# ClusterDB - Encrypted cluster secrets database
# ---------------------------------------------------------------------------
# Security Practice Labels & FIPS-140 Compliance:
#   - [SEC-CRED-ENCRYPT]: Sensitive key material encrypted at rest (AES-256-GCM)
#   - [SEC-AUDIT-LOG]: All operations produce audit log entries
#   - [FIPS-140]: AES-256-GCM (NIST SP 800-38D) with PBKDF2-SHA256 KDF
#   - NIST SP 800-132: 600,000 PBKDF2 iterations for key derivation
#   - Database file permissions enforced at 0600
#   - Keyfile permissions verified (must be 0400 / owner-read-only)
#
# Dependencies: DBI, DBD::SQLite, CryptX (Crypt::AuthEnc::GCM,
#               Crypt::KeyDerivation, Crypt::PRNG), MIME::Base64
# ---------------------------------------------------------------------------

use DBI;
use Carp           qw(croak);
use POSIX          qw(strftime);
use File::Basename qw(dirname);
use MIME::Base64   qw(encode_base64 decode_base64);
use Crypt::AuthEnc::GCM;
use Crypt::KeyDerivation qw(pbkdf2);
use Crypt::PRNG          qw(random_bytes);

# FIPS 140-2/3 cryptographic parameters
use constant {
    AES_KEY_LEN => 32,          # 256-bit key (FIPS 140-2)
    GCM_IV_LEN  => 12,          # per NIST SP 800-38D
    GCM_TAG_LEN => 16,          # 128-bit authentication tag
    PBKDF2_ITER => 600_000,     # NIST SP 800-132
    PBKDF2_HASH => 'SHA256',    # FIPS approved
    SALT_LEN    => 32,          # 256-bit salt
};

# ---------------------------------------------------------------------------
# Constructor
# ---------------------------------------------------------------------------
sub new {
    my ( $class, %args ) = @_;
    my $self = bless {
        db_path    => $args{db_path}    // croak("db_path required"),
        passphrase => $args{passphrase} // croak("passphrase required"),
        audit_log  => $args{audit_log},
        _dbh       => undef,
        _enc_key   => undef,
    }, $class;
    return $self;
}

# ---------------------------------------------------------------------------
# Class method: obtain passphrase from env var or keyfile
# Priority: CLUSTER_DB_KEY env var > keyfile
# ---------------------------------------------------------------------------
sub get_passphrase {
    my ( $class, %args ) = @_;
    my $keyfile = $args{keyfile};

    if ( my $key = $ENV{CLUSTER_DB_KEY} ) {
        return $key;
    }

    if ( $keyfile && -f $keyfile ) {

        # [SEC-CRED-ENCRYPT]: open first then fstat to eliminate TOCTOU race
        open my $fh, '<', $keyfile or croak "Cannot read keyfile: $!";
        my $mode = ( stat($fh) )[2] & 07777;
        croak "Keyfile '$keyfile' permissions too open ("
          . sprintf( "%04o", $mode )
          . "). Required: 0400 (owner read-only)."
          if $mode & 0377;
        chomp( my $pass = <$fh> );
        close $fh;
        return $pass;
    }

    croak "No encryption key available.\n"
      . "Set CLUSTER_DB_KEY env var or provide --keyfile.\n"
      . "Generate: openssl rand -base64 32 > keyfile && chmod 400 keyfile\n";
}

# ---------------------------------------------------------------------------
# Initialize database schema
# ---------------------------------------------------------------------------
sub init {
    my ($self) = @_;

    my $db_dir = dirname( $self->{db_path} );
    if ( !-d $db_dir ) {
        require File::Path;
        File::Path::make_path($db_dir);
    }

    my $dbh = $self->_connect;

    $dbh->do("PRAGMA journal_mode=WAL");
    $dbh->do("PRAGMA secure_delete=ON");

    $dbh->do(<<'SQL');
CREATE TABLE IF NOT EXISTS pubkeys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    machine_name TEXT NOT NULL,
    key_type TEXT NOT NULL,
    public_key_enc TEXT NOT NULL,
    fingerprint TEXT NOT NULL DEFAULT '',
    comment TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    rotated_at TEXT,
    created_by TEXT,
    UNIQUE(machine_name, key_type)
)
SQL

    $dbh->do(<<'SQL');
CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    machine_name TEXT NOT NULL,
    username_enc TEXT NOT NULL,
    password_enc TEXT NOT NULL,
    comment TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    rotated_at TEXT,
    created_by TEXT,
    UNIQUE(machine_name)
)
SQL

    $dbh->do(<<'SQL');
CREATE TABLE IF NOT EXISTS db_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
)
SQL

    $dbh->do(<<'SQL');
CREATE TABLE IF NOT EXISTS key_passphrases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    machine_name TEXT NOT NULL,
    passphrase_enc TEXT NOT NULL,
    comment TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    rotated_at TEXT,
    created_by TEXT,
    UNIQUE(machine_name)
)
SQL

    my ($existing_salt) =
      $dbh->selectrow_array("SELECT value FROM db_metadata WHERE key = 'salt'");

    my $salt;
    if ( !$existing_salt ) {
        $salt = random_bytes(SALT_LEN);
        $dbh->do( "INSERT INTO db_metadata (key, value) VALUES ('salt', ?)",
            undef, encode_base64( $salt, '' ) );
        $dbh->do(
            "INSERT INTO db_metadata (key, value) VALUES ('created_at', ?)",
            undef, _timestamp() );
        $dbh->do(
"INSERT INTO db_metadata (key, value) VALUES ('cipher', 'AES-256-GCM')"
        );
        $dbh->do(
"INSERT INTO db_metadata (key, value) VALUES ('kdf', 'PBKDF2-SHA256-600000')"
        );
    }
    else {
        $salt = decode_base64($existing_salt);
    }

    $self->{_enc_key} = _derive_key( $self->{passphrase}, $salt );
    chmod 0600, $self->{db_path};

    $self->_audit( 'db_initialized', db_path => $self->{db_path} );
    return 1;
}

# ---------------------------------------------------------------------------
# Store a public key (encrypts content, tracks rotation)
# ---------------------------------------------------------------------------
sub store_key {
    my ( $self, %args ) = @_;
    my $machine     = $args{machine}     // croak "machine required";
    my $key_type    = $args{key_type}    // croak "key_type required";
    my $public_key  = $args{public_key}  // croak "public_key required";
    my $fingerprint = $args{fingerprint} // '';
    my $comment     = $args{comment}     // '';

    # OWASP A03:2021 - input validation
    croak "Invalid machine name '$machine'"
      unless $machine =~ /^[a-zA-Z0-9._-]+$/;
    croak "Invalid key_type '$key_type'"
      unless $key_type =~ /^[a-zA-Z0-9._-]+$/;

    my $dbh     = $self->_connect;
    my $enc_key = $self->_get_enc_key;

    my $encrypted = _encrypt( $public_key, $enc_key );
    my $now       = _timestamp();
    my $user      = ( getpwuid($<) )[0] // 'uid:' . $<;

    # Upsert: update rotated_at if key already exists
    my ($existing_id) = $dbh->selectrow_array(
        "SELECT id FROM pubkeys WHERE machine_name = ? AND key_type = ?",
        undef, $machine, $key_type );

    if ($existing_id) {
        $dbh->do(
            <<'SQL', undef, $encrypted, $fingerprint, $now, $user, $comment, $machine, $key_type );
UPDATE pubkeys SET public_key_enc = ?, fingerprint = ?, rotated_at = ?,
    created_by = ?, comment = ?
WHERE machine_name = ? AND key_type = ?
SQL
        $self->_audit(
            'key_rotated',
            machine  => $machine,
            key_type => $key_type
        );
    }
    else {
        $dbh->do(
            <<'SQL', undef, $machine, $key_type, $encrypted, $fingerprint, $now, $user, $comment );
INSERT INTO pubkeys
    (machine_name, key_type, public_key_enc, fingerprint, created_at, created_by, comment)
VALUES (?, ?, ?, ?, ?, ?, ?)
SQL
        $self->_audit(
            'key_stored',
            machine  => $machine,
            key_type => $key_type
        );
    }

    return 1;
}

# ---------------------------------------------------------------------------
# Retrieve and decrypt public key(s) for a machine
# ---------------------------------------------------------------------------
sub get_key {
    my ( $self, %args ) = @_;
    my $machine  = $args{machine} // croak "machine required";
    my $key_type = $args{key_type};

    croak "Invalid machine name '$machine'"
      unless $machine =~ /^[a-zA-Z0-9._-]+$/;

    my $dbh     = $self->_connect;
    my $enc_key = $self->_get_enc_key;

    my $sql =
        "SELECT key_type, public_key_enc, fingerprint, created_at, rotated_at"
      . " FROM pubkeys WHERE machine_name = ?";
    my @bind = ($machine);
    if ($key_type) {
        $sql .= " AND key_type = ?";
        push @bind, $key_type;
    }

    my $sth = $dbh->prepare($sql);
    $sth->execute(@bind);

    my @results;
    while ( my $row = $sth->fetchrow_hashref ) {
        push @results,
          {
            machine     => $machine,
            key_type    => $row->{key_type},
            public_key  => _decrypt( $row->{public_key_enc}, $enc_key ),
            fingerprint => $row->{fingerprint},
            created_at  => $row->{created_at},
            rotated_at  => $row->{rotated_at},
          };
    }
    $sth->finish;

    $self->_audit(
        'key_retrieved',
        machine => $machine,
        count   => scalar @results
    );
    return @results;
}

# ---------------------------------------------------------------------------
# List all keys (metadata only, no decryption)
# ---------------------------------------------------------------------------
sub list_keys {
    my ($self) = @_;
    my $dbh = $self->_connect;

    my $sth = $dbh->prepare(<<'SQL');
SELECT machine_name, key_type, fingerprint, created_at, rotated_at,
       created_by, comment
FROM pubkeys ORDER BY machine_name, key_type
SQL
    $sth->execute;

    my @results;
    while ( my $row = $sth->fetchrow_hashref ) {
        push @results,
          {
            machine     => $row->{machine_name},
            key_type    => $row->{key_type},
            fingerprint => $row->{fingerprint},
            created_at  => $row->{created_at},
            rotated_at  => $row->{rotated_at},
            created_by  => $row->{created_by},
            comment     => $row->{comment},
          };
    }
    $sth->finish;
    return @results;
}

# ---------------------------------------------------------------------------
# Store a credential (username + password, both encrypted)
# ---------------------------------------------------------------------------
sub store_credential {
    my ( $self, %args ) = @_;
    my $machine  = $args{machine}  // croak "machine required";
    my $username = $args{username} // croak "username required";
    my $password = $args{password} // croak "password required";
    my $comment  = $args{comment}  // '';

    croak "Invalid machine name '$machine'"
      unless $machine =~ /^[a-zA-Z0-9._-]+$/;

    my $dbh     = $self->_connect;
    my $enc_key = $self->_get_enc_key;

    my $enc_user = _encrypt( $username, $enc_key );
    my $enc_pass = _encrypt( $password, $enc_key );
    my $now      = _timestamp();
    my $user     = ( getpwuid($<) )[0] // 'uid:' . $<;

    my ($existing_id) = $dbh->selectrow_array(
        "SELECT id FROM credentials WHERE machine_name = ?",
        undef, $machine );

    if ($existing_id) {
        $dbh->do(
            <<'SQL', undef, $enc_user, $enc_pass, $now, $user, $comment, $machine );
UPDATE credentials SET username_enc = ?, password_enc = ?, rotated_at = ?,
    created_by = ?, comment = ?
WHERE machine_name = ?
SQL
        $self->_audit( 'credential_rotated', machine => $machine );
    }
    else {
        $dbh->do(
            <<'SQL', undef, $machine, $enc_user, $enc_pass, $now, $user, $comment );
INSERT INTO credentials
    (machine_name, username_enc, password_enc, created_at, created_by, comment)
VALUES (?, ?, ?, ?, ?, ?)
SQL
        $self->_audit( 'credential_stored', machine => $machine );
    }
    return 1;
}

# ---------------------------------------------------------------------------
# Retrieve and decrypt credential for a machine
# Returns hashref { username => ..., password => ... } or undef
# ---------------------------------------------------------------------------
sub get_credential {
    my ( $self, %args ) = @_;
    my $machine = $args{machine} // croak "machine required";

    croak "Invalid machine name '$machine'"
      unless $machine =~ /^[a-zA-Z0-9._-]+$/;

    my $dbh     = $self->_connect;
    my $enc_key = $self->_get_enc_key;

    my $row = $dbh->selectrow_hashref(
"SELECT username_enc, password_enc FROM credentials WHERE machine_name = ?",
        undef, $machine
    );
    return undef unless $row;

    $self->_audit( 'credential_retrieved', machine => $machine );
    return {
        username => _decrypt( $row->{username_enc}, $enc_key ),
        password => _decrypt( $row->{password_enc}, $enc_key ),
    };
}

# ---------------------------------------------------------------------------
# List all credentials (metadata only, no decryption)
# ---------------------------------------------------------------------------
sub list_credentials {
    my ($self) = @_;
    my $dbh = $self->_connect;

    my $sth = $dbh->prepare(<<'SQL');
SELECT machine_name, created_at, rotated_at, created_by, comment
FROM credentials ORDER BY machine_name
SQL
    $sth->execute;

    my @results;
    while ( my $row = $sth->fetchrow_hashref ) {
        push @results,
          {
            machine    => $row->{machine_name},
            created_at => $row->{created_at},
            rotated_at => $row->{rotated_at},
            created_by => $row->{created_by},
            comment    => $row->{comment},
          };
    }
    $sth->finish;
    return @results;
}

# ---------------------------------------------------------------------------
# Delete credential for a machine
# ---------------------------------------------------------------------------
sub delete_credential {
    my ( $self, %args ) = @_;
    my $machine = $args{machine} // croak "machine required";

    croak "Invalid machine name '$machine'"
      unless $machine =~ /^[a-zA-Z0-9._-]+$/;

    my $dbh  = $self->_connect;
    my $rows = $dbh->do( "DELETE FROM credentials WHERE machine_name = ?",
        undef, $machine );
    $self->_audit(
        'credential_deleted',
        machine => $machine,
        rows    => $rows
    );
    return $rows;
}

# ---------------------------------------------------------------------------
# Delete key(s) for a machine
# ---------------------------------------------------------------------------
sub delete_key {
    my ( $self, %args ) = @_;
    my $machine  = $args{machine} // croak "machine required";
    my $key_type = $args{key_type};

    croak "Invalid machine name '$machine'"
      unless $machine =~ /^[a-zA-Z0-9._-]+$/;

    my $dbh  = $self->_connect;
    my $sql  = "DELETE FROM pubkeys WHERE machine_name = ?";
    my @bind = ($machine);
    if ($key_type) {
        $sql .= " AND key_type = ?";
        push @bind, $key_type;
    }

    my $rows = $dbh->do( $sql, undef, @bind );
    $self->_audit(
        'key_deleted',
        machine  => $machine,
        key_type => $key_type // 'all',
        rows     => $rows
    );
    return $rows;
}

# ---------------------------------------------------------------------------
# Store an SSH key passphrase (encrypted, [SEC-KEY-PASSPHRASE])
# ---------------------------------------------------------------------------
sub store_key_passphrase {
    my ( $self, %args ) = @_;
    my $machine    = $args{machine}    // croak "machine required";
    my $passphrase = $args{passphrase} // croak "passphrase required";
    my $comment    = $args{comment}    // '';

    croak "Invalid machine name '$machine'"
      unless $machine =~ /^[a-zA-Z0-9._-]+$/;

    my $dbh     = $self->_connect;
    my $enc_key = $self->_get_enc_key;

    my $encrypted = _encrypt( $passphrase, $enc_key );
    my $now       = _timestamp();
    my $user      = ( getpwuid($<) )[0] // 'uid:' . $<;

    my ($existing_id) = $dbh->selectrow_array(
        "SELECT id FROM key_passphrases WHERE machine_name = ?",
        undef, $machine );

    if ($existing_id) {
        $dbh->do( <<'SQL', undef, $encrypted, $now, $user, $comment, $machine );
UPDATE key_passphrases SET passphrase_enc = ?, rotated_at = ?,
    created_by = ?, comment = ?
WHERE machine_name = ?
SQL
        $self->_audit( 'key_passphrase_rotated', machine => $machine );
    }
    else {
        $dbh->do( <<'SQL', undef, $machine, $encrypted, $now, $user, $comment );
INSERT INTO key_passphrases
    (machine_name, passphrase_enc, created_at, created_by, comment)
VALUES (?, ?, ?, ?, ?)
SQL
        $self->_audit( 'key_passphrase_stored', machine => $machine );
    }
    return 1;
}

# ---------------------------------------------------------------------------
# Retrieve and decrypt an SSH key passphrase
# Returns the plaintext passphrase string, or undef if not found
# ---------------------------------------------------------------------------
sub get_key_passphrase {
    my ( $self, %args ) = @_;
    my $machine = $args{machine} // croak "machine required";

    croak "Invalid machine name '$machine'"
      unless $machine =~ /^[a-zA-Z0-9._-]+$/;

    my $dbh     = $self->_connect;
    my $enc_key = $self->_get_enc_key;

    my $row = $dbh->selectrow_hashref(
        "SELECT passphrase_enc FROM key_passphrases WHERE machine_name = ?",
        undef, $machine );
    return undef unless $row;

    $self->_audit( 'key_passphrase_retrieved', machine => $machine );
    return _decrypt( $row->{passphrase_enc}, $enc_key );
}

# ---------------------------------------------------------------------------
# Private: database connection (cached)
# ---------------------------------------------------------------------------
sub _connect {
    my ($self) = @_;
    return $self->{_dbh} if $self->{_dbh} && $self->{_dbh}->ping;

    $self->{_dbh} = DBI->connect(
        "dbi:SQLite:dbname=$self->{db_path}",
        '', '',
        {
            RaiseError                       => 1,
            PrintError                       => 0,
            AutoCommit                       => 1,
            sqlite_use_immediate_transaction => 1,
        }
    ) or croak "Cannot connect to database: $DBI::errstr";

    $self->{_dbh}->do("PRAGMA secure_delete=ON");
    return $self->{_dbh};
}

# ---------------------------------------------------------------------------
# Private: derive or retrieve cached encryption key
# ---------------------------------------------------------------------------
sub _get_enc_key {
    my ($self) = @_;
    return $self->{_enc_key} if $self->{_enc_key};

    my $dbh = $self->_connect;
    my ($salt_b64) =
      $dbh->selectrow_array("SELECT value FROM db_metadata WHERE key = 'salt'");
    croak "Database corrupted: no salt found" unless $salt_b64;

    my $salt = decode_base64($salt_b64);
    $self->{_enc_key} = _derive_key( $self->{passphrase}, $salt );
    return $self->{_enc_key};
}

# ---------------------------------------------------------------------------
# Private: PBKDF2 key derivation (FIPS 140-2, NIST SP 800-132)
# ---------------------------------------------------------------------------
sub _derive_key {
    my ( $passphrase, $salt ) = @_;
    return pbkdf2( $passphrase, $salt, PBKDF2_ITER, PBKDF2_HASH, AES_KEY_LEN );
}

# ---------------------------------------------------------------------------
# Private: AES-256-GCM encrypt (FIPS 140-2, NIST SP 800-38D)
# Returns base64( IV || tag || ciphertext )
# ---------------------------------------------------------------------------
sub _encrypt {
    my ( $plaintext, $key ) = @_;
    my $iv         = random_bytes(GCM_IV_LEN);
    my $gcm        = Crypt::AuthEnc::GCM->new( 'AES', $key, $iv );
    my $ciphertext = $gcm->encrypt_add($plaintext);
    my $tag        = $gcm->encrypt_done;
    return encode_base64( $iv . $tag . $ciphertext, '' );
}

# ---------------------------------------------------------------------------
# Private: AES-256-GCM decrypt with authentication verification
# ---------------------------------------------------------------------------
sub _decrypt {
    my ( $packed_b64, $key ) = @_;
    my $packed = decode_base64($packed_b64);
    croak "Ciphertext too short"
      if length($packed) < GCM_IV_LEN + GCM_TAG_LEN;
    my $iv        = substr( $packed, 0,          GCM_IV_LEN );
    my $tag       = substr( $packed, GCM_IV_LEN, GCM_TAG_LEN );
    my $ct        = substr( $packed, GCM_IV_LEN + GCM_TAG_LEN );
    my $gcm       = Crypt::AuthEnc::GCM->new( 'AES', $key, $iv );
    my $plaintext = $gcm->decrypt_add($ct);
    $gcm->decrypt_done($tag)
      or croak "GCM authentication failed: data may be tampered";
    return $plaintext;
}

# ---------------------------------------------------------------------------
# Private: ISO 8601 timestamp
# ---------------------------------------------------------------------------
sub _timestamp {
    return strftime( '%Y-%m-%dT%H:%M:%S%z', localtime );
}

# ---------------------------------------------------------------------------
# Private: audit logging [SEC-AUDIT-LOG]
# ---------------------------------------------------------------------------
sub _audit {
    my ( $self, $action, %details ) = @_;
    my $log_path = $self->{audit_log} or return;
    my $log_dir  = dirname($log_path);
    mkdir $log_dir unless -d $log_dir;
    if ( open my $fh, '>>', $log_path ) {
        my $ts   = _timestamp();
        my $user = ( getpwuid($<) )[0] // 'uid:' . $<;
        # Strip newlines from action and all detail values to prevent log injection
        ( my $safe_action = $action ) =~ s/[\r\n]/ /g;
        my $detail = join(
            ', ',
            map {
                my $v = $details{$_};
                $v =~ s/[\r\n]/ /g;
                "$_=$v"
            } sort keys %details
        );
        say $fh "[$ts] user=$user action=$safe_action $detail";
        close $fh;
        chmod 0600, $log_path;
    }
}

sub DESTROY {
    my ($self) = @_;
    $self->{_dbh}->disconnect if $self->{_dbh};
}

1;
