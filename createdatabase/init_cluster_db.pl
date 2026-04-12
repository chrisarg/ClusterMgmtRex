#!/usr/bin/env perl
# ---------------------------------------------------------------------------
# init_cluster_db.pl - Initialize the encrypted cluster public key database
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Security Practice Labels & FIPS-140 Compliance:
#   - AES-256-GCM encryption for all stored keys [FIPS-140]
#   - PBKDF2-SHA256 key derivation with 600,000 iterations (NIST SP 800-132)
#   - Database file permissions set to 0600
#   - Keyfile permissions verified (must be 0400 / owner-read-only)
#   - All operations audit-logged [SEC-AUDIT-LOG]
#
# Usage:
#   # First-time setup - generate a keyfile:
#   openssl rand -base64 32 > .cluster_db.keyfile && chmod 400 .cluster_db.keyfile
#
#   # Initialize the database:
#   perl init_cluster_db.pl --keyfile .cluster_db.keyfile
#
#   # Or use environment variable:
#   CLUSTER_DB_KEY='your-passphrase' perl init_cluster_db.pl
#
#   # Import existing .pub files from pubkeys/:
#   perl init_cluster_db.pl --keyfile .cluster_db.keyfile --import pubkeys
# ---------------------------------------------------------------------------

use v5.38;
use feature 'try';
no warnings 'experimental::try';
use FindBin qw($Bin);
use lib $Bin;
use File::Spec;
use File::Basename qw(basename);
use Getopt::Long;
use ClusterDB;

my $db_path    = File::Spec->catfile( $Bin, 'cluster_keys.db' );
my $keyfile    = File::Spec->catfile( $Bin, '.cluster_db.keyfile' );
my $import_dir = File::Spec->catdir( $Bin, 'pubkeys' );
my $users_csv  = File::Spec->catfile( $Bin, '..', 'system_db_setup', 'users_db.csv' );
my $audit_log  = File::Spec->catfile( $Bin, '..', 'logs', 'audit.log' );
my $help;

GetOptions(
    'db=s'        => \$db_path,
    'keyfile=s'   => \$keyfile,
    'import=s'    => \$import_dir,
    'users-csv=s' => \$users_csv,
    'help'        => \$help,
) or die "Usage: $0 [--db path] [--keyfile path] [--import dir] [--users-csv path]\n";

if ($help) {
    say <<~'USAGE';
        Initialize the cluster SSH public key database.

        Options:
        --db        PATH    Database file path (default: ./cluster_keys.db)
        --keyfile   PATH    Encryption keyfile (default: ./.cluster_db.keyfile)
        --import    DIR     Directory of .pub files to import (default: ./pubkeys)
        --users-csv PATH    CSV file with credentials to import (default: ../system_db_setup/users_db.csv)
        --help              Show this help

        Environment:
        CLUSTER_DB_KEY     Encryption passphrase (alternative to --keyfile)

        First-time setup:
        openssl rand -base64 32 > .cluster_db.keyfile
        chmod 400 .cluster_db.keyfile
        perl init_cluster_db.pl

        DISA-STIG-aligned security practice notes:
        - AES-256-GCM authenticated encryption [FIPS-140]
        - PBKDF2-SHA256 key derivation, 600,000 iterations (NIST SP 800-132)
        - Database file permissions enforced at 0600
        - Keyfile permissions must be 0400 (owner read-only)
        - All operations produce audit log entries [SEC-AUDIT-LOG]
        USAGE
    exit 0;
}

my $passphrase = ClusterDB->get_passphrase( keyfile => $keyfile );

my $db = ClusterDB->new(
    db_path    => $db_path,
    passphrase => $passphrase,
    audit_log  => $audit_log,
);

say "Initializing database at $db_path";
$db->init;
say "  - schema created";
say "  - encryption: AES-256-GCM (FIPS 140-2)";
say "  - KDF: PBKDF2-SHA256, 600,000 iterations (NIST SP 800-132)";

# Import .pub files from pubkeys directory if present
if ( -d $import_dir ) {
    my @pub_files = glob("$import_dir/*.pub");
    if (@pub_files) {
        say "\nImporting public keys from $import_dir";
        my $imported = 0;
        for my $file ( sort @pub_files ) {
            my $name = basename( $file, '.pub' );

            # Validate filename as machine name (OWASP A03:2021)
            if ( $name !~ /^[a-zA-Z0-9._-]+$/ ) {
                warn "  ! Skipping '$name': invalid machine name format\n";
                next;
            }

            open my $fh, '<', $file or do {
                warn "  ! Cannot read $file: $!\n";
                next;
            };
            chomp( my $content = do { local $/; <$fh> } );
            close $fh;

            # Parse SSH public key format: type key [comment]
            my ( $key_type, $key_material, $comment ) =
              split /\s+/, $content, 3;
            if ( !$key_type || !$key_material ) {
                warn "  ! Invalid key format in $file\n";
                next;
            }

            # Compute fingerprint via ssh-keygen
            my $fingerprint = '';
            try {
                chomp( my $fp = `ssh-keygen -lf \Q$file\E 2>/dev/null` );
                $fingerprint = $fp;
            }
            catch ($e) { }

            $db->store_key(
                machine     => $name,
                key_type    => $key_type,
                public_key  => $content,
                fingerprint => $fingerprint,
                comment     => $comment // '',
            );
            say "  + $name ($key_type)";
            $imported++;
        }
        say "  $imported key(s) imported";
    }
    else {
        say "\nNo .pub files found in $import_dir (ready for key import)";
    }
}
else {
    say "\nImport directory not found: $import_dir";
}

# Import credentials from users_db.csv [SEC-CRED-ENCRYPT]: stored encrypted
if ( -f $users_csv ) {
    my $csv_mode = ( stat($users_csv) )[2] & 07777;
    if ( $csv_mode & 0044 ) {
        warn "WARNING: $users_csv is group/world-readable (mode "
          . sprintf( "%04o", $csv_mode )
          . "). It contains plaintext passwords — restrict to 0400 before use.\n";
    }
    say "\nImporting credentials from $users_csv";
    open my $fh, '<', $users_csv or die "Cannot open $users_csv: $!\n";
    my $header = <$fh>;    # skip header
    my $imported = 0;
    while (<$fh>) {
        chomp;
        s/^\s+|\s+$//g;
        next unless length;
        my ( $hostname, $username, $password ) = split /\s*,\s*/, $_, 3;

        if ( !$hostname || $hostname !~ /^[a-zA-Z0-9._-]+$/ ) {
            warn "  ! Skipping invalid hostname: " . ( $hostname // '(empty)' ) . "\n";
            next;
        }
        if ( !$username || !$password ) {
            warn "  ! Skipping '$hostname': missing username or password\n";
            next;
        }

        $db->store_credential(
            machine  => $hostname,
            username => $username,
            password => $password,
            comment  => "imported from users_db.csv",
        );
        say "  + $hostname ($username)";
        $imported++;
    }
    close $fh;
    say "  $imported credential(s) imported";
    say "SECURITY REMINDER: Delete or restrict '$users_csv' after import — it contains plaintext passwords.";
}
else {
    say "\nCredentials CSV not found: $users_csv (skipping credential import)";
}

my @keys = $db->list_keys;
my @creds = $db->list_credentials;
say "\nDatabase ready.";
say "  Keys stored       : " . scalar(@keys);
say "  Credentials stored: " . scalar(@creds);
say "  File permissions  : "
  . sprintf( "%04o", ( stat($db_path) )[2] & 07777 );
say "  Secure delete     : ON";
