#!/home/chrisarg/perl5/perlbrew/perls/current/bin/perl
use v5.38;
use FindBin qw($Bin);
use File::Path qw(make_path);
use File::Spec;
use YAML::Tiny;

my $cmdb_dir = File::Spec->catdir( $Bin, '..', 'cmdb' );

# ---------------------------------------------------------------------------
# Parse users_db.csv  (Hostname, Username, Password)
# Used only to know which hosts to create YAML files for.
# Credentials are stored in the encrypted ClusterDB, NOT in YAML.
# ---------------------------------------------------------------------------
my %users;
{
    open my $fh, '<', File::Spec->catfile( $Bin, 'users_db.csv' )
        or die "Cannot open users_db.csv: $!";
    <$fh>;    # skip header
    while (<$fh>) {
        chomp;
        s/^\s+|\s+$//g;
        next unless length;
        my ( $hostname, $username, $password ) = split /\s*,\s*/, $_, 3;
        if ( !$hostname || $hostname !~ /^[a-zA-Z0-9._-]+$/ ) {
            warn "generate_cmdb: skipping invalid hostname: "
              . ( $hostname // '(empty)' ) . "\n";
            next;
        }
        $users{$hostname} = { username => $username, password => $password };
    }
}

# ---------------------------------------------------------------------------
# Parse networks_db.csv  (Network, Hostname, IP)
# ---------------------------------------------------------------------------
my %networks;
{
    open my $fh, '<', File::Spec->catfile( $Bin, 'networks_db.csv' )
        or die "Cannot open networks_db.csv: $!";
    <$fh>;    # skip header
    while (<$fh>) {
        chomp;
        s/^\s+|\s+$//g;
        next unless length;
        my ( $network, $hostname, $ip ) = split /\s*,\s*/, $_, 3;
        if ( !$hostname || $hostname !~ /^[a-zA-Z0-9._-]+$/ ) {
            warn "generate_cmdb: skipping invalid hostname in networks: "
              . ( $hostname // '(empty)' ) . "\n";
            next;
        }
        if ( !$network || $network !~ /^[a-zA-Z0-9._-]+$/ ) {
            warn "generate_cmdb: skipping invalid network name: "
              . ( $network // '(empty)' ) . "\n";
            next;
        }
        if ( defined $ip ) {
            $ip =~ s/\s+$//;    # strip trailing whitespace/CR
            if ( $ip !~ /^(\d{1,3}\.){3}\d{1,3}$/ ) {
                warn "generate_cmdb: skipping invalid IP '$ip' for $hostname/$network\n";
                next;
            }
        }
        $networks{$hostname}{$network} = $ip;
    }
}

# ---------------------------------------------------------------------------
# Emit one YAML file per host (networks + mac only, NO credentials)
# [SEC-CRED-ENCRYPT]: credentials stored in encrypted ClusterDB database only
# ---------------------------------------------------------------------------
make_path($cmdb_dir);

for my $hostname ( sort keys %users ) {
    my %data;
    $data{networks} = $networks{$hostname} if exists $networks{$hostname};

    my $file = File::Spec->catfile( $cmdb_dir, "$hostname.yml" );

    # Preserve existing mac data if YAML file already exists
    if ( -f $file ) {
        my $existing = YAML::Tiny->read($file);
        if ( $existing && $existing->[0]{mac} ) {
            $data{mac} = $existing->[0]{mac};
        }
    }

    YAML::Tiny->new( \%data )->write($file)
        or die "Cannot write $file: " . YAML::Tiny->errstr;
    print "Written: $file\n";
}

# Warn about hosts in networks_db but missing from users_db
for my $hostname ( sort keys %networks ) {
    warn "Warning: '$hostname' in networks_db.csv has no entry in users_db.csv\n"
        unless exists $users{$hostname};
}

say "\nNote: Credentials NOT written to YAML files.";
say "Run createdatabase/init_cluster_db.pl to import credentials into encrypted DB.";
