package ClusterSSHHelpers;
# ---------------------------------------------------------------------------
# ClusterSSHHelpers - Helper functions for Rex-based cluster SSH management
# ---------------------------------------------------------------------------
# Shared utility module extracted from the Rexfile. Provides SSH option
# builders, audit logging, admin detection, bootstrap helpers,
# IO::Interface management, and other reusable subroutines.
#
# Usage (from a Rexfile or script):
#   use FindBin qw($Bin);
#   use lib "$Bin/..";           # adjust to reach the repo root
#   use ClusterSSHHelpers;
#
#   ClusterSSHHelpers::init(
#       machines           => \@machines,
#       machine_set        => \%machine_set,
#       audit_log_path     => $audit_log_path,
#       cluster_key_path   => $cluster_key_path,
#       cluster_db_path    => $cluster_db_path,
#       cluster_db_keyfile => $cluster_db_keyfile,
#       has_cluster_db     => $HAS_CLUSTER_DB,
#       default_ssh_retry  => $DEFAULT_SSH_RETRY,
#   );
#
# Security Practice Labels:
#   [SEC-SSH-NOPASSWD]     Password authentication disabled (key-based only)
#   [SEC-STRICT-HOSTKEY]   StrictHostKeyChecking enforced (except bootstrap)
#   [SEC-CRED-ENCRYPT]     No plaintext credentials in process table or on disk
#   [SEC-AUDIT-LOG]        All mutating operations produce audit log entries
#   [SEC-KEY-PASSPHRASE]   SSH keys protected with random passphrase
# ---------------------------------------------------------------------------

use v5.38;
use feature 'try';
no warnings 'experimental::try';
use Exporter 'import';
use File::Basename qw(dirname);
use File::Path     qw(remove_tree);
use File::Temp     qw(tempfile tempdir);
use IPC::System::Simple qw(capturex systemx);
use POSIX               qw(strftime);
use Net::Ping;

our @EXPORT = qw(
    ssh_opts
    ssh_opts_bootstrap
    command_exists
    kh_key
    run_or_warn
    shell_quote
    audit_log
    validate_name
    detect_admin
    tcp_pinger
    resolve_targets
    require_cluster_key
    generate_passphrase
    ensure_agent_loaded
    cluster_db
    get_credential
    bootstrap_via_askpass
    bootstrap_run_or_warn
    bootstrap_capturex
    generate_load_cluster_key_script
    bootstrap_remote_mktemp
    io_interface_probe_code
    perl_can_load_io_interface
    ensure_io_interface
    cleanup_io_interface
    all_networks
    get_mac_for_ip
    get_networks
    @ssh_opts
    @ssh_opts_bootstrap
);

# ---------------------------------------------------------------------------
# Package-level configuration — set via init()
# ---------------------------------------------------------------------------
my @machines;
my %machine_set;
my $audit_log_path;
my $cluster_key_path;
my $cluster_db_path;
my $cluster_db_keyfile;
my $HAS_CLUSTER_DB;
my $DEFAULT_SSH_RETRY;

# Mutable SSH option arrays — callers use local() to override per-task
our @ssh_opts;
our @ssh_opts_bootstrap;

# ---------------------------------------------------------------------------
# init() — must be called before using any helper that depends on shared state
# ---------------------------------------------------------------------------
sub init {
    my (%cfg) = @_;
    @machines           = @{ $cfg{machines}           // [] };
    %machine_set        = %{ $cfg{machine_set}        // {} };
    $audit_log_path     = $cfg{audit_log_path}     // '';
    $cluster_key_path   = $cfg{cluster_key_path}   // '';
    $cluster_db_path    = $cfg{cluster_db_path}    // '';
    $cluster_db_keyfile = $cfg{cluster_db_keyfile} // '';
    $HAS_CLUSTER_DB     = $cfg{has_cluster_db}     // 0;
    $DEFAULT_SSH_RETRY  = $cfg{default_ssh_retry}  // 5;

    @ssh_opts           = ssh_opts($DEFAULT_SSH_RETRY);
    @ssh_opts_bootstrap = ssh_opts_bootstrap($DEFAULT_SSH_RETRY);
}

# ---------------------------------------------------------------------------
# SSH option builders
# ---------------------------------------------------------------------------

# Build operational SSH options with a given retry count
# [SEC-SSH-NOPASSWD]: PasswordAuthentication disabled
# [SEC-STRICT-HOSTKEY]: StrictHostKeyChecking enforced
sub ssh_opts {
    my ($retries) = @_;
    $retries //= $DEFAULT_SSH_RETRY;
    return (
        '-o',               'StrictHostKeyChecking=yes', '-o',
        'ConnectTimeout=5', '-o',             "ConnectionAttempts=$retries",
        '-o',               'LogLevel=ERROR', '-o',
        'PasswordAuthentication=no', '-o',    'PubkeyAuthentication=yes',
        '-i',                        $cluster_key_path,
    );
}

# Build bootstrap SSH options with a given retry count
# WARNING: host verification disabled; use only for first-time setup
sub ssh_opts_bootstrap {
    my ($retries) = @_;
    $retries //= $DEFAULT_SSH_RETRY;
    return (
        '-o',                           'StrictHostKeyChecking=no', '-o',
        'UserKnownHostsFile=/dev/null', '-o', 'ConnectTimeout=5',
        '-o',                           "ConnectionAttempts=$retries", '-o',
        'LogLevel=ERROR',
    );
}

# ---------------------------------------------------------------------------
# Core utilities
# ---------------------------------------------------------------------------

sub command_exists {
    my ($cmd) = @_;
    for my $dir ( split /:/, ( $ENV{PATH} // '/usr/bin:/bin' ) ) {
        return 1 if -x "$dir/$cmd";
    }
    return 0;
}

# Extract (host_field, key_type, key_material_base64) from a known_hosts line.
# Returns () for blank/comment lines.
sub kh_key {
    my ($line) = @_;
    return () if !defined $line || $line !~ /\S/ || $line =~ /^\s*#/;
    my ( $host_field, $kt, $km_raw ) = split /\s+/, $line, 3;
    return () unless defined $kt && defined $km_raw;

    my ($km) = split /\s+/, $km_raw;
    return () unless defined $km && length $km;
    return ( $host_field, $kt, $km );
}

sub run_or_warn {
    my (@cmd) = @_;
    try {
        systemx(@cmd);
    }
    catch ($e) {
        warn "Command failed: " . join( ' ', @cmd ) . "\n";
        return 0;
    }
    return 1;
}

sub shell_quote {
    my ($text) = @_;
    $text //= '';
    $text =~ s/'/'"'"'/g;
    return "'$text'";
}

# ---------------------------------------------------------------------------
# Audit logging [SEC-AUDIT-LOG]
# ---------------------------------------------------------------------------

sub audit_log {
    my ( $action, %details ) = @_;
    my $timestamp = strftime( '%Y-%m-%dT%H:%M:%S%z', localtime );
    my $user      = ( getpwuid($<) )[0] // 'uid:' . $<;
    my $log_dir   = dirname($audit_log_path);
    if ( !-d $log_dir ) {
        mkdir $log_dir or do {
            warn "Cannot create audit log dir $log_dir: $!\n";
            return;
        };
    }
    if ( open my $fh, '>>', $audit_log_path ) {

        # Strip newlines to prevent log injection
        ( my $safe_action = $action ) =~ s/[\r\n]/ /g;
        my $detail_str = join(
            ', ',
            map {
                my $v = $details{$_};
                $v =~ s/[\r\n]/ /g;
                "$_=$v"
            } sort keys %details
        );
        say $fh "[$timestamp] user=$user action=$safe_action $detail_str";
        close $fh;
        CORE::chmod 0600, $audit_log_path;
    }
    else {
        warn "Cannot write audit log $audit_log_path: $!\n";
    }
}

# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

sub validate_name {
    my ($name) = @_;
    die "Invalid name '$name': must match /^[a-zA-Z0-9._-]+\$/\n"
      unless defined $name && $name =~ /^[a-zA-Z0-9._-]+$/;
    return $name;
}

# ---------------------------------------------------------------------------
# Admin detection, pinger, target resolution
# ---------------------------------------------------------------------------

# Detect the admin machine — the one whose IP on this network matches a local IP.
# If $network_name is given, match only that network; otherwise match any network.
# Returns ($admin_ip, $admin_machine) or (undef, undef).
# Uses Rex::CMDB::get() which must be available in the caller's environment.
sub detect_admin {
    my ($network_name) = @_;
    my @local_ips =
      grep { $_ } split( /\s+/, capturex( 'hostname', '-I' ) );
    my %local_ip_set = map { $_ => 1 } @local_ips;
    for my $m ( sort @machines ) {
        my $nets = get_networks($m);
        next unless ref $nets eq 'HASH';
        if ($network_name) {
            my $ip = $nets->{$network_name};
            if ( $ip && $local_ip_set{$ip} ) {
                return ( $ip, $m );
            }
        }
        else {
            for my $ip ( values %$nets ) {
                if ( $local_ip_set{$ip} ) {
                    return ( $ip, $m );
                }
            }
        }
    }
    return ( undef, undef );
}

# Create a Net::Ping TCP prober on port 22 with the given timeout.
sub tcp_pinger {
    my ($timeout) = @_;
    $timeout //= 1;
    my $pinger = Net::Ping->new( 'tcp', $timeout );
    $pinger->port_number(22);
    return $pinger;
}

# Resolve --group/--machine parameters into a target member list.
# If both are given, --group takes precedence.
# Returns @target_members.
sub resolve_targets {
    my ($param) = @_;
    my $group_name   = $param->{group};
    my $machine_name = $param->{machine};

    if ( defined $group_name && defined $machine_name ) {
        warn "Both --group and --machine specified; --group='$group_name' takes precedence.\n";
        undef $machine_name;
    }
    $group_name //= 'all';

    if ( defined $machine_name ) {
        validate_name($machine_name);
        die "Machine '$machine_name' not found in CMDB.\n"
          unless $machine_set{$machine_name};
        return ($machine_name);
    }

    die "Group '$group_name' is not defined.\n"
      unless Rex::Group->is_group($group_name);
    return map { "$_" } Rex::Group->get_group($group_name);
}

# ---------------------------------------------------------------------------
# Key and credential helpers
# ---------------------------------------------------------------------------

sub require_cluster_key {
    die "Admin SSH key not found at $cluster_key_path\n"
      . "Run 'rex setup_ssh_keys --network=<name> --bootstrap=1' first.\n"
      unless -f $cluster_key_path;
}

# Generate a cryptographically strong random passphrase [SEC-KEY-PASSPHRASE]
# Returns a 44-character base64 string (~256 bits of entropy)
sub generate_passphrase {
    chomp( my $pp = capturex( 'openssl', 'rand', '-base64', '32' ) );
    die "Failed to generate passphrase\n" unless $pp && length($pp) >= 40;
    return $pp;
}

# Ensure the admin's cluster key is loaded into ssh-agent [SEC-KEY-PASSPHRASE]
sub ensure_agent_loaded {

    my $agent_keys = do {
        my $out = '';
        if ( open my $fh, '-|', 'ssh-add', '-l' ) {
            $out = do { local $/; <$fh> };
            close $fh;
        }
        $out // '';
    };
    my $fp;
    try {
        chomp( my $f = capturex( 'ssh-keygen', '-lf', $cluster_key_path ) );
        $fp = ( split /\s+/, $f )[1];
    }
    catch ($e) { }
    $fp //= '';

    if ( $fp && $agent_keys =~ /\Q$fp\E/ ) {
        return 1;
    }

    my $db = cluster_db()
      or die "Cannot open ClusterDB to retrieve key passphrase.\n"
      . "Ensure cluster_keys.db and keyfile exist.\n";
    my $passphrase = $db->get_key_passphrase( machine => 'admin' )
      or die "No key passphrase found for admin in ClusterDB.\n"
      . "Re-run 'rex setup_ssh_keys --network=<name> --bootstrap=1' "
      . "to generate passphrased keys.\n";

    my ( $ap_fh, $ap_script ) = tempfile(
        '.cl_XXXXXXXX',
        DIR    => '/tmp',
        UNLINK => 1
    );
    my ( $pw_fh, $pw_file ) = tempfile(
        '.cl_XXXXXXXX',
        DIR    => '/tmp',
        UNLINK => 1
    );
    print $pw_fh $passphrase;
    close $pw_fh;
    CORE::chmod 0400, $pw_file;
    print $ap_fh "#!/bin/sh\ncat $pw_file\n";
    close $ap_fh;
    CORE::chmod 0500, $ap_script;

    local $ENV{SSH_ASKPASS}         = $ap_script;
    local $ENV{SSH_ASKPASS_REQUIRE} = 'force';
    local $ENV{DISPLAY}             = ':0';

    my $ok;
    try {
        systemx( 'ssh-add', $cluster_key_path );
        $ok = 1;
    }
    catch ($e) { }
    unlink $pw_file, $ap_script;

    die "Failed to load cluster key into ssh-agent.\n"
      . "Ensure ssh-agent is running (eval \$(ssh-agent) or add to shell rc).\n"
      unless $ok;

    audit_log( 'agent_key_loaded', key => $cluster_key_path );
    return 1;
}

# Lazy-connect to the encrypted key database (returns undef if unavailable)
sub cluster_db {
    state $attempted = 0;
    state $db;
    return $db if $attempted;
    $attempted = 1;
    return undef unless $HAS_CLUSTER_DB;
    my $passphrase;
    try {
        $passphrase = ClusterDB->get_passphrase( keyfile => $cluster_db_keyfile );
    }
    catch ($e) { }
    return undef unless $passphrase;
    try {
        $db = ClusterDB->new(
            db_path    => $cluster_db_path,
            passphrase => $passphrase,
            audit_log  => $audit_log_path,
        );
    }
    catch ($e) { }
    return $db;
}

# Look up credentials from encrypted DB only [SEC-CRED-ENCRYPT]
# Returns ($username, $password) or (undef, undef)
sub get_credential {
    my ($machine) = @_;
    if ( my $db = cluster_db() ) {
        my $cred = $db->get_credential( machine => $machine );
        if ($cred) {
            return ( $cred->{username}, $cred->{password} );
        }
    }
    return ( undef, undef );
}

# ---------------------------------------------------------------------------
# Bootstrap helpers — SSH_ASKPASS + 0400 tempfile
# [SEC-CRED-ENCRYPT]: password never in SSHPASS env var, process args, or
# /proc/environ
# ---------------------------------------------------------------------------

sub bootstrap_via_askpass {
    my ( $password, $runner, @cmd ) = @_;

    if ( @cmd >= 2 && $cmd[0] eq 'sshpass' && $cmd[1] eq '-e' ) {
        splice @cmd, 0, 2;
    }

    my ( $pw_fh, $pw_file ) =
      tempfile( '.cl_XXXXXXXX', DIR => '/tmp', UNLINK => 1 );
    print $pw_fh $password;
    close $pw_fh;
    CORE::chmod 0400, $pw_file;

    my ( $ap_fh, $ap_script ) =
      tempfile( '.cl_XXXXXXXX', DIR => '/tmp', UNLINK => 1 );
    print $ap_fh "#!/bin/sh\ncat $pw_file\n";
    close $ap_fh;
    CORE::chmod 0500, $ap_script;

    local $ENV{SSH_ASKPASS}         = $ap_script;
    local $ENV{SSH_ASKPASS_REQUIRE} = 'force';
    local $ENV{DISPLAY}             = $ENV{DISPLAY} // ':0';
    delete local $ENV{SSHPASS};

    my $result;
    my $err;
    try {
        $result = $runner->(@cmd);
    }
    catch ($e) {
        $err = $e;
    }
    unlink $pw_file, $ap_script;
    die $err if $err;
    return $result;
}

sub bootstrap_run_or_warn {
    my ( $password, @cmd ) = @_;
    return bootstrap_via_askpass(
        $password,
        sub { systemx(@_); 1 },
        @cmd,
    ) // 0;
}

sub bootstrap_capturex {
    my ( $password, @cmd ) = @_;
    return bootstrap_via_askpass(
        $password,
        sub { capturex(@_) },
        @cmd,
    );
}

# ---------------------------------------------------------------------------
# Node-local key loader script [SEC-KEY-PASSPHRASE] [SEC-CRED-ENCRYPT]
# ---------------------------------------------------------------------------

sub generate_load_cluster_key_script {
    return <<'SCRIPT';
#!/usr/bin/env perl
# load_cluster_key.pl
# Deployed by cluster_mgmt setup_ssh_keys; do not edit manually.
# Unlocks ~/.ssh/id_ecdsa_p521_cluster and loads it into the local ssh-agent.
# [SEC-KEY-PASSPHRASE]: passphrase never in process args or env vars.
# [SEC-CRED-ENCRYPT]: passphrase only transiently in memory + 0400 tempfile.
use strict;
use warnings;
use File::Temp qw(tempfile);

my $ssh_dir = "$ENV{HOME}/.ssh";
my $key     = "$ssh_dir/id_ecdsa_p521_cluster";
my $keyfile = "$ssh_dir/.cluster_node_keyfile";
my $enc_pp  = "$ssh_dir/.cluster_node_pp";

die "Cluster key not found: $key\n"             unless -f $key;
die "Node keyfile not found: $keyfile\n"         unless -f $keyfile;
die "Encrypted passphrase not found: $enc_pp\n"  unless -f $enc_pp;

# Check if key is already in agent.
my $agent_keys = do {
    my $out = '';
    if ( open my $fh, '-|', 'ssh-add', '-l' ) {
        $out = do { local $/; <$fh> };
        close $fh;
    }
    $out // '';
};
my $fp = do {
    my $f = '';
    if ( open my $fh, '-|', 'ssh-keygen', '-lf', $key ) {
        $f = do { local $/; <$fh> };
        close $fh;
    }
    ( split /\s+/, $f )[1] // '';
};

if ( $fp && index( $agent_keys, $fp ) >= 0 ) {
    exit 0;    # already loaded
}

# Decrypt passphrase into a 0400 temp file
my ( $pp_fh, $pp_file ) =
  tempfile( '.cl_XXXXXXXX', DIR => '/tmp', UNLINK => 1 );
close $pp_fh;
chmod 0400, $pp_file;

my $rc = system( 'openssl', 'enc', '-d', '-aes-256-cbc', '-pbkdf2',
    '-iter', '600000', '-pass', "file:$keyfile",
    '-in', $enc_pp, '-out', $pp_file );
if ( $rc != 0 ) {
    unlink $pp_file;
    die "Failed to decrypt cluster key passphrase\n";
}

# SSH_ASKPASS shim reads from pp_file — passphrase never in env or args
my ( $ap_fh, $ap_script ) =
  tempfile( '.cl_XXXXXXXX', DIR => '/tmp', UNLINK => 1 );
print $ap_fh "#!/bin/sh\ncat $pp_file\n";
close $ap_fh;
chmod 0500, $ap_script;

local $ENV{SSH_ASKPASS}         = $ap_script;
local $ENV{SSH_ASKPASS_REQUIRE} = 'force';
local $ENV{DISPLAY}             = $ENV{DISPLAY} // ':0';
delete $ENV{SSHPASS};

my $ok = ( system( 'ssh-add', $key ) == 0 );
unlink $pp_file, $ap_script;

die "Failed to load cluster key into ssh-agent.\n"
  . "Ensure ssh-agent is running: eval \$(ssh-agent -s)\n"
  unless $ok;

exit 0;
SCRIPT
}

# Create a secure temporary file on a remote host via SSH using mktemp(1).
sub bootstrap_remote_mktemp {
    my ( $password, $target, $template ) = @_;
    $template //= '/tmp/.cl_XXXXXXXX';
    my $remote_path =
      bootstrap_capturex( $password, 'sshpass', '-e', 'ssh',
        '-o', 'StrictHostKeyChecking=accept-new',
        '-o', 'BatchMode=no', $target, "mktemp $template" );
    chomp $remote_path;
    die "Remote mktemp failed on $target\n" unless $remote_path =~ m{^/};
    return $remote_path;
}

# ---------------------------------------------------------------------------
# IO::Interface helpers (used by obtain_mac)
# ---------------------------------------------------------------------------

sub io_interface_probe_code {
    return join ' ',
      'require IO::Socket::INET;',
      'require IO::Interface;',
      'my $ip = shift;',
      'my $sock = IO::Socket::INET->new(Proto => q{udp}) or exit 1;',
      'for my $iface ($sock->if_list) {',
      'my $addr = eval { $sock->if_addr($iface) };',
      'next unless defined $addr && $addr eq $ip;',
      'my $mac = eval { $sock->if_hwaddr($iface) };',
      'next unless defined $mac && length $mac;',
      '$mac =~ s/\s+//g;',
      'print lc $mac;',
      'exit 0;',
      '}',
      'exit 1;';
}

sub perl_can_load_io_interface {
    my (%args) = @_;
    my ( $local, $target, $libdir ) = @args{qw(local target libdir)};

    my @libopt = $libdir ? ( '-I', $libdir ) : ();
    my $code   = 'require IO::Socket::INET; require IO::Interface; exit 0;';

    if ($local) {
        try {
            capturex( 'perl', @libopt, '-e', $code );
            return 1;
        }
        catch ($e) {
            return 0;
        }
    }

    my @parts = ('perl');
    push @parts, '-I ' . shell_quote($libdir) if $libdir;
    push @parts, '-e ' . shell_quote($code);
    my $cmd = join ' ', @parts;
    try {
        capturex( 'ssh', @ssh_opts, $target, $cmd );
        return 1;
    }
    catch ($e) {
        return 0;
    }
}

sub ensure_io_interface {
    my (%args) = @_;
    my ( $machine, $local, $target ) = @args{qw(machine local target)};

    my %state = (
        machine        => $machine,
        local          => $local,
        target         => $target,
        installed_temp => 0,
        prefix         => undef,
        libdir         => undef,
    );

    return \%state
      if perl_can_load_io_interface(
        local  => $local,
        target => $target,
      );

    return undef if !command_exists('cpan');

    my ( $prefix, $libdir );
    if ($local) {
        $prefix = tempdir(
            ".cl_XXXXXXXX",
            DIR     => '/tmp',
            CLEANUP => 0,
        );
    }
    else {
        try {
            chomp(
                my $out = capturex(
                    'ssh',   @ssh_opts,
                    $target, 'mktemp -d /tmp/.cl_XXXXXXXX'
                )
            );
            $prefix = $out;
        }
        catch ($e) { }
        return undef if !$prefix || !length $prefix;
    }
    $libdir = "$prefix/lib/perl5";

    if ($local) {
        try {
            systemx(
                'env',
                'PERL_MM_USE_DEFAULT=1',
                'NONINTERACTIVE_TESTING=1',
                "PERL_MM_OPT=INSTALL_BASE=$prefix",
                "PERL_MB_OPT=--install_base $prefix",
                'cpan',
                '-T',
                '-i',
                'IO::Interface'
            );
        }
        catch ($e) {
            return undef;
        }
    }
    else {
        my $install_cmd = join ' ',
          'env',
          'PERL_MM_USE_DEFAULT=1',
          'NONINTERACTIVE_TESTING=1',
          'PERL_MM_OPT=' . shell_quote("INSTALL_BASE=$prefix"),
          'PERL_MB_OPT=' . shell_quote("--install_base $prefix"),
          'cpan -T -i IO::Interface';

        try {
            capturex( 'ssh', @ssh_opts, $target, $install_cmd );
        }
        catch ($e) {
            return undef;
        }
    }

    return undef
      if !perl_can_load_io_interface(
        local  => $local,
        target => $target,
        libdir => $libdir,
      );

    $state{installed_temp} = 1;
    $state{prefix}         = $prefix;
    $state{libdir}         = $libdir;
    return \%state;
}

sub cleanup_io_interface {
    my (%args) = @_;
    my ( $local, $target, $prefix ) = @args{qw(local target prefix)};

    return 1 if !$prefix;

    if ($local) {
        remove_tree($prefix);
        return 1;
    }

    my $code = 'require File::Path; File::Path::remove_tree(shift); exit 0;';
    my $cmd  = join ' ', 'perl', '-e ' . shell_quote($code), '--',
      shell_quote($prefix);

    try {
        capturex( 'ssh', @ssh_opts, $target, $cmd );
        return 1;
    }
    catch ($e) {
        return 0;
    }
}

# Safe wrapper around Rex::CMDB::get('networks', $machine).
# Rex CMDB may return '' instead of undef for missing keys;
# this always returns a hashref.
sub get_networks {
    my ($machine) = @_;
    my $nets = Rex::CMDB::get( 'networks', $machine );
    return ref $nets eq 'HASH' ? $nets : {};
}

# ---------------------------------------------------------------------------
# Network / MAC helpers
# ---------------------------------------------------------------------------

sub all_networks {
    my %seen;
    for my $m (@machines) {
        my $nets = get_networks($m);
        next unless ref $nets eq 'HASH';
        $seen{$_}++ for keys %$nets;
    }
    return sort keys %seen;
}

# Discover MAC for a given machine IP using IO::Interface.
sub get_mac_for_ip {
    my (%args) = @_;
    my ( $ip, $local, $target, $libdir ) = @args{qw(ip local target libdir)};

    my @libopt = $libdir ? ( '-I', $libdir ) : ();
    my $code   = io_interface_probe_code();

    my $mac;
    my $err;
    if ($local) {
        try {
            $mac = capturex( 'perl', @libopt, '-e', $code, '--', $ip );
        }
        catch ($e) { $err = $e; }
    }
    else {
        my @parts = ('perl');
        push @parts, '-I ' . shell_quote($libdir) if $libdir;
        push @parts, '-e ' . shell_quote($code), '--', shell_quote($ip);
        my $cmd = join ' ', @parts;
        try {
            $mac = capturex( 'ssh', @ssh_opts, $target, $cmd );
        }
        catch ($e) { $err = $e; }
    }

    return undef if $err || !defined $mac || !length $mac;
    $mac =~ s/\s+//g;
    return length($mac) ? lc $mac : undef;
}

1;
