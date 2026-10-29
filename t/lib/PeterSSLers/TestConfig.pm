package PeterSSLers::TestConfig;
use strict;
use warnings;
use Cwd qw(cwd);
use File::Basename qw(basename);
use File::Temp qw(tempdir);

# Set this before Test::Nginx loads so its listener and our API fixtures agree.
$ENV{TEST_NGINX_SERVER_PORT} ||= $ENV{TEST_NGINX_PORT} || 1984;

# Random run identity also distinguishes workers with identical PIDs in separate
# containers sharing a test datastore. The hostname prefix stays DNS-safe.
unless ($ENV{TEST_NGINX_FIXTURE_ID}) {
    my $identity = lc basename(tempdir('sslers-XXXXXXXXXXXX', TMPDIR => 1, CLEANUP => 1));
    $identity =~ s/[^a-z0-9-]/-/g;
    $ENV{TEST_NGINX_FIXTURE_ID} = $identity;
}
die "TEST_NGINX_FIXTURE_ID must contain 1-32 lowercase DNS label characters\n"
    unless $ENV{TEST_NGINX_FIXTURE_ID} =~ /\A[a-z0-9-]{1,32}\z/;

# Test::Nginx builds shell commands and nginx directives with unquoted runtime
# paths. Keep generated files outside checkouts whose paths contain whitespace.
# Preserve the runtime directory after failure so logs remain available.
if (!$ENV{TEST_NGINX_SERVROOT} && cwd() =~ /\s/) {
    $ENV{TEST_NGINX_SERVROOT} = tempdir('sslers-tests-XXXXXX', TMPDIR => 1);
}

1;
