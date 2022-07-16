#!/usr/bin/env perl
use strict;
use warnings FATAL => 'all';
use feature qw(:5.24);

my $code = system "make";
exit if $code != 0;

our $APP_NAME = 'isucholar';
our @APP_SERVERS = (
    # 'server01',
);
our @SERVERS = (
    # 'server01',
    # 'server02',
);

for my $server (@SERVERS) {
    if (grep($server, @APP_SERVERS)) {
        say _stop_app($server);
        say _deploy($server);
        say _restart_app($server);
    }
    say _isulog_lotate($server);
}
say 'DEPLOY FINISHED';

sub _stop_app {
    my ($server) = @_;
    <<`CMD`;
ssh $server << EOF
sudo systemctl stop ${APP_NAME}.go.service
EOF
CMD
}

sub _deploy {
    my ($server) = @_;
    <<`CMD`;
sftp $server << EOF
cd /home/isucon/webapp/go
put $APP_NAME
EOF
CMD
}

sub _restart_app {
    my ($server) = @_;
    <<`CMD`;
ssh $server << EOF
sudo systemctl start  ${APP_NAME}.go.service
sudo systemctl status ${APP_NAME}.go.service
EOF
CMD
}

sub _isulog_lotate {
    my ($server) = @_;
    <<`CMD`;
ssh $server << EOF
isulog lotate
EOF
CMD
}

1;
