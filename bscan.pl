#!/usr/bin/perl -w
#
# bscan harvests service banners from a 
# ip or ip range then saves  
# any findings to a log named "results"
#
# 	by Jonathan D Gonzalez/xor-function

use strict;
use IO::Socket;
use Net::Telnet;
use Net::IP;
use LWP;

# requires hostname and port as parameter arguments
sub set_url {

        my $chost = $_[0];
        my $cport = $_[1];

        my $ssl_prefix  = 'https';
        my $http_prefix = 'http';
        my $ftp_prefix  = 'ftp';
        my $prefix;

        if ($cport eq 443) { $prefix = $ssl_prefix; }
        elsif ($cport eq 80) { $prefix = $http_prefix; }
        elsif ($cport eq 21)  { $prefix = $ftp_prefix; }
        my $fullurl = join('://', $prefix, $chost );

        return $fullurl;
}

# win uses the $banner and then $port as an argument to clear out the
# variable from unwanted charaters
sub win {

        my $bnr = $_[0];
        my $cport = $_[1];

        print "\n[+] connecting to $cport \n";
        chomp($bnr);
        $bnr =~ s/\r|\n//g;
        print "\n$bnr\n";

        return $bnr;

}

# uses the current iteration of the port number as a parameter
sub fail {

        my $cport = $_[0];
        print "\n[!] connecting to $cport failed\n";
}

# sub gen_hosts requires the variable $net for an argument
sub gen_hosts {

  my $srnet = $_[0];
  my @hostips;

  unless ($srnet =~ m// ) {
       print "match\n";
       @hostips = $ARGV[0];

     } else {
 
                my $ip = new Net::IP ($srnet) || die "invalid ip address range\n";

                do {

                        my $shost = $ip->ip();
                        # do not scan ip address of network or broadcast ip 
                        unless ( $shost =~ /(\.0)/ or $shost =~ /(\.255)/ ) {
                                # print $host, "\n";
                                push @hostips, $shost;
                        }

                } while (++$ip);

    }

        return @hostips;

}

# provide current host, port variables as parameters
sub get_telnet {

        my $chost = $_[0];
        my $bnr;
        my $nbnr;

        # removed default Net::Telent errmode action "die" with a blank subroutine
        if ( my $conn = new Net::Telnet( Host => $chost, Timeout => 5, Errmode => sub{ }, )) {

                ($bnr) = $conn->waitfor('/login: ?/');
                $conn->close;
                $nbnr = win($bnr, "23");
        }
          else {
                fail("23");
        }

        return $nbnr;

}

# provide current host, port variables as parameters
sub getsshmail {

        my $chost = $_[0];
        my $cport = $_[1];
        my $bnr;
        my $nbnr;

        if (my $conn = IO::Socket::INET->new( PeerAddr => $chost, PeerPort => $cport, Proto =>'tcp', Timeout =>'5', )) {

                print $conn "GET \n";        
                while (readline($conn)) {
                        if (defined($_)) { $bnr .= $_; }
                        last;                            
                }
                close $conn;
                $nbnr = win($bnr, $cport);

        } else { 
                fail($cport);

        }

        return $nbnr;

}

# provide current host, port variables as parameters
sub use_lwp {

        my $chost = $_[0];
        my $cport = $_[1];

        my $url = set_url($chost, $cport);
        my $rqst = LWP::UserAgent->new( timeout => 3 );
        my $rsp  = $rqst->get("$url");
        my $bnr = $rsp->header("Server");
        my $nbnr;

        # add web scraping logic when there is a hit on detection.
        if (defined($bnr)) {
                $nbnr = win($bnr, $cport);
        }else {
                fail($cport);
        }

        return $nbnr;

}

# provide current host, log variables as parameters 
sub chk_ports {

    my $cphost = $_[0];
    my $slog = $_[1];
    my @ports = (21, 22, 23, 25, 80, 443);

    open(my $fh, '+>>', "$slog" ) or die "Could not open file $!";
    print $fh "\n---------------------------------------------------";
    print $fh "\n[+] summary for $cphost";
    close $fh;

    foreach(@ports) {

                my $port = $_;
                my $banner;

                if ($port eq 80 or $port eq 443 or $port eq 21 ) { $banner = use_lwp($cphost, $port); }
                if ($port eq 23) { $banner = get_telnet($cphost); }
                if ($port eq 22 or $port eq 25) { $banner = getsshmail($cphost, $port); }

                open(my $fh, '+>>', "$slog" ) or die "Could not open file $!";
                print $fh "\n   Port : $port : ";
                if (defined($banner))
                        { print $fh "$banner";}
                        else {
                        print $fh "no service detected";
                }

                close $fh;

        }

                open($fh, '+>>', "$slog" ) or die "Could not open file $!";
                print $fh "\n";
                close $fh;

}


print "\n";
print "--------------------------------\n";
print "         B  S  C  A  N          \n";
print "--------------------------------\n";
print "\n";

if ( @ARGV == 0 ) { die "[!] use $0 [host ip or valid network ip with cidr netmask]\n"; }

my $net = $ARGV[0];
my $log = "results";

my @hosts = gen_hosts($net);

foreach(@hosts) {

        my $host = $_;
        print "\n[+] summary for $host\n";
        chk_ports($host, $log);

}

print "\n[+] Done with scan!\n\n";
exit(0);

