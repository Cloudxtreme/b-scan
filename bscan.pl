#!/usr/bin/perl
#
# bscan 
# harvests service banners from a 
# ip or ip range then saves  
# any findings to a log named "results"
#
# by Jonathan D Gonzalez || xor-function

 



use strict;
use warnings;
use IO::Socket;
use Net::Telnet;
use Net::IP;
use LWP;

my $ssl_prefix  = 'https';
my $http_prefix = 'http';
my $ftp_prefix  = 'ftp';

my ($rqst, $rsp, $url);
my (@hosts, $host, $net, $ip);
my ($port, $conn, $banner, $cidr);
my $log = "results";

if ( @ARGV == 0 ) { die "[!] use $0 [host ip or valid network ip with cidr netmask]\n"; }

$net = $ARGV[0];

sub set_url {
	my $prefix;
	if ($port eq 443) { $prefix = $ssl_prefix;
	} elsif ($port eq 80) { $prefix = $http_prefix; }
	elsif ($port eq 21)  { $prefix = $ftp_prefix; }            
	$url = join('://', $prefix, $_[0] );
}

sub win {
	print "\n[+] connecting to $port \n";
        chomp($banner);
	$banner =~ s/\r|\n//g;
	print "\n$banner\n";
}

sub fail {
	print "\n[!] connecting to $port failed\n";
}

sub gen_hosts {

  unless ($net =~ m// ) 
     { 
       print "match\n";     
       $host = $ARGV[0];

     } else {
 
        $cidr = 'true';
	$ip = new Net::IP ($net) || die "invalid ip address range\n";               
	
	do 
 	{
		$host = $ip->ip();
		# do not scan ip address of network or broadcast ip 
		unless ( $host =~ /(\.0)/ or $host =~ /(\.255)/ ) {
       			# print $host, "\n";
			push @hosts,$host;
		}

	} while (++$ip);

      }

}


sub chk_ports {

    open(my $fh, '+>>', "$log" ) or die "Could not open file $!";
    print $fh "\n---------------------------------------------------";
    print $fh "\n[+] summary for $host";
    close $fh;
    
    my @ports = (21, 22, 23, 25, 80, 443);

    foreach(@ports) 
     {

	$port = $_;
	undef $conn;
	undef $url;

	if ($port eq 80 or $port eq 443 or $port eq 21 ) 
	 { 
         
		set_url($host);
		$rqst = LWP::UserAgent->new( timeout => 5 );
		     $rsp    = $rqst->get("$url");
		     $banner = $rsp->header("Server");       
  
                # add web scraping logic when there is a hit on detection.
		if (defined($banner))        
		   { win(); } 
                   else { fail(); }
             
          } 
    

	if ($port eq 23) 
	 {


		# removed default Net::Telent errmode action "die" with a blank subroutine                
		if ( $conn = new Net::Telnet( Host => $host,
		                               Timeout => 5, 
                                          Errmode => sub{ }, ))
		   {
           
                       ($banner) = $conn->waitfor('/login: ?/');
                       $conn->close;
                       win();
                   } else 
                       { fail();}
     
	 } 

	if ($port eq 22 or $port eq 25)
	 {
      
		if ($conn = IO::Socket::INET->new( PeerAddr => $host, 
                                                   PeerPort => $port, 
                                                       Proto =>'tcp', 
                                                       Timeout =>'5', ))
 
		   { 
			print $conn "GET \n";              
 			while (readline($conn)) { 
                            if (defined($_)) { $banner .= $_; }
                            last;                                           	       
                        }
			close $conn;
			win();          
		    } else 
                       { fail(); }

	 }


	open(my $fh, '+>>', "$log" ) or die "Could not open file $!";
	print $fh "\n	Port : $port : ";
	if (defined($banner)) 
		{ print $fh "$banner";} 
		else { print $fh "no service detected"; } 
	close $fh;       
        undef $banner;
    }

}

print "\n";
print "--------------------------------\n";
print "         B  S  C  A  N          \n";
print "--------------------------------\n";


gen_hosts();


if (defined($cidr)) 
  {
       foreach(@hosts)
        {
                $host = $_;
                print "\n[+] summary for $_\n";
                chk_ports();
        }

  } else {

        print "\n[+] summary for $host\n";
        chk_ports();
  }


print "\n[+] Done with scan!\n\n";
