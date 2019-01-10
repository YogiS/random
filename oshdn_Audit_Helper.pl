#!/usr/bin/perl -Tw
=blockComment
###########################################################################
File:   oshdn_Audit_Helper

Description:
        This script carries out the OS Hardening by invoking script flxsecaudit  
	and fixes problems found by executing flxoshdn script.  It also performs 
	audits on various other parameters not detected by flxsecaudit and fixes them.
	This script can be run manually.

Inputs: 
        None.

Exit:
	0 => no mismatches
	1 => mismatches found and corrected
        2 => mismatches found and some not corrected

Output:
	STDOUT gives the results of the Audit
	Format:
	apid:recordType:parameter:valuefound:desired value:
	STDERR contains error messages 
        apid:Error Mesage:

=cut

$ENV{PATH} = "/bin:/usr/bin:/usr/sbin";
$ENV{CDPATH} = "/bin:/usr/bin";

my $apid = `/sbin/uname -n`;
if( $apid =~ /^([-\@\w.]+)$/ )
{
  $apid = $1;
}
chomp($apid);

use Fcntl qw(:DEFAULT :flock);

my $appDefaultFile = "/flx/data/FMSoshdn/20evdo";

sub verifyUser();
sub parseflxsecaudit();
sub fixSupOSConfig(%);
sub auditIfconfig();
sub checkForAppDefaultFile(); 
sub checkAndModifyBasedOnSSHstatus();
sub processCorrections($@);
sub processUnCorrectedParams($$@);

use lib "/flx/FMSoshdn/current/lib";

use strict;

verifyUser();

checkForAppDefaultFile();
checkAndModifyBasedOnSSHstatus();

if (my $pid = open(FROMCHILD, "-|")) 
{  # in parent
  my $return_code = 0;
  my $returncode2 = 1;
  my $table = "";
  my $field;
  my %A =();
  my $mismatch =0;
  while( <FROMCHILD>)
  {
    # put tokens that come back from child into hash table
    # set mismatch if mismatch reported
    my $line = $_; 
    $line =~ s/^\s+//;
    if( $line =~ /::/)
    {
      $table = $line;
      $table =~ s/table_name:: //;
    } else
    {
      my @fields = split(/ /, $line );
      if( $line !~ "<No problem found>")
      {
	my $script = $fields[0];
	my $rec = {};
	$rec->{$script} = [@fields];
	push(@{$A{$table}}, $rec);
	$mismatch = 1;
      }
    }
  }
  close(FROMCHILD);

  if(auditIfconfig()){
    $mismatch = 1;
  }

  if($mismatch)
  {
    my $oldtable = "";
    $table = "";
    my $checkOldtable = 0;
    if(fixSupOSConfig(%A))
    {
      print STDERR "$apid:Supplementary Audit failed:";
      exit(-1); # Audit failed
    }
    `./createoneproblem`;
    if( system("/flx/FMSoshdn/current/bin/flxoshdn")) 
    {
      print STDERR "$apid:flxoshdn failed:";
      exit(-1); # Audit failed
    }
    if( $pid = open(FROMCHILD2, "-|"))
    {
      while(<FROMCHILD2>)
      {
        my $line = $_; 
	if( $line =~ /::/)
	{
	  $oldtable = $table;
	  $table = $line;
          $table =~ s/table_name:: //;
	  if($checkOldtable)
          {
	    processCorrections($oldtable,@{$A{$oldtable}}); 
            delete($A{$oldtable});
            $checkOldtable = 0;
          }
	} else
	{
	  my @fields = split(/ /, $line );
	  $field = $fields[0];
	  if( $line =~ "<No problem found>")
	  {
	    if(exists($A{$table})) {
		processCorrections($table,@{$A{$table}});
		delete($A{$table});
	    }
	  }
	  else
	  {
	    my @fields = split(/ /, $line );
	    $field = $fields[1];
	    if(exists($A{$table})) {
              $returncode2 = processUnCorrectedParams($table,$field,@{$A{$table}});
	      $checkOldtable = 1;
	    }
	  }
	}
      } #done with child
      #if last table had mix of corrected and uncorrected process the corrected params
      if($checkOldtable)
      {
        processCorrections($oldtable,@{$A{$oldtable}}); 
        delete($A{$oldtable});
      }
      if($returncode2 > 1) 
      {
	$return_code = $returncode2;
      }
      exit $return_code; 
    }
    else
    {
      parseflxsecaudit();
    }
  }
  else
  {
    #no mismatches
    exit 0;
  }

} else
{
	# in child
	parseflxsecaudit();
}

sub parseflxsecaudit()
{

    $ENV{PATH} = "/bin:/usr/bin";
    $ENV{CDPATH} = "/bin:/usr/bin";
    open(FROM, "/flx/bin/flxsecaudit  |");
    my $lineno = 0;
    my $have_table_name = 0;
    my $have_format = 0;
    my $format_size = 0;
    my $table_name = "";
    my $have_seen_data = 0;
    while (<FROM>)
    {
        chomp;
        $lineno++;
        my $line = $_;      # save original for use in output messages
        next if m/^\s*#/;   # skip full line comments
        s/#.*//;            # strip trailing comments
        s/^\s+//;           # strip leading white spaces for each line
        s/\s+$//;           # strip trailing white spaces for each line
        if (/^\s*$/)
	{
	  $have_format = 0;
	  $have_table_name = 0;
	  next;
	}

        my @fields = split(/\|/, $_);
        my @tmp_ary = ();

        # strip off leading/trailing white spaces for each field, but not
        # spaces in the middle.
	my $size = $#fields + 0;
	if($size == 0 && $have_table_name == 0 && $have_format == 0)
	{
	  if(uc($fields[0]) eq $fields[0]) 
	  {
	    if(!($fields[0] =~ /\+/))
	    {
	      $table_name = $fields[0];
	      $have_table_name = 1;
	      print "table_name:: $table_name\n";
	    }
	    else 
	    {
	      $have_table_name = 1;
	    }
	  }
	  next;
	}
	if($size > 0 && $have_table_name == 1 && $have_format == 0)
	{
	  $format_size = $size;
	  $have_format = 1;
	  next;
	}
	if($size == 0 && $have_format == 1 && $have_seen_data == 1)
	{
	  $have_format = 0;	
	  $have_table_name = 0;
	  $have_seen_data = 0;
	  next;
	}
	if($size == $format_size && $have_format == 1) 
	{
	  $have_seen_data = 1;
          foreach my $field (@fields)
          {
            $field =~ s/^\s+//;
            $field =~ s/\s+$//;
            push (@tmp_ary, $field);
          }

          @fields = @tmp_ary;
          foreach my $field (@fields)
          {
	    print $field ;
	    print " ";
          }
	  print "\n";
	}
    }
    close(FROM);
    close(STDOUT);

    return;
}

sub verifyUser()
{
  if($<) 
  {
    print STDERR "$apid:$0 Only root/super user can run this utility:\n";
    exit(1);
  }
}

sub fixSupOSConfig(%)
{
my %A = @_;
sub fixEtc_System();
sub fixInetd();

  my $return_code = 0;
  if(exists($A{"ETC_SYSTEM\n"}))
  {
    $return_code += fixEtc_System(); 
  }
  if(exists($A{"INETD\n"}))
  {
    $return_code += fixInetd(); 
  }
  if(exists($A{"RC_DAEMON\n"}))
  {
    $return_code += fixRcDaemon(@{$A{"RC_DAEMON\n"}});
  }
  return $return_code; 
}

sub fixEtc_System()
{
  sub readEtcSystem($@);
  my $return_code = 0;
  my $rc1 = 0;
  my $rc2 = 0;
  if( -f "/etc/system")
  {
    ($return_code) = readEtcSystem("/etc/system", qw(noexec_user_stack noexec_user_stack_log)); 
  }
  else 
  { 
    return 1;
  }
  if($return_code & 0x1)
  {
    open(FH, ">>/etc/system");  
    print FH "set noexec_user_stack=1\n"; 
    close(FH);
    $rc1 = system("echo noexec_user_stack/W 1 |mdb -k -w > /dev/null");
  }
  if($return_code & 0x2)
  {
    open(FH, ">>/etc/system");  
    print FH "set noexec_user_stack_log=1\n"; 
    close(FH);
    $rc2 = system("echo noexec_user_stack_log/W 1 |mdb -k -w > /dev/null");
  }
  return ($rc1 + $rc2);
}

sub readEtcSystem($@)
{
  sub commentEtcSystemParam($);
  my ($file,@param_list) = @_;
  open(FH, "<$file") || error("Can't open $file: $!", 1);
  my @file_content = <FH>;
  chomp(@file_content);
  close(FH);

  my $return_code = 0;
  my $base = 1;
  my $found = 0;
  foreach my $param (@param_list)
  {
    $found = 0;
    foreach my $line (@file_content)
    {
      next if ($line =~ m/^\s*$/);
      next if($line !~ m/set/);
      if($line =~ /^set $param=1$/)
      {
        $return_code +=0;
        $found = 1;
        last;
      }
      #If we dont find exact match then we find lines that contain the params
      # and add a # in front of them 
      chomp($line);
      if($line =~ /^set $param/)
      {
        commentEtcSystemParam($param);
      }
    }
    if(!$found)
    {
      $return_code += $base;
    }
    $base *= 2;
  }
  return ($return_code);
}

sub commentEtcSystemParam($)
{
  my ($param) = @_;
  my $file = "/etc/system";
  if (-f $file && !system("sed 's.set $param.#set $param.' $file > $file.tmp")
		&& !system("mv $file.tmp $file"))
  {
      chmod 0744, $file;
      return 0;
  }
  else { return 1}
}

sub fixInetd()
{
  my $file = "/etc/rc2.d/S72inetsvc";
  if (-f $file && !system("sed 's./usr/sbin/inetd -s.#/usr/sbin/inetd -s.' $file > $file.tmp")
               && !system("mv $file.tmp $file"))
               
  {
    chmod 0744,  $file;
    open (FH, ">>$file") || error("Can't open $file: $!", 1);
    print FH "/usr/sbin/inetd -s -r 40 60\n"; 
    close(FH);
    if (!system("$file stop") && !system("$file start > /dev/null"))
    {
      return 0;
    }
  }
  return 1;
}

sub fixRcDaemon(@)
{
  my @Scripts = @_;

  my @value ;

  foreach my $script (@Scripts)
  {
    for my $role ( keys %$script ) 
    {
      @value =  @{$script->{$role}};

      foreach my $D("/etc/rc0.d","/etc/rc2.d","/etc/rc3.d")
      {
	my $sname = undef;
        if( -f "$D/$value[0]")
        {
	  $sname = "$value[0]";
        }
        else
        {
	  if( -f "$D/DISABLE_$value[0]")
	  {
	    $sname = "DISABLE_$value[0]";
	  }
        }
	
        if(defined($sname) && $sname !~ "S89PRESERVE")
        {
		# S89PRESERVE does not take stop argument and can take a long time
		# to run
		# page 562 Programming Perl for the pattern to untaint
  		if( $sname =~ /^([-\@\w.]+)$/ )
		{
			$sname = $1;

		} 
		my $disname = "DISABLE_$value[0]";
		if($disname =~ /^([-\@\w.]+)$/ )
		{
			$disname = $1;
		}
		if( $value[3] eq "RUNNING")
		{
			if(system("sh $D/$sname stop"))
			{
			  return 1;
			}
		}
		if( !($sname =~ /DISABLE/))
		{
        		if(!rename("$D/$sname", "$D/$disname"))
			{
			  return 1;
			}
		}
	}
      }
    }
  }
  return 0;
}

sub auditIfconfig() 
{
  my $intf =  `ifconfig -a | cut -d: -f1 | egrep -v 'ether|inet' | uniq` ;
  my @interfaces = split ( /\n/, $intf);
  foreach my $interface (@interfaces) 
  {
    if( $interface =~ /^([-\@\w.]+)$/ )
    {
	$interface = $1;
    }
    my $r = `ndd  /dev/ip "$interface:ip_forwarding"`;
    if($r == 1 ) 
    {
	
	return 1;
    }
	
  }
  return 0;
} 

sub checkForAppDefaultFile()
{
  if(-f $appDefaultFile)
  {
    return 0;
  }

  if(open(FH, ">$appDefaultFile"))
  {
    print FH "#EVDO data registration file\n";
    print FH "#enable/disable services in /etc/inetd.conf file\n";
    print FH "#EVC_INETD_CONF:service:setting\n";
    print FH "#1 => service enabled\n";
    print FH "#0 => service disabled\n";
    print FH "#\n";
    print FH "ETC_INETD_CONF:ftp:1\n";
    print FH "ETC_INETD_CONF:login:1\n";
    print FH "ETC_INETD_CONF:shell:1\n";
    print FH "ETC_INETD_CONF:telnet:0\n";
    print FH "ETC_INETD_CONF:tftp:0\n";
    print FH "#\n";
  }
  close (FH);
  return 1;
}

sub checkAndModifyBasedOnSSHstatus()
{
  my $rc = `/flx/bin/flxsshstatus -q -h $apid`;

  if($rc =~ /insecure/) 
  {
    if( -f $appDefaultFile 
	&& !system("sed -e 's/:login:0/:login:1/' -e 's/:shell:0/:shell:1/' $appDefaultFile>$appDefaultFile.tmp") && !system("mv $appDefaultFile.tmp $appDefaultFile"))
    {
      chmod 0744,  $appDefaultFile;
      return 0;
    }
  }
  else
  {
    if( -f $appDefaultFile
	&& !system("sed -e 's/:login:1/:login:0/' -e 's/:shell:1/:shell:0/' $appDefaultFile > $appDefaultFile.tmp")
        && !system("mv $appDefaultFile.tmp $appDefaultFile"))
    {
      chmod 0744,  $appDefaultFile;
      return 0;
    }
  }
  return 1;
}

sub processCorrections($@)
{
  my ($table,@Corrections) = @_;
  chomp($table);
  my @value;


  foreach my $script (@Corrections)
  {
    for my $role ( keys %$script ) {
      @value =  @{$script->{$role}};
      my $ub = "_";
      my $param = uc($value[0]);
      $table = uc($table);
      SWITCH: 
      {
        if($table eq "INETD")
        {
	  $param = "INETD_ARG";
	  print STDOUT "$apid:1:$table$ub$param: :$value[2] $value[3] $value[4]:";
	  last SWITCH;
        }
        if($table eq "SYSTEM_ACCOUNT")
        {
	  if($value[0] == "/etc/group")
	  {
	     $value[3] = "0444";
	  }
	  print "value0 $value[0], $value[1], $value[2], $value[3]\n";
	}
          print STDOUT "$apid:1:$table$ub$param:$value[1]:$value[scalar(@value)-2]:";
      }
    }
  }
}

sub processUnCorrectedParams($$@)
{
  my ($table,$newparam,@Corrections) = @_;
  chomp($table);
  my @value;

  foreach my $script (@Corrections)
  {
    for my $role ( keys %$script ) 
    {
      @value =  @{$script->{$role}};
      my $ub = "_";
      my $param = uc($value[0]);
      my $newparam = uc($newparam);
      $table = uc($table);
      if($newparam eq $param)
      {
         print STDOUT "$apid:2:$table$ub$param:$value[1]:$value[scalar(@value)-2]:";
	 delete $script->{$role};
      }
    }
  }
  return 2;
}
