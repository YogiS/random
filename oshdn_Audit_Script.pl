#!/usr/bin/perl -Tw
=blockComment
###########################################################################
File:   oshdn_Audit_Script

Description:
        This script will be executed by the RNCSA process running on the non-HOC 
        Lead AP and HOC Lead AP. This script performs the OS Hardening Audit by 
	executing oshdn_Audit_Helper script.

Inputs: 
        None

Exit:
	success 0
	fail    1

Output:
	STDOUT gives the results of the Audit
	Format:
	apid:recordType:statusCode:
	apid:recordType:parameter:valuefound:desired value:
	STDERR contains error messages 
        apid:Error Mesage:

=cut

use strict; 
use Fcntl qw(:DEFAULT :flock);

sub getApInfo();
sub ReadHostsFile();
sub GetNumberOfAps();
sub GetListofAPs();
sub checkIfHocLeadAP();
sub process(@);
sub checkIfNotHoc($);
sub REAPER();

$ENV{PATH} = "/bin:/usr/bin:/usr/sbin:/flx/rcc/bin";
$ENV{CDPATH} = "/bin:/usr/bin";


my $HostsFile = "/evcData.cfg";

my $auditHelperScript = "/flx/ONEXEVc/current/release/tools/cfg/security/oshdn_Audit_Helper";

my @HostFileLines = ();   
my $NumAPs = 0;        
my @ApName;          
my $return_code = 0;
my $myApId = `uname -n`;
my $myHocApId;
my $log = "";
my $results = ();
my $rc = ();

$SIG{CHLD} = \&REAPER;

if( $myApId =~ /^([-\@\w.]+)$/ )
{
  $myApId = $1;
}

if(checkIfHocLeadAP())
{
  if(getApInfo())
  {
    process(@ApName);
  }
  else 
  {
    print STDERR "$myApId:Error while performing Audit:";
  }
}
else
{
  #Exit If Not HOC. 
  chomp($myApId);
  if(checkIfNotHoc($myApId))
  {
    print STDERR "$myApId:Error AP is NOT HOC:";
    exit 1;
  }
  #else we are non-hoc lead AP. Perform Audit Locally.
  `./createproblem`;
  $results = `$auditHelperScript`;
  $rc = $?;
  local $|=1;
  flock(STDOUT, LOCK_EX); #lock to ensure that we dont write partial results
  print STDOUT "$myApId:0:$rc:";
  print STDOUT "$results\n";
  flock(STDOUT, LOCK_UN); 
}

my $FINAL_RC = 0;

exit $FINAL_RC;

sub getApInfo()
{
  if(-f $HostsFile)
  {
    if(!ReadHostsFile())
    {
      print STDERR "Cannot open $HostsFile\n";
      return 0; 
    }
  }
  else
  {
    print STDERR  "$HostsFile does not exist\n";
    return 0; 
  } 

  if(!GetNumberOfAps())
  {
      print STDERR "Count not get num of AP's\n";
      return 0; 
  }
  
  if(!GetListofAPs())
  {
      print STDERR "Count not get List of AP's\n";
      return 0; 
  }
  return 1;
}

sub ReadHostsFile()
{
   my $Rc = 0;

   if (open (HOSTS, $HostsFile))
   {
      while (<HOSTS>)
      {
         $_ =~ s/^\s+//;
         $_ =~ s/\s+$//;
         push (@HostFileLines, $_);
      }
      close(HOSTS);
      $Rc = 1;
   }
   return $Rc;
}

sub GetNumberOfAps ()
{
   my $Rc = 1;
   my $Line;

   foreach $Line (@HostFileLines)
   {
     if ($Line =~ s/^flxNum://)
     {
       chomp $Line;
       $NumAPs = $Line;
       last;
     }
   }

   if ($NumAPs == 0)
   {
     $NumAPs = 8;
     $Rc = 0;
   }
   return $Rc;
}

sub GetListofAPs ()
{
   my $Line;
   my $Ap;
   my $Rc = 0;
   my $Index;

   ### Find the ID names of the APs.
   foreach $Line (@HostFileLines)
   {
      if ($Line =~ s/^flxNames://)
      {
         @ApName = split (/ /, $Line);
         $Rc = 1;
         last;
      }
   }

   ### Now truncate the array so that it matches the number of APs configured in the system
   while (@ApName > $NumAPs)
   {
     pop @ApName;
   }

   ### Validate each entry.
   for ($Index = 0; $Index < $NumAPs; $Index++)
   {
     if (!($ApName[$Index]) || ($ApName[$Index] !~ m/flx\d{1,3}/))
     {
       $Rc = 0;
     }
   }
   return $Rc;
}

sub checkIfHocLeadAP()
{
  $myHocApId = `/flx/ONEXEVc/current/release/util/FindPriBkup.pl|grep HOCVCVM|grep PRIMARY|awk '{print \$3}'`;
  if($myHocApId)
  {
    if($myApId eq $myHocApId)
    {
      return  1;
    }
  }
  return 0;
}

sub process(@)
{
  my $ap = shift @_;
  my @apName = @_;
  my $pid;
  if($ap)
  {
    if($pid = fork())
    {
      # In Parent
      if($ap =~ /^([-\@\w.]+)$/)
      {
        $ap = $1;
      }
      chomp($myApId);
      if($ap eq $myApId)
      {
        $results = `$auditHelperScript`;
	$rc = $?;
      }
      if(checkIfNotHoc($ap)) 
      {
        #print "ssh to AP in parent $ap with PID is $$\n";
        $results = `ssh $ap '$auditHelperScript'`;
	$rc = $?;
      }
      else 
      {
        return;
      }
      flock(STDOUT, LOCK_EX); #lock to ensure that we dont write partial results
      local $|=1;
      print STDOUT "$ap:0:$rc:";
      print STDOUT "$results";
      flock(STDOUT, LOCK_UN);
      return;
    }
    else
    {
      # In Child
      if(@apName)
      {
        process(@apName);
      }
      exit 0;
    }
  }
}

sub checkIfNotHoc($)
{
  my ($aptoChecK) = @_; 
  my $HocStatus=`/flx/ONEXEVc/current/release/util/FindPriBkup.pl|grep HOCVCVM|grep $aptoChecK`;
  if($HocStatus)
  {
    return 0;
  }
  return 1;
}

sub REAPER() {
	$SIG{CHLD} = \&REAPER;
}
