#!/usr/bin/perl
use WWW::Curl::Simple;
use strict;
use warnings;
 
# The path to this script's stored files
my $bpath = "/home/user/bin/vulns/";
# Store last time accessed in var lasta
my $lafile = $bpath . 'lastaccessed.txt', 
my $outfile = 'payload.txt',
my $dif,
my $week = 7 * 24 * 60 * 60;

sub getXML {
    # If it's been less than one week,
    # just get the modified file
    if ($dif < $week) {
        getFile("modified.xml.gz", 
            'https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-Modified.xml.gz');
        return;
    }
    # However if it's been more than a week,
    # get all the files except for modified + recent
    # https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2002.xml.gz
    for (my $year = 2002, my $result = 0; $result == 0 && $year < 2030;$year++) {
        my $url = "https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-".$year.".xml.gz";
        my $filename = $url;
        $filename =~ s/.*(nvdcve.*)/$1/;
        print "Downloaded ".$filename . "\n";
        # get the file. If there's an error, $result will == 1
        my $result = getFile($filename, $url);
        print $result . " " . $year . "\n";
    }
}

# Sub getFile - Curls a compressed gz file from a url,
# deletes the older uncompressed version, and then 
# uncompresses the new archive file.
# @params:
#   filename: the name to save the archive file as
#   url: the location of the archive download
# @returns:
#   0 on success, 1 on failure
sub getFile {
    my ($filename, $url) = @_;
    my $unzippedName = $filename;
    $unzippedName =~ s/\.gz//;

    my $curl = WWW::Curl::Simple->new();
    my $res  = $curl->get($url);
    # If there was an error with the request,
    # as in, we requested a file that doesn't
    # exist (like a file for year 2100), stop.
    return 1 if $res->is_error;

    open(my $fh, '>', $bpath . $filename) or die "Could not open file $filename $!";
    print $fh $res->decoded_content;
    close $fh;
    system ("find $bpath -name $unzippedName -exec rm {} \\;");
    system ("gunzip " . $bpath . $filename);
    return 0;
}

# sub calcdif
# Read in the contents of the lastAccessedFile
# Use that date to calculate the elapsed time
# since this script ran
# @POSTCONDITION:
#   $lasta will contain the last time this script ran
#   $dif will contain the elapsed time since script ran
sub calcdif {
    my $lasta = '';
    if (open(my $fh, '<:encoding(UTF-8)', $lafile)) {
        while (my $row = <$fh>) {
            chomp $row;
            $lasta = $row;
        }
    } else {
        warn "Could not open file '$lafile' $!";
    }
    # if lasta is null, put some old date in 
    $lasta = int (time() / 2) if ($lasta eq "");
    $dif = time() - $lasta;
}

# updateLA updates the last accessed time for this program.
# That time is stored as seconds since 1970, in a file.
sub updateLA {
    open(my $fh, '>', $lafile) or die "Could not open file '$lafile' $!";
    print $fh time();
    close $fh;
}

sub xmlToCols {
    opendir DIR, $bpath or die "cannot open dir $bpath: $!";
    my @files = readdir DIR;
    closedir DIR;

    if ($dif < $week) {
        @files = ("modified.xml");
    }
    else {
        @files = grep { /nvdcve.*xml/ } @files;
    }
    foreach my $xml (@files) {
        my $txt = $xml;
        $txt =~ s/xml/txt/;
        print "Creating \"" . $txt . "\" from \"" . $xml . "\"\n";

        if (open(my $fh, '<:encoding(UTF-8)', $bpath . $xml)) {
            open(my $out, '>:encoding(UTF-8)', $bpath . $txt) or die "Could not open file '$txt' $!";
            while (my $row = <$fh>) {
                chomp $row;
                if ($row =~ /<entry id="CVE.+">/){
                    $row =~ s/.*(CVE.*)">/$1/;
                    print $out $row; # row is eq CVE ..
                } 
                if ($row =~ /<cvss:score>\d+\.\d*</) {
                    $row =~ s/.*>(\d+\.\d*)<.*/$1/;
                    print $out "\t" . $row; # lineline  is a score
                }
                if ($row =~ /<\/entry/) {
                    print $out "\n"; # end of an entry
                }   
            }
            close $fh;
        } else {
            warn "Could not open file '$xml' $!";
        }
        close $txt;
    }
}
sub mergePayload {
    opendir DIR, $bpath or die "cannot open dir $bpath: $!";
    my @files = readdir DIR;
    closedir DIR;

    if ($dif < $week) {
        @files = ("modified.txt");
    }
    else {
        @files = grep { /nvdcve.*txt/ } @files;
    }
    # Overwrite old payload file
    open(my $out, '>:encoding(UTF-8)', $bpath . $outfile) or die "Could not open file '$outfile' $!";
    print $out "";
    close $out;

    # For each CVE, add it to payload file
    open($out, '>>:encoding(UTF-8)', $bpath . $outfile) or die "Could not open file '$outfile' $!";
    foreach my $txt (@files) {
        open(my $in, '<:encoding(UTF-8)', $bpath . $txt) or die "Could not open file '$txt' $!";
        print "file: " .$txt . "\n";
        while (my $row = <$in>) {
            print $out $row;
        }
    }
    close $out;
}
calcdif();
updateLA();
# Just get everything, every time
$dif = $week * 2;
getXML();
xmlToCols();
mergePayload();
