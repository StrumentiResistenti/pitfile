#!/usr/bin/perl

use strict;
use warnings;

use Fuse;
use POSIX qw(EIO EROFS ENOTDIR ENOENT ENOSYS EEXIST EPERM O_RDONLY O_WRONLY O_RDWR O_APPEND O_CREAT setsid);
use Fcntl qw(S_ISBLK S_ISCHR S_ISFIFO SEEK_SET S_ISREG S_ISFIFO S_IMODE S_ISCHR S_ISBLK S_ISSOCK S_IWUSR S_IWGRP S_IWOTH S_ISDIR S_ISLNK);
use Unix::Mknod;
use Logger::Syslog;
use Digest::SHA qw(sha1_hex);
use Mail::Sendmail;

#
# Debug levels are:
#
# 1. error
# 2. warning
# 3. notice
# 4. debug
#
my $loglevel = 2;

#
# Context read from the repository's .pitfilerc
#
our %filters;
our %config;

#
# Get the repository
#
my $repository = $ARGV[0];
usage("No repository provided") unless defined $repository and $repository;

#
# Get the mountpoint
#
my $mountpoint = $ARGV[1];
usage("No mountpoint provided") unless defined $mountpoint and $mountpoint;

#
# Compute the .pitfilerc path
#
my $pitfilerc = "$repository/.pitfilerc";

#
# Create the quarantine area
#
my $quarantine_area = $repository;
$quarantine_area =~ s#/+$##;
$quarantine_area .= ".quarantine";
unless (-d $quarantine_area) {
	CORE::mkdir($quarantine_area, 0700) || die "Can't create quarantine area: $quarantine_area";
}

#
# Check Unix::Mknod availability
#
my $has_mknod = 0;
eval {
	require Unix::Mknod;
	1;
} and do {
	$has_mknod = 1;
	Unix::Mknod->import();
};

#
# Receiving a 'kill -HUP', pitfile should read its config file again
#
$SIG{'HUP'} = sub {
	our %filters;
	our %config;
	
	warning("Reading $pitfilerc again on SIGHUP");
	do $pitfilerc;
};

#
# Translate any relative path to the corresponding repository path
#
# @param $path the path to translate
# @return the translated (absolute) path
#
sub xlate {
	my $path = shift() || return "";
	if ($path =~ /^$repository/) { return $path; }
	my $xlated = "$repository/$path";
	$xlated =~ s#/+#/#g;
	return $xlated;
}

#
# FUSE getattr
#
# Return the stat() equivalent set of metadata about a path,
# applying some transformations in the while
#
sub getattr {
	my ($path) = @_;
	return -1 * ENOENT if $path =~ m#/.pitfilerc$#;
	
	my @res = CORE::lstat(xlate($path));
	if (0 == $#res) {
		debug("OP: getattr($path) -> FAILED!") if $loglevel >= 4;
		return @res;
	}

	unless (defined $res[2]) {
		debug("OP: getattr($path) -> FAILED!") if $loglevel >= 4;
		return @res;
	}

	my $size = $res[7];
	my $type = S_ISDIR($res[2]) ? "DIR" : S_ISLNK($res[2]) ? "LINK" : "FILE";
	debug("OP: getattr($path) -> [$type] $size bytes") if $loglevel >= 4;
	return @res;
}

#
# FUSE readlink
#
sub readlink {
	my ($path) = @_;
	my $res = CORE::readlink(xlate($path));
	debug("OP: readlink($path) -> $res") if $loglevel >= 4;
	return $res ? 0 : -$!;
}

#
# FUSE mknod
#
sub mknod {
	my ($path, $mode, $dev) = @_;
	
	#
	# do not allow the creation of .pitfilerc
	#
	return -1 * EROFS if $path =~ m#/.pitfilerc$#;
	
	my $xlated = xlate($path);

	#
	# since this is called for ALL files, not just devices, pitfile runs
	# some checks and possibly use the real mknod command.
	#
	
	#
	# Regular file
	#
	if (S_ISREG($mode)) {
		CORE::open(FILE, '>', $xlated) || return -$!;
		print FILE '';
		CORE::close(FILE);
		CORE::chmod S_IMODE($mode), $xlated;
		debug("OP: mknod($path, $mode, $dev) -> 0") if $loglevel >= 4;
		return 0;
	}

	#
	# FIFO pipe
	#
	if (S_ISFIFO($mode)) {
		my ($rv) = POSIX::mkfifo($xlated, S_IMODE($mode));
		my $res = $rv ? 0 : -POSIX::errno();
		debug("OP: mknod($path, $mode, $dev) -> $res") if $loglevel >= 4;
		return $res;
	}

	#
	# Character or block device
	#
	if (S_ISCHR($mode) || S_ISBLK($mode)) {
		if($has_mknod){
			Unix::Mknod::mknod($xlated, $mode, $dev);
			my $res = -$!;
			debug("OP: mknod($path, $mode, $dev) -> $res") if $loglevel >= 4;
			return $res;
		} else {
			my $res = -POSIX::errno();
			debug("OP: mknod($path, $mode, $dev) -> $res") if $loglevel >= 4;
			return $res;
		}
	}

	#
	# S_ISSOCK should be handled too; however, for our
	# purposes it does not really matter.
	#
	my $res = -1 * ENOSYS;
	debug("OP: mknod($path, $mode, $dev) -> $res") if $loglevel >= 4;
	return $res;
}

#
# FUSE mkdir
#
sub mkdir {
	my ($path, $mode) = @_;
	my $res = CORE::mkdir(xlate($path), $mode);
	debug("OP: mkdir($path, $mode) -> $res") if $loglevel >= 4;
	return $res ? 0 : -$!;
}

#
# FUSE unlink
#
sub unlink {
	my ($path) = @_;
	
	#
	# Can't unlink .pitfilerc
	#
	return -1 * ENOENT if $path =~ m#/.pitfilerc$#;
	
	my $res = CORE::unlink(xlate($path));
	debug("OP: unlink($path) -> $res") if $loglevel >= 4;
	return $res ? 0 : -$!;
}

#
# FUSE rmdir
#
sub rmdir {
	my ($path) = @_;
	my $res = CORE::rmdir(xlate($path));
	debug("OP: rmdir($path) -> $res") if $loglevel >= 4;
	return $res ? 0 : -$!;
}

#
# FUSE symlink
#
sub symlink {
	my ($from, $to) = @_;
	my $res = CORE::symlink(xlate($from), xlate($to));
	debug("OP: symlink($from, $to) -> $res") if $loglevel >= 4;
	return $res ? 0 : -$!;
}

#
# FUSE link
#
sub link {
	my ($from, $to) = @_;
	my $res = CORE::link(xlate($from), xlate($to));
	debug("OP: link($from, $to) -> $res") if $loglevel >= 4;
	return $res ? 0 : -$!;
}

#
# FUSE rename
#
sub rename {
	my ($from, $to) = @_;
	
	#
	# Can't rename from or to .pitfilerc
	#
	return -1 * EROFS if $from =~ m#/.pitfilerc$#;
	return -1 * EROFS if $to   =~ m#/.pitfilerc$#;
	
	my $res = CORE::rename(xlate($from), xlate($to));
	debug("OP: rename($from, $to) -> $res") if $loglevel >= 4;
	return $res ? 0 : -$!;
}

#
# FUSE chmod
#
sub chmod {
	my ($path, $mode) = @_;
	
	#
	# Protect .pitfilerc
	#
	return -1 * EROFS if $path =~ m#/.pitfilerc$#;
	
	my $res = CORE::chmod(xlate($path), $mode);
	warning("OP: chmod($path, $mode) -> $res") if $loglevel >= 2;
	return $res ? 0 : -$!;
}

#
# FUSE chown
#
sub chown {
	my ($path, $uid, $gid) = @_;

	#
	# Protect .pitfilerc
	#
	return -1 * EROFS if $path =~ m#/.pitfilerc$#;
	
	my $res = CORE::chown(xlate($path), $uid, $gid);
	warning("OP: chown($path, $uid, $gid) -> $res") if $loglevel >= 2;
	return $res ? 0 : -$!;
}

#
# FUSE truncate
#
sub truncate {
	my ($path, $offset) = @_;
	
	#
	# Protect .pitfilerc
	#
	return -1 * EROFS if $path =~ m#/.pitfilerc$#;

	my $res = CORE::truncate(xlate($path), $offset);
	$res = defined $res ? 0 : -1 * EIO;
	debug("OP: truncate($path, $offset) -> $res") if $loglevel >= 4;
	return $res;
}

#
# FUSE utime
#
sub utime {
	my ($path, $actime, $modtime) = @_;

	#
	# Protect .pitfilerc
	#
	return -1 * EROFS if $path =~ m#/.pitfilerc$#;

	my $res = CORE::utime($actime, $modtime, xlate($path));
	debug("OP: utime($path, $actime, $modtime) -> $res") if $loglevel >= 4;
	return $res ? 0 : -$!;
}

#
# FUSE open
#
sub open {
	my ($path, $flags, $fileinfo) = @_;
	
	#
	# Protect .pitfilerc
	#
	return -1 * ENOENT if $path =~ m#/.pitfilerc$#;
	
	my $filehandle = POSIX::open(xlate($path), $flags);

	if (defined $filehandle and $filehandle) {
		debug("OP: open($path, $flags, <fileinfo> -> 0") if $loglevel >= 4;
		return (0, $filehandle);
	} else {
		my $res = -POSIX::errno();
		debug("OP: open($path, $flags, <fileinfo> -> $res") if $loglevel >= 4;
		return $res;
	}
}

#
# FUSE create
#
sub create {
	my ($path, $flags, $fileinfo) = @_;

	#
	# Protect .pitfilerc
	#
	return -1 * EROFS if $path =~ m#/.pitfilerc$#;
	
	my $filehandle = POSIX::creat(xlate($path), $flags);

	if (defined $filehandle and $filehandle) {
		debug("OP: create($path, $flags, <fileinfo> -> 0") if $loglevel >= 4;
		return (0, $filehandle);
	} else {
		my $res = -POSIX::errno();
		debug("OP: create($path, $flags, <fileinfo> -> $res") if $loglevel >= 4;
		return $res;
	}
}

#
# FUSE read
#
sub read {
	my ($path, $size, $offset, $filehandle) = @_;
	
	#
	# Protect .pitfilerc
	#
	return -1 * EIO if $path =~ m#/.pitfilerc$#;

	my $buffer;

	unless (defined $filehandle and $filehandle) {
		$filehandle = POSIX::open(xlate($path), &POSIX::O_RDONLY);

		unless (defined $filehandle and $filehandle) {
			my $res = -POSIX::errno();
			debug("OP: read($path, $size, $offset, $filehandle) -> $res") if $loglevel >= 4;
			return $res;
		}
	}

	my $res = POSIX::lseek($filehandle, $offset, &POSIX::SEEK_SET);
	unless (defined $res) {
		my $res = -POSIX::errno();
		debug("OP: read($path, $size, $offset, $filehandle) -> $res") if $loglevel >= 4;
		return $res;
	}

	$res = POSIX::read($filehandle, $buffer, $size);
	unless (defined $res) {
		my $res = -1 * EIO;
		debug("OP: read($path, $size, $offset, $filehandle) -> $res") if $loglevel >= 4;
		return $res;
	}

	debug("OP: read($path, $size, $offset, $filehandle) -> 0 (" . length($buffer) . " bytes)") if $loglevel >= 4;
	return $buffer;
}

#
# FUSE write
#
sub write {
	my ($path, $buffer, $offset, $filehandle) = @_;

	#
	# Protect .pitfilerc
	#
	return -1 * EIO if $path =~ m#/.pitfilerc$#;

	unless (defined $filehandle and $filehandle) {
		$filehandle = POSIX::open(xlate($path), &POSIX::O_WRONLY);
		unless (defined $filehandle and $filehandle) {
			my $res = -POSIX::errno();
			debug("OP: write($path, $buffer, $offset, <filehanlde>) -> $res") if $loglevel >= 4;
			return $res;
		}
	}

	my $res = POSIX::lseek($filehandle, $offset, &POSIX::SEEK_SET);
	unless (defined $res) {
		my $res = -POSIX::errno();
		debug("OP: write($path, $buffer, $offset, <filehanlde>) -> $res") if $loglevel >= 4;
		return $res;
	}

	$res = POSIX::write($filehandle, $buffer, length($buffer));
	unless (defined $res) {
		my $res = -POSIX::errno();
		debug("OP: write($path, $buffer, $offset, <filehanlde>) -> $res") if $loglevel >= 4;
		return $res;
	}

	debug("OP: write($path, $buffer, $offset, <filehanlde>) -> 0 ($res bytes)") if $loglevel >= 4;
	return $res;
}

#
# FUSE statfs
#
sub statfs {
	my ($path) = @_;
	debug("OP: statfs($path)") if $loglevel >= 4;
}

#
# FUSE flush
#
sub flush {
	my ($path, $filehandle) = @_;
	debug("OP: flush($path, <filehandle>)") if $loglevel >= 4;

	return 0;
}

#
# FUSE release
#
sub release {
	my ($path, $flags, $filehandle, $flock_flag, $lock_owner) = @_;

	if (defined $filehandle and $filehandle) {
		my $res = POSIX::close($filehandle);
		unless (defined $res) {
			my $res = -POSIX::errno();
			debug("OP: release($path, ...) -> $res") if $loglevel >= 4;
			return $res;
		}
	}

	if ($flags & O_WRONLY || $flags & O_RDWR) {
		analyze(xlate($path));
	}

	debug("OP: release($path, ...) -> 0") if $loglevel >= 4;
	return 0;
}

#
# FUSE opendir
#
sub opendir {
	my ($path) = @_;

	my $dirhandle = POSIX::opendir(xlate($path));
	unless (defined $dirhandle) {
		my $res = -1 * EIO;
		debug("OP: opendir($path) -> $res") if $loglevel >= 4;
		return $res;
	}

	debug("OP: opendir($path) -> 0") if $loglevel >= 4;
	return (0, $dirhandle);
}

#
# FUSE readdir
#
sub readdir {
	my ($path, $offset, $dirhandle) = @_;

	unless (defined $dirhandle and $dirhandle) {
		$dirhandle = POSIX::opendir(xlate($path)) unless defined $dirhandle and $dirhandle;
		unless (defined $dirhandle and $dirhandle) {
			my $res = -POSIX::errno();
			debug("OP: readdir($path, $offset, <dirhandle>) -> $res") if $loglevel >= 4;
			return $res;
		}
	}

	my @entries = POSIX::readdir($dirhandle);
	@entries = grep(!/^.pitfilerc$/, @entries); # remove .pitfilerc from listed files
	push @entries, 0;

	debug("OP: readdir($path, $offset, <dirhandle>) -> 0 (" . $#entries . " entries)") if $loglevel >= 4;
	return @entries;
}

#
# FUSE releasedir
#
sub releasedir {
	my ($path, $filehandle) = @_;

	if (defined $filehandle and $filehandle) {
		my $res = POSIX::closedir($filehandle);
		unless (defined $res and $res) {
			my $res = -1 * EIO;
			debug("OP: releasedir($path) -> $res") if $loglevel >= 4;
			return $res;
		}
	}

	debug("OP: releasedir($path) -> 0") if $loglevel >= 4;
	return 0;
}

#
# FUSE init
#
sub init {
	our %filters;
	our %config;

	# logger_init();
	logger_prefix('pitfile: ');
	logger_set_default_facility("auth");
	debug("OP: init") if $loglevel >= 4;
	
	#
	# Save standard .pitfilerc
	#
	unless (-f $pitfilerc) {
		if (CORE::open(RC, ">$pitfilerc")) {
			while (<DATA>) { print RC $_; }
			CORE::close(RC);
		}
	}
	
	#
	# Parse repository .pitfilerc
	#
	if (-f $pitfilerc) {
		do $pitfilerc;
	} else {
		die "Can't parse $pitfilerc rc file";
	}
	
	#
	# Get hostname
	#
	$config{'hostname'} = `hostname`;
	$config{'hostname'} =~ s/\s.*//;
}

#
# FUSE destroy
#
sub destroy {
	debug("OP: destroy") if $loglevel >= 4;
}

#
# Internal mail function to report anolies
#
# @param $subject the email subject
# @param $body the email body
#
sub mail {
	my ($subject, $body) = @_;
	return unless defined $subject and $subject;
	return unless defined $body and $body;
	
	our %config;
	
	sendmail(
		From => "pitfile@" . $config{'hostname'},
		To => $config{'mail_recipient'},
		Subject => $subject,
		Message => $body,
	);
}

#
# Load file content limited to a requested size
# If size is 0 or undef, the entire file is loaded
#
# @param $path the file path
# @param $length the file portion to load in bytes
#
sub load_file_content {
	my ($path, $length) = @_;
	
	my $content = "";
	my $size = 0;
	
	unless (defined $length and $length) {
		my @stat = stat($path);
        $length = $stat[7];	
	}
	
	if (CORE::open(IN, $path)) {
		while ($size < $length) {
			my $buffer;
			my $res = CORE::read(IN, $buffer, 1024);
			
			last unless defined $res;
			last if 0 == $res;
			
			$content += $buffer;
			$size += $res;
		}
		CORE::close(IN);
	}
	
	return ($content);
}

#
# Move a file into quarantine area
#
# @param $path the relative file path inside the repository
# @param $xlated the absolute file path on disk
#
sub quarantine {
	my ($path, $xlated) = @_;

	#
	# place the file in the quarantine area
	#
	my $sha1 = sha1_hex($path);
	CORE::rename($xlated, "$quarantine_area/$sha1");
	warning("$path quarantined as $quarantine_area/$sha1");

	#
	# load some kilobytes of malicious file to add some
	# context to the email
	#
	my $content = load_file_content($xlated, $config{'file_excerpt_size'});
	my $size = length($content);

	#
	# Send the email
	#
	mail(
		"Quarantine advisor", 
		"$path has been quarantined as $quarantine_area/$sha1\n" .
		"Here follows an excerpt of $size byted from the file:\n\n" .
		"$content\n"
	);
}

#
# Applies a set of filters to a file, returning the filter that matches
#
# @param $path the file relative path
# @param $xlated the file translated path (absolute on disk)
# @param $payload the text that must be checked (usually filled with $path or with file content)
# @param $filter_set an array reference to the filter set to be applied
#
sub apply_filters {
	my ($path, $xlated, $payload, $filter_set) = @_;

	my @filter_set = @{$filter_set};
	for (my $i = 0; $i < $#filter_set; $i += 2) {
		my $pattern = $filter_set[$i];
		my $action  = $filter_set[$i+1];

		if (defined $pattern and $pattern and $payload =~ /$pattern/) {
			if (defined $action and $action) { &$action($path, $xlated); }
			return ($pattern);
		}
	}

	return (undef);
}

#
# Analyze new files looking for suspicious traits or invalid conditions
#
# @param $path the file path relative to repository mountpoint
#
sub analyze {
	my ($path) = @_;
	our %filters;

	info("Analyzing $path");
	my $xlated = xlate($path);

	#
	# First look for path whitelisting
	#
	my $path_whitelist_match = apply_filters($path, $xlated, $path, $filters{'path'}->{'whitelist'});
	if (defined $path_whitelist_match and $path_whitelist_match) {
		info("$path path is whitelisted by /$path_whitelist_match/");
		return;
	}

	#
	# Then look for path blacklisting
	#
	my $path_blacklist_match = apply_filters($path, $xlated, $path, $filters{'path'}->{'blacklist'});
	if (defined $path_blacklist_match and $path_blacklist_match) {
		warning("$path path is blacklisted by /$path_blacklist_match/");
		quarantine($path, $xlated);
		return;
	}

	#
	# If path blacklisting has been passed, pitfile reads file content
	# and scans for patterns
	#
	my $content = load_file_content($xlated, undef);
	return unless defined $content and $content;
	
	#
	# First look for content whitelisting
	#
	my $content_whitelist_match = apply_filters($path, $xlated, $content, $filters{'content'}->{'whitelist'});
	if (defined $content_whitelist_match and $content_whitelist_match) {
		info("$path content is whitelisted by /$content_whitelist_match/");
		return;
	}

	#
	# Then look for content blacklisting
	#
	my $content_blacklist_match = apply_filters($path, $xlated, $content, $filters{'content'}->{'blacklist'});
	if (defined $content_blacklist_match and $content_blacklist_match) {
		info("$path content is blacklisted by /$content_blacklist_match/");
		quarantine($path, $xlated);
		return;
	}
}

#
# Prints usage message and exits
#
sub usage {
	my ($msg) = @_;
	print STDERR "\n";
	print STDERR " $msg\n";
	print STDERR " Usage: $0 <repository> <mountpoint>\n";
	print STDERR "\n";
	exit (1);
}

#
# Call Fuse
#
Fuse::main(
	mountpoint	=> $mountpoint,
	threaded	=> 0,

	#
	# Fuse operations
	#
	getattr		=> "main::getattr",
	readlink	=> "main::readlink",
	mknod		=> "main::mknod",
	mkdir		=> "main::mkdir",
	unlink		=> "main::unlink",
	rmdir		=> "main::rmdir",
	symlink		=> "main::symlink",
	link		=> "main::link",
	rename		=> "main::rename",
	chmod		=> "main::chmod",
	chown		=> "main::chown",
	truncate	=> "main::truncate",
	utime		=> "main::utime",
	open		=> "main::open",
	read		=> "main::read",
	write		=> "main::write",
	statfs		=> "main::statfs",
	flush		=> "main::flush",
	release		=> "main::release",
	fsync		=> "main::fsync",
	# setxattr	=> "main::setxattr",
	# getxattr	=> "main::getxattr",
	# listxattr	=> "main::listxattr",
	# removexattr	=> "main::removexattr",
	opendir		=> "main::opendir",
	readdir		=> "main::readdir",
	releasedir	=> "main::releasedir",
	# fsyncdir	=> "main::fsyncdir",
	init		=> "main::init",
	destroy		=> "main::destroy",
	# access		=> "main::access",
	create		=> "main::create",
	# ftruncate	=> "main::ftruncate",
	# fgetattr	=> "main::fgetattr",
	# lock		=> "main::lock",
	# utimens		=> "main::utimens",
);

__DATA__
#
# This is a template for .pitfilerc
# Customize it to fit your needs
#

#
# %config holds some context values
#
our %config = (
	#
	# The email address to be contacted
	#
    mail_recipient => 'nobody@example.com',
    
    #
    # The max size of the content excerpt sent by email, in bytes
    #
    file_excerpt_size => 10 * 1024,
);

#
# %filters holds a set of regular expression patterns to
# be matched against newly created files to guess if
# quarantine is required or not. The section 'content'
# applies to file contents while 'path' applies to file
# paths. Each section is further divided into 'whitelist'
# (if matches the file is accepted) and 'blacklist' (if
# a match is found the file in immediately quarantined).
# Each pattern can be associated to an anonymous function
# which is called on match. Functions receive two values:
# $path, the relative file path, and $xlated, the absolute
# file path
#
our %filters = (
    content => {
    	#
    	# When a pattern matches the file content, 
    	# the file is accepted without any further checking;
    	# if the pattern has an associated subroutine, it's called
    	#
        whitelist => [
            q|^<\?php die\("Access Denied"\);| => undef,
        ],

		#
    	# When a pattern matches the file content, 
    	# the file is immediately quarantined
    	# if the pattern has an associated subroutine, it's called
		#
        blacklist => [
            q|<\?php| => sub {
                my ($path, $xlated) = @_;
                warning("PHP code upload detected on $path ($xlated)!");
            },

            q|eval\(| => sub {
                my ($path, $xlated) = @_;
                warning("File $path is PHP code calling eval()");
            },

            q|base64\(| => sub {
                my ($path, $xlated) = @_;
                warning("File $path is PHP code calling base64()");
            },

            q|gzip_inflate\(| => sub {
                my ($path, $xlated) = @_;
                warning("File $path is PHP code calling gzip_inflate()");
            },
        ],
    },

    path => {
   		#
    	# When a pattern matches the file path, 
    	# the file is accepted without any further checking
    	# if the pattern has an associated subroutine, it's called
		#
        whitelist => [
        ],

   		#
    	# When a pattern matches the file path, 
    	# the file is immediately quarantined
    	# if the pattern has an associated subroutine, it's called
		#
        blacklist => [
        ],
    },
);

# vim:syntax=perl
