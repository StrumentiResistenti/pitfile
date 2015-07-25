#!/usr/bin/perl

use strict;
use warnings;

use Fuse;
use POSIX qw(EIO ENOTDIR ENOENT ENOSYS EEXIST EPERM O_RDONLY O_WRONLY O_RDWR O_APPEND O_CREAT setsid);
use Fcntl qw(S_ISBLK S_ISCHR S_ISFIFO SEEK_SET S_ISREG S_ISFIFO S_IMODE S_ISCHR S_ISBLK S_ISSOCK S_IWUSR S_IWGRP S_IWOTH S_ISDIR S_ISLNK);
use Unix::Mknod;
use Logger::Syslog;
use Digest::SHA qw(sha1_hex);

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
# Configuration profile
#
my %config = (
	uid => 3333,
	gid => 3333,
);

#
# Get the repository
#
my $repository = $ARGV[0];
die "No repository provided" unless defined $repository and $repository;

#
# Get the mountpoint
#
my $mountpoint = $ARGV[1];
die "No mountpoint provided" unless defined $mountpoint and $mountpoint;

#
# Create the quarantine area
#
my $quarantine_area = $repository;
$quarantine_area =~ s#/+$##;
$quarantine_area .= ".quarantine";
unless (-d $quarantine_area) {
	mkdir ($quarantine_area, 0700) || die "Can't create quarantine area: $quarantine_area";
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
# Translate any path to the corresponding repository path
#
sub xlate {
	my $path = shift() || return "";
	if ($path =~ /^$repository/) { return $path; }
	my $xlated = "$repository/$path";
	$xlated =~ s#/+#/#g;
	return $xlated;
}

#
# Return the stat() equivalent set of metadata about a path,
# applying some transformations in the while
#
sub getattr {
	my ($path) = @_;
	my @result = lstat(xlate($path));
	if ($#result == 0) {
		debug("OP: getattr($path) -> FAILED!") if $loglevel >= 4;
		return @result;
	}

	unless (defined $result[2]) {
		debug("OP: getattr($path) -> FAILED!") if $loglevel >= 4;
		return @result;
	}

	my $size = $result[7];
	my $type = S_ISDIR($result[2]) ? "DIR" : S_ISLNK($result[2]) ? "LINK" : "FILE";
	debug("OP: getattr($path) -> [$type] $size bytes") if $loglevel >= 4;
	return @result;
}

sub readlink {
	my ($path) = @_;
	my $result = readlink(xlate($path));
	debug("OP: readlink($path) -> $result") if $loglevel >= 4;
	return $result;
}

sub mknod {
	my ($path, $mode, $dev) = @_;
	my $xlated = xlate($path);

	# since this is called for ALL files, not just devices, I'll do some checks
	# and possibly run the real mknod command.

	if (S_ISREG($mode)) {
		open(FILE, '>', $xlated) || return -$!;
		print FILE '';
		close(FILE);
		chmod S_IMODE($mode), $xlated;
		debug("OP: mknod($path, $mode, $dev) -> 0") if $loglevel >= 4;
		return 0;
	}

	if (S_ISFIFO($mode)) {
		my ($rv) = POSIX::mkfifo($xlated, S_IMODE($mode));
		my $result = $rv ? 0 : -POSIX::errno();
		debug("OP: mknod($path, $mode, $dev) -> $result") if $loglevel >= 4;
		return $result;
	}

	if (S_ISCHR($mode) || S_ISBLK($mode)) {
		if($has_mknod){
			Unix::Mknod::mknod($xlated, $mode, $dev);
			my $result = -$!;
			debug("OP: mknod($path, $mode, $dev) -> $result") if $loglevel >= 4;
			return $result;
		} else {
			my $result = -POSIX::errno();
			debug("OP: mknod($path, $mode, $dev) -> $result") if $loglevel >= 4;
			return $result;
		}
	}

	# S_ISSOCK maybe should be handled; however, for our test it should
	# not really matter.
	my $result = -&ENOSYS;
	debug("OP: mknod($path, $mode, $dev) -> $result") if $loglevel >= 4;
	return $result;
}

sub mkdir {
	my ($path, $mode) = @_;
	my $result = mkdir(xlate($path), $mode);
	debug("OP: mkdir($path, $mode) -> $result") if $loglevel >= 4;
	return $result;
}

sub unlink {
	my ($path) = @_;
	my $result = unlink(xlate($path));
	debug("OP: unlink($path) -> $result") if $loglevel >= 4;
	return $result;
}

sub rmdir {
	my ($path) = @_;
	my $result = rmdir(xlate($path));
	debug("OP: rmdir($path) -> $result") if $loglevel >= 4;
	return $result;
}

sub symlink {
	my ($from, $to) = @_;
	my $result = symlink(xlate($from), xlate($to));
	debug("OP: symlink($from, $to) -> $result") if $loglevel >= 4;
	return $result;
}

sub link {
	my ($from, $to) = @_;
	my $result = link(xlate($from), xlate($to));
	debug("OP: link($from, $to) -> $result") if $loglevel >= 4;
	return $result;
}

sub rename {
	my ($from, $to) = @_;
	my $result = rename(xlate($from), xlate($to));
	debug("OP: rename($from, $to) -> $result") if $loglevel >= 4;
	return $result;
}

sub chmod {
	my ($path, $mode) = @_;
	my $result = chmod(xlate($path), $mode);
	warning("OP: chmod($path, $mode) -> $result") if $loglevel >= 2;
	return $result;
}

sub chown {
	my ($path, $uid, $gid) = @_;
	my $result = chown(xlate($path), $uid, $gid);
	warning("OP: chown($path, $uid, $gid) -> $result") if $loglevel >= 2;
	return $result;
}

sub truncate {
	my ($path, $offset) = @_;

	my $res = truncate(xlate($path), $offset);
	my $result = defined $res ? 0 : -1 * EIO;
	debug("OP: truncate($path, $offset) -> $result") if $loglevel >= 4;
	return $result;
}

sub utime {
	my ($path, $actime, $modtime) = @_;
	my $result = utime(xlate($path), $actime, $modtime);
	debug("OP: utime($path, $actime, $modtime) -> $result") if $loglevel >= 4;
	return $result;
}

sub open {
	my ($path, $flags, $fileinfo) = @_;
	my $filehandle = POSIX::open(xlate($path), $flags);

	if (defined $filehandle and $filehandle) {
		debug("OP: open($path, $flags, <fileinfo> -> 0") if $loglevel >= 4;
		return (0, $filehandle);
	} else {
		my $result = -POSIX::errno();
		debug("OP: open($path, $flags, <fileinfo> -> $result") if $loglevel >= 4;
		return $result;
	}
}

sub create {
	my ($path, $flags, $fileinfo) = @_;
	my $filehandle = POSIX::creat(xlate($path), $flags);

	if (defined $filehandle and $filehandle) {
		debug("OP: create($path, $flags, <fileinfo> -> 0") if $loglevel >= 4;
		return (0, $filehandle);
	} else {
		my $result = -POSIX::errno();
		debug("OP: create($path, $flags, <fileinfo> -> $result") if $loglevel >= 4;
		return $result;
	}
}

sub read {
	my ($path, $size, $offset, $filehandle) = @_;

	my $buffer;

	unless (defined $filehandle and $filehandle) {
		$filehandle = POSIX::open(xlate($path), &POSIX::O_RDONLY);

		unless (defined $filehandle and $filehandle) {
			my $result = -POSIX::errno();
			debug("OP: read($path, $size, $offset, $filehandle) -> $result") if $loglevel >= 4;
			return $result;
		}
	}

	my $res = POSIX::lseek($filehandle, $offset, &POSIX::SEEK_SET);
	unless (defined $res) {
		my $result = -POSIX::errno();
		debug("OP: read($path, $size, $offset, $filehandle) -> $result") if $loglevel >= 4;
		return $result;
	}

	$res = POSIX::read($filehandle, $buffer, $size);
	unless (defined $res) {
		my $result = -1 * EIO;
		debug("OP: read($path, $size, $offset, $filehandle) -> $result") if $loglevel >= 4;
		return $result;
	}

	debug("OP: read($path, $size, $offset, $filehandle) -> 0 (" . length($buffer) . " bytes)") if $loglevel >= 4;
	return $buffer;
}

sub write {
	my ($path, $buffer, $offset, $filehandle) = @_;

	unless (defined $filehandle and $filehandle) {
		$filehandle = POSIX::open(xlate($path), &POSIX::O_WRONLY);
		unless (defined $filehandle and $filehandle) {
			my $result = -POSIX::errno();
			debug("OP: write($path, $buffer, $offset, <filehanlde>) -> $result") if $loglevel >= 4;
			return $result;
		}
	}

	my $res = POSIX::lseek($filehandle, $offset, &POSIX::SEEK_SET);
	unless (defined $res) {
		my $result = -POSIX::errno();
		debug("OP: write($path, $buffer, $offset, <filehanlde>) -> $result") if $loglevel >= 4;
		return $result;
	}

	$res = POSIX::write($filehandle, $buffer, length($buffer));
	unless (defined $res) {
		my $result = -POSIX::errno();
		debug("OP: write($path, $buffer, $offset, <filehanlde>) -> $result") if $loglevel >= 4;
		return $result;
	}

	debug("OP: write($path, $buffer, $offset, <filehanlde>) -> 0 ($res bytes)") if $loglevel >= 4;
	return $res;
}

sub statfs {
	my ($path) = @_;
	debug("OP: statfs($path)") if $loglevel >= 4;
}

sub flush {
	my ($path, $filehandle) = @_;
	debug("OP: flush($path, <filehandle>)") if $loglevel >= 4;

	return 0;
}

sub release {
	my ($path, $flags, $filehandle, $flock_flag, $lock_owner) = @_;

	if (defined $filehandle and $filehandle) {
		my $res = POSIX::close($filehandle);
		unless (defined $res) {
			my $result = -POSIX::errno();
			debug("OP: release($path, ...) -> $result") if $loglevel >= 4;
			return $result;
		}
	}

	if ($flags & O_WRONLY || $flags & O_RDWR) {
		analyze(xlate($path));
	}

	debug("OP: release($path, ...) -> 0") if $loglevel >= 4;
	return 0;
}

sub opendir {
	my ($path) = @_;

	my $dirhandle = POSIX::opendir(xlate($path));
	unless (defined $dirhandle) {
		my $result = -1 * EIO;
		debug("OP: opendir($path) -> $result") if $loglevel >= 4;
		return $result;
	}

	debug("OP: opendir($path) -> 0") if $loglevel >= 4;
	return (0, $dirhandle);
}

sub readdir {
	my ($path, $offset, $dirhandle) = @_;

	unless (defined $dirhandle and $dirhandle) {
		$dirhandle = POSIX::opendir(xlate($path)) unless defined $dirhandle and $dirhandle;
		unless (defined $dirhandle and $dirhandle) {
			my $result = -POSIX::errno();
			debug("OP: readdir($path, $offset, <dirhandle>) -> $result") if $loglevel >= 4;
			return $result;
		}
	}

	my @entries = POSIX::readdir($dirhandle);
	push @entries, 0;

	debug("OP: readdir($path, $offset, <dirhandle>) -> 0 (" . $#entries . " entries)") if $loglevel >= 4;
	return @entries;
}

sub releasedir {
	my ($path, $filehandle) = @_;

	if (defined $filehandle and $filehandle) {
		my $res = POSIX::closedir($filehandle);
		unless (defined $res and $res) {
			my $result = -1 * EIO;
			debug("OP: releasedir($path) -> $result") if $loglevel >= 4;
			return $result;
		}
	}

	debug("OP: releasedir($path) -> 0") if $loglevel >= 4;
	return 0;
}

sub init {
	# logger_init();
	logger_prefix('pitfile: ');
	logger_set_default_facility("auth");
	debug("OP: init") if $loglevel >= 4;
}

sub destroy {
	debug("OP: destroy") if $loglevel >= 4;
}

sub analyze {
	my ($path) = @_;
	info("Analyzing $path");

	my $xlated = xlate($path);
	if (CORE::open(IN, "$xlated")) {
		my $file = "";
		while (<IN>) { $file .= $_; }
		close(IN);

		my $quarantined = 0;

		#
		# Do not quarantine cache and session files created by joomla
		#
		return if $file =~ /^<?php die("Access Denied");/;

		if ($file =~ /<\?php/)			{ warning("PHP upload detected on $xlated!");	$quarantined++; }
		if ($file =~ /eval\(/)			{ warning("File matches eval");					$quarantined++; }
		if ($file =~ /base64\(/)		{ warning("File matches base64");				$quarantined++; }
		if ($file =~ /gzip_inflate\(/)	{ warning("File matches gzip_inflate");			$quarantined++; }

		if ($quarantined) {
			my $sha1 = sha1_hex($path);
			CORE::rename($xlated, "$quarantine_area/$sha1");
			warning("File quarantined as $quarantine_area/$sha1");
		}
	}
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

