# Pitfile

Pitfile is a *filesystem wrapper* written in Perl with FUSE. It's intended to add a
layer between a web server and its filesystem to trap illegal or suspicious activities,
like file uploads, and put new files into a quarantine area, if found positive to
some checks.

When malicious contents are uploaded on a server, the damage is almost done. The
attacker can later easily invoke the uploded file to perform undesirable actions.
Using restrictive permissions on disk or using restriction frameworks (like Suhosin
for PHP) can prevent even legit use cases. Pitfile tries to solve this drawbacks
without loosing too much server security.

The idea behind pitfile is very simple: place some checking logic inside the filesystem.
After a file is created, pitfile performs some customizable checks on it. If its
name is suspect or its content reveal malicious intentions, the file is quarantined,
an entry is reported in the logs and the administrator is warned by email. The uploader
can't any longer invoke the file or use its contents.

Pitfile is still an experimental project and is not indended for heavily loaded
public servers. Pitfile is written in Perl and requires a small number of external
modules to run:

 * Fuse
 * POSIX
 * Fcntl
 * Unix::Mknod
 * Logger::Syslog
 * Digest::SHA
 * Mail::Sendmail

It use is really simple. If the actual server contents are located in `/srv/original_content`,
mount pitfile like this:

    # pitfile.pl /srv/original_content /srv/mount_point

then configure your server (apache2, proftpd, ...) to point `/srv/mount_point`. Pitfile
will deliver its filtering capabilities out of the box. To customize the checks
executed on uploaded files, edit `/srv/original_content/.pitfilerc`; a template 
is provided when the repository is mounted for the first time:

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
       mail_recipient => 'admin@example.com',
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
