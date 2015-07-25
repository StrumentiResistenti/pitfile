# Pitfile

Pitfile is a *filesystem wrapper* written in Perl with FUSE. It's intended to add a
layer on top of a web server filesystem to trap illegal or suspicious activities,
like file uploads, and put new files into a quarantine area, if found positive to
some checks.
