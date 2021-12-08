# Welcome to apt2sbom

This package contains a library and a CLI tool to convert a Ubuntu
software package inventory to an SPDX file.  You are in the wrong
place if you are not running Ubuntu.

The package is under active development.  Don't be surprised if
something doesn't work quite right.  please see CONTRIBUTING.md for
details.

## Building

Building is easy:

1. Bop the version on setup.cfg
2. python3 -m build -w
3. cd dist
4. pip3 install that file

Do this, of course, on a Ubuntu system.

## Usage

To use the CLI tool:

% apt2sbom (--json|--yaml)

Will produce either JSON or YAML forms of an SPDX file. There is no
default.  Pick one.

There is also a werkzeug interface so that an SPDX file can be
delivered via HTTP.  To use, create a simple wsgi file as follows:

> from apt2sbom.wsbom import app as application
>
> # application = create_app(_name_)

and call that file from your httpd. An apache example follows:

 > WSGIScriptAlias /.well-known/sbom /usr/lib/cgi-bin/sbom.wsgi
 > WSGIPassAuthorization On

When this is done, a very simple password file is expected in
/etc/sbom.users:

{
  "user" : "password",
  "otheruser" : "otherpassword",
  ...
}

The passwords aren't hashed.  This is clearly something that has to
be addressed in the future.

