# Welcome to apt2sbom

This package contains a library and a CLI tool to convert a Ubuntu
software package inventory to a software bill of materials.  You are
in the wrong place if you are not running Ubuntu.

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

    % apt2sbom (--json|--yaml|--cyclonedx [--pip])

Will produce either JSON or YAML forms of an SPDX file, or the JSON form of a CycloneDX file . There is no default.  Pick one.

To include python packages, add --pip.

There is also a werkzeug interface so that an SBOM file can be
delivered via HTTP.  To use, create a simple wsgi file as follows:

    from apt2sbom.wsbom import app as application  
    application = create_app(\_name\_)


and call that file from your httpd. An apache example follows:

    WSGIScriptAlias /.well-known/sbom /usr/lib/cgi-bin/sbom.wsgi
    WSGIPassAuthorization On

There is a configuration file: /etc/sbom.conf

It is in the form of a JSON object.  It currently has the following
parameters and defaults as follows:

    {
       "do_auth": true,  # otherwise don't auth
       "passwd_file": "/etc/sbom.users",  # where to find the passwds
       "include_pip": false, # pip results take a long time
       "pregen_file": null # only open and read this file; otherwise gen.
    }

Note- don't put comments in.  (ToDo)

When this is done, a very simple password file is expected by default
in /etc/sbom.users:

    {
       "user" : "password",
       "otheruser" : "otherpassword",
        ...
    }

The passwords aren't hashed.  This is clearly something that has to
be addressed in the future.

The type of SBOM returned depends on the Accepts: header sent.
