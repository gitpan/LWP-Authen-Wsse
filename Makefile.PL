#!/usr/bin/env perl
# $File: /member/local/autrijus/Win32-Exe/Makefile.PL $ $Author: autrijus $
# $Revision: #6 $ $Change: 1505 $ $Date: 2004-02-17T15:40:29.640821Z $

use inc::Module::Install;

name		('LWP-Authen-Wsse');
author		('Autrijus Tang <autrijus@autrijus.org>');
abstract	('Library for enabling X-WSSE authentication in LWP');
license		('perl');
version_from	('lib/LWP/Authen/Wsse.pm');

requires	(
    'LWP'	    => 0,
    'Digest::SHA1'  => 0,
    'MIME::Base64'  => 0,
);

WriteAll( sign => 1 );
