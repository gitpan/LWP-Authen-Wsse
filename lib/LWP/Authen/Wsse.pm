package LWP::Authen::Wsse;
$LWP::Authen::Wsse::VERSION = '0.03';

use strict;
use Digest::SHA1 ();
use MIME::Base64 ();

=head1 NAME

LWP::Authen::Wsse - Library for enabling X-WSSE authentication in LWP

=head1 VERSION

This document describes version 0.03 of LWP::Authen::Wsse, released
June 2, 2004.

=head1 SYNOPSIS

    use LWP::UserAgent;
    use HTTP::Request::Common;
    my $url = 'http://www.example.org/protected_page.html';

    # Set up the WSSE client
    my $ua = LWP::UserAgent->new;
    $ua->credentials('example.org', '', 'username', 'password');

    $request = GET $url;
    print "--Performing request now...-----------\n";
    $response = $ua->request($request);
    print "--Done with request-------------------\n";

    if ($response->is_success) {
        print "It worked!->", $response->code, "\n";
    }
    else {
        print "It didn't work!->", $response->code, "\n";
    }

=head1 DESCRIPTION

C<LWP::Authen::Wsse> allows LWP to authenticate against servers that are using
the C<X-WSSE> authentication scheme, as required by the Atom Authentication API.

The module is used indirectly through LWP, rather than including it directly in
your code.  The LWP system will invoke the WSSE authentication when it
encounters the authentication scheme while attempting to retrieve a URL from a
server.

You also need to set the credentials on the UserAgent object like this:

   $ua->credentials('www.company.com:80', '', "username", "password");

Alternatively, you may also subclass B<LWP::UserAgent> and override the 
C<get_basic_credentials()> method.  See L<LWP::UserAgent> for more details.

=cut

sub authenticate {
    my ($class, $ua, $proxy, $auth_param, $response,
       $request, $arg, $size) = @_;

    my ($user, $pass) = $ua->get_basic_credentials(
        $auth_param->{realm},
        $request->url,
        $proxy,
    );

    return $response unless (defined $user and defined $pass);

    my $now = $class->now_w3cdtf;
    my $nonce = $class->make_nonce;
    my $nonce_enc = MIME::Base64::encode_base64($nonce, '');
    my $digest = MIME::Base64::encode_base64(
        Digest::SHA1::sha1($nonce . $now . $pass), ''
    );

    my $auth_header = ($proxy ? 'Proxy-Authorization' : 'Authorization');
    my $wsse_value = 'UsernameToken ' . join(
        ', ',
        qq(Username="$user"),
        qq(PasswordDigest="$digest"),
        qq(Nonce="$nonce_enc"),
        qq(Created="$now"),
    );

    my $referral = $request->clone;

    # Need to check this isn't a repeated fail!
    my $r = $response;
    my $failed;
    while ($r) {
        my $prev = $r->request->{wsse_user_pass};
        if ($r->code == 401
            and $prev
            and $prev->[0] eq $user
            and $prev->[1] eq $pass
            and $failed++
        ) {
            # here we know this failed before
            $response->header(
                'Client-Warning' => "Credentials for '$user' failed before"
            );
            return $response;
        }
        $r = $r->previous;
    }

    $referral->header($auth_header => 'WSSE profile="UsernameToken"');
    $referral->header('X-WSSE' => $wsse_value);

    $referral->{wsse_user_pass} = [$user, $pass];

    return $ua->request($referral, $arg, $size, $response);
}

sub make_nonce {
    return Digest::SHA1::sha1(Digest::SHA1::sha1(time() . {} . rand() . $$));
}

sub now_w3cdtf {
    my ($sec, $min, $hour, $mday, $mon, $year) = gmtime();
    $mon++; $year += 1900;

    return sprintf(
        "%02s-%02s-%02sT%02s:%02s:%02sZ",
        $year, $mon, $mday, $hour, $min, $sec,
    );
}


1;

=head1 SEE ALSO

L<LWP>, L<LWP::UserAgent>, L<lwpcook>.

=head1 AUTHORS

Autrijus Tang E<lt>autrijus@autrijus.orgE<gt>

=head1 COPYRIGHT

Copyright 2004 by Autrijus Tang E<lt>autrijus@autrijus.orgE<gt>.

This program is free software; you can redistribute it and/or 
modify it under the same terms as Perl itself.

See L<http://www.perl.com/perl/misc/Artistic.html>

=cut
