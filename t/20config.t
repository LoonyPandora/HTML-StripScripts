
use strict;
use Test::More tests => 16;

BEGIN { $^W = 1 }

use HTML::StripScripts;
my $f = HTML::StripScripts->new;

$f->input_start_document;
$f->input_start('<p>');
$f->input_text('foo');
$f->input_end_document;
is( $f->filtered_document, '<p>foo</p>', 'default context is Flow' );

$f = HTML::StripScripts->new({ Context => 'Flow' });
$f->input_start_document;
$f->input_start('<p>');
$f->input_text('foo');
$f->input_end_document;
is( $f->filtered_document, '<p>foo</p>', 'context Flow' );

$f = HTML::StripScripts->new({ Context => 'Inline' });
$f->input_start_document;
$f->input_start('<p>');
$f->input_start('<i>');
$f->input_text('foo');
$f->input_end_document;
is( $f->filtered_document, '<!--filtered--><i>foo</i>', 'context Inline' );

$f = HTML::StripScripts->new({ Context => 'NoTags' });
$f->input_start_document;
$f->input_start('<p>');
$f->input_start('<i>');
$f->input_text('foo');
$f->input_end_document;
is( $f->filtered_document, '<!--filtered--><!--filtered-->foo', 'context NoTags' );

$f = HTML::StripScripts->new({ Context => 'Document' });
$f->input_start_document;
$f->input_start('<html>');
$f->input_start('<body>');
$f->input_start('<p>');
$f->input_text('foo');
$f->input_end_document;
is( $f->filtered_document, '<html><body><p>foo</p></body></html>', 'context Document' );

$f->input_start_document;
$f->input_text('foo');
$f->input_end_document;
is( $f->filtered_document, '<html><body>foo</body></html>', 'context Document both' );

$f->input_start_document;
$f->input_start('<body>');
$f->input_text('foo');
$f->input_end_document;
is( $f->filtered_document, '<html><body>foo</body></html>', 'context Document html' );

$f = HTML::StripScripts->new({ BanList => {'i' => 1, 'p' => 1} });
$f->input_start_document;
$f->input_start('<p>');
$f->input_text('foo');
$f->input_start('</p>');
$f->input_start('<hr>');
$f->input_start('<b>');
$f->input_start('<i>');
$f->input_text('bar');
$f->input_end_document;
is( $f->filtered_document,
    '<!--filtered-->foo<!--filtered--><hr /><b><!--filtered-->bar</b>',
    'BanList takes effect' );

$f = HTML::StripScripts->new({ BanAllBut => [qw(i hr)] });
$f->input_start_document;
$f->input_start('<p>');
$f->input_text('foo');
$f->input_start('</p>');
$f->input_start('<hr>');
$f->input_start('<b>');
$f->input_start('<i>');
$f->input_text('bar');
$f->input_end_document;
is( $f->filtered_document,
    '<!--filtered-->foo<!--filtered--><hr /><!--filtered--><i>bar</i>',
    'BanAllBut takes effect' );

$f = HTML::StripScripts->new({ BanList   => {'i' => 1, 'p' => 1},
                            BanAllBut => [qw(i hr)]            });
$f->input_start_document;
$f->input_start('<p>');
$f->input_text('foo');
$f->input_start('</p>');
$f->input_start('<hr>');
$f->input_start('<b>');
$f->input_start('<i>');
$f->input_text('bar');
$f->input_end_document;
is( $f->filtered_document,
    '<!--filtered-->foo<!--filtered--><hr /><!--filtered--><!--filtered-->bar',
    'BanList beats BanAllBut' );

$f = HTML::StripScripts->new;
$f->input_start_document;
$f->input_start('<img src="http://www.example.com/img.png" />');
$f->input_end_document;
is( $f->filtered_document, '<img />', 'AllowSrc defaults to no' );

$f = HTML::StripScripts->new({ AllowSrc => 1 });
$f->input_start_document;
$f->input_start('<img src="http://www.example.com/img.png" />');
$f->input_end_document;
is( $f->filtered_document, '<img src="http://www.example.com/img.png" />', 'AllowSrc yes' );

$f = HTML::StripScripts->new({ AllowSrc => 1 });
$f->input_start_document;
$f->input_start('<img src="javascript:alert(31337)" />');
$f->input_end_document;
is( $f->filtered_document, '<img />', 'AllowSrc checks URL' );

$f = HTML::StripScripts->new;
$f->input_start_document;
$f->input_start('<a href="http://www.example.com/img.png">');
$f->input_text('foo');
$f->input_end_document;
is( $f->filtered_document, '<a>foo</a>', 'AllowHref defaults to no' );

$f = HTML::StripScripts->new({ AllowHref => 1 });
$f->input_start_document;
$f->input_start('<a href="http://www.example.com/img.png">');
$f->input_text('foo');
$f->input_end_document;
is( $f->filtered_document, '<a href="http://www.example.com/img.png">foo</a>', 'AllowHref yes' );

$f = HTML::StripScripts->new({ AllowHref => 1 });
$f->input_start_document;
$f->input_start('<a href="javascript:alert(31337)">');
$f->input_text('foo');
$f->input_end_document;
is( $f->filtered_document, '<a>foo</a>', 'AllowHref checks URL' );

