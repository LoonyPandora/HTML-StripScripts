package HTML::StripScripts;
use strict;

use vars qw($VERSION);
$VERSION = '0.03';

=head1 NAME

HTML::StripScripts - strip scripting constructs out of HTML

=head1 SYNOPSIS

  use HTML::StripScripts;

  my $hss = HTML::StripScripts->new({ Context => 'Inline' });

  $hss->input_start_document;

  $hss->input_start('<i>');
  $hss->input_text('hello, world!');
  $hss->input_end('</i>');

  $hss->input_end_document;

  print $hss->filtered_document;

=head1 DESCRIPTION

This module strips scripting constructs out of HTML, leaving as
much non-scripting markup in place as possible.  This allows web
applications to display HTML originating from an untrusted source
without introducing XSS (cross site scripting) vulnerabilities.

The process is based on whitelists of tags, attributes and attribute
values.  This approach is the most secure against disguised scripting
constructs hidden in malicious HTML documents.

As well as removing scripting constructs, this module ensures that
there is a matching end for each start tag, and that the tags are
properly nested.

The HTML document must be parsed into start tags, end tags and
text before it can be filtered by this module.  Use either
L<HTML::StripScripts::Parser> or L<HTML::StripScripts::Regex> instead
if you want to input an unparsed HTML document.

=head1 CONSTRUCTORS

=over

=item new ( CONFIG )

Creates a new C<HTML::StripScripts> filter object, bound to a
particular filtering policy.  If present, the CONFIG parameter
must be a hashref.  The following keys are recognized (unrecognized
keys will be silently ignored).

=over

=item C<Context>

A string specifying the context in which the filtered document
will be used.  This influences the set of tags that will be
allowed.

If present, the C<Context> value must be one of:

=over

=item C<Document>

If C<Context> is C<Document> then the filter will allow a full
HTML document, including the C<HTML> tag and C<HEAD> and C<BODY>
sections.

=item C<Flow>

If C<Context> is C<Flow> then most of the cosmetic tags that one
would expect to find in a document body are allowed, including
lists and tables but not including forms.

=item C<Inline>

If C<Context> is C<Inline> then only inline tags such as C<B>
and C<FONT> are allowed.

=item C<NoTags>

If C<Context> is C<NoTags> then no tags are allowed.

=back

The default C<Context> value is C<Flow>.

=item C<BanList>

If present, this option must be a hashref.  Any tag that would normally
be allowed (because it presents no XSS hazard) will be blocked if the
lowercase name of the tag is a key in this hash.

For example, in a guestbook application where C<HR> tags are used to
separate posts, you may wish to prevent posts from including C<HR>
tags, even though C<HR> is not an XSS risk.

=item C<BanAllBut>

If present, this option must be reference to an array holding a list of
lowercase tag names.  This has the effect of adding all but the listed
tags to the ban list, so that only those tags listed will be allowed.

=item C<AllowSrc>

By default, the filter won't allow constructs that cause the browser to
fetch things automatically, such as C<SRC> attributes in C<IMG> tags.
If this option is present and true then those constructs will be
allowed.

=item C<AllowHref>

By default, the filter won't allow constructs that cause the browser to
fetch things if the user clicks on something, such as the C<HREF>
attribute in C<A> tags.  Set this option to a true value to allow this
type of construct.

=item C<AllowRelURL>

By default, the filter won't allow relative URLs such as C<../foo.html>
in C<SRC> and C<HREF> attribute values.  Set this option to a true value
to allow them.

=back

=cut

sub new {
    my ($pkg, $cfg) = @_;

    my $self = bless {}, ref $pkg || $pkg;
    $self->hss_init($cfg);
    return $self;
}

sub hss_init {
    my ($self, $cfg) = @_;
    $cfg ||= {};

    $self->{_hssCfg} = $cfg;

    $self->{_hssContext} = $self->init_context_whitelist;
    $self->{_hssAttrib}  = $self->init_attrib_whitelist;
    $self->{_hssAttVal}  = $self->init_attval_whitelist;
    $self->{_hssStyle}   = $self->init_style_whitelist;
    $self->{_hssDeInter} = $self->init_deinter_whitelist;

    $self->{_hssBanList} = $cfg->{BanList} || {};
    if ( $cfg->{BanAllBut} ) {
        my %ban = map {$_ => 1} keys %{ $self->{_hssAttrib} };
        foreach my $dontban (@{ $cfg->{BanAllBut} }) {
            delete $ban{$dontban} unless $self->{_hssBanList}{$dontban};
        }
        $self->{_hssBanList} = \%ban;
    }
}

=back

=head1 METHODS

This class provides the following methods:

=over

=item input_start_document ()

This method initializes the filter, and must be called once before
starting on each HTML document to be filtered.

=cut

sub input_start_document {
    my ($self, $context) = @_;

    $self->{_hssStack} = [{
        NAME => '',
        FULL => '',
        CTX  => $self->{_hssCfg}{Context} || 'Flow',
    }];
    $self->{_hssOutput} = '';

    $self->output_start_document;
}

=item input_start ( TEXT )

Handles a start tag from the input document.  TEXT must be the
full text of the tag, including angle-brackets.

=cut

sub input_start {
    my ($self, $text) = @_;

    $self->_hss_accept_input_start($text) or $self->reject_start($text);
}

sub _hss_accept_input_start {
    my ($self, $text) = @_;

    return 0 unless $text =~ m|^<([a-zA-Z0-9]+)\b(.*)>$|m;
    my ($tag, $attr) = (lc $1, $self->strip_nonprintable($2));

    return 0 if $self->{_hssSkipToEnd};
    if ($tag eq 'script' or $tag eq 'style') {
        $self->{_hssSkipToEnd} = $tag;
	return 0;
    }

    return 0 if $self->_hss_tag_is_banned($tag);

    my $allowed_attr = $self->{_hssAttrib}{$tag};
    return 0 unless defined $allowed_attr;

    return 0 unless $self->_hss_get_to_valid_context($tag);

    my $filtered_attr = '';
    while ($attr =~ s#^\s*(\w+)(?:\s*=\s*(?:([^"'>\s]+)|"([^"]*)"|'([^']*)'))?##) {
        my $key = lc $1;
        my $val = ( defined $2 ? $self->unquoted_to_canonical_form($2) :
                    defined $3 ? $self->quoted_to_canonical_form($3)   :
                    defined $4 ? $self->quoted_to_canonical_form($4)   :
                    ''
                  );

        my $value_class = $allowed_attr->{$key};
        next unless defined $value_class;
        my $attval_handler = $self->{_hssAttVal}{$value_class};
        next unless defined $attval_handler;

        my $filtered_value = &{ $attval_handler }($self, $tag, $key, $val);

        if (defined $filtered_value) {
            my $escaped = $self->canonical_form_to_attval($filtered_value);
            $filtered_attr .= qq| $key="$escaped"|;
        }
    }

    my $new_context =
        $self->{_hssContext}{ $self->{_hssStack}[0]{CTX} }{ $tag };

    if ($new_context eq 'EMPTY') {
        $self->output_start("<$tag$filtered_attr />");
    }
    else {
        my $html = "<$tag$filtered_attr>";
        unshift @{ $self->{_hssStack} }, {
           NAME => $tag,
           FULL => $html,
           CTX  => $new_context
        };
        $self->output_start($html);
    }

    return 1;
}

=item input_end ( TEXT )

Handles an end tag from the input document.  TEXT must be the
full text of the end tag, including angle-brackets.

=cut

sub input_end {
    my ($self, $text) = @_;

    $self->_hss_accept_input_end($text) or $self->reject_end($text);
}

sub _hss_accept_input_end {
    my ($self, $text) = @_;

    return 0 unless $text =~ m#^</(\w+)>$#;
    my $tag = lc $1;

    if ($self->{_hssSkipToEnd}) {
        if ($self->{_hssSkipToEnd} eq $tag) {
            delete $self->{_hssSkipToEnd};
        }
        return 0;
    }

    # Ignore a close without an open
    return 0 unless grep {$_->{NAME} eq $tag} @{ $self->{_hssStack} };

    # Close open tags up to the matching open
    my @close = ();
    while (scalar @{ $self->{_hssStack} } and $self->{_hssStack}[0]{NAME} ne $tag) {
        push @close, shift @{ $self->{_hssStack} };
    }
    push @close, shift @{ $self->{_hssStack} };

    foreach my $tag (@close) {
        $self->output_end('</' . $tag->{NAME} . '>');
    }

    # Reopen any we closed early if all that were closed are
    # configured to be auto de-interleaved.
    unless (grep {! $self->{_hssDeInter}{$_->{NAME}} } @close) {
        pop @close;
        unshift @{ $self->{_hssStack} }, @close;
        foreach my $reopen (reverse @close) {
            $self->output_start($reopen->{FULL});
        }
    }

    return 1;
}

=item input_text ( TEXT )

Handles some non-tag text from the input document.

=cut

sub input_text {
    my ($self, $text) = @_;

    return if $self->{_hssSkipToEnd};

    $text = $self->strip_nonprintable($text);

    if ( $text =~ /^(\s*)$/ ) {
        $self->output_text($1);
        return;
    }

    unless ( $self->_hss_get_to_valid_context('CDATA') ) {
        $self->reject_text($text);
        return;
    }

    my $filtered = $self->filter_text( $self->text_to_canonical_form($text) );
    $self->output_text( $self->canonical_form_to_text( $filtered ) );
}

=item input_process ( TEXT )

Handles a processing instruction from the input document.

=cut

sub input_process {
    my ($self, $text) = @_;

    $self->reject_process($text);
}

=item input_comment ( TEXT )

Handles an HTML comment from the input document.

=cut

sub input_comment {
    my ($self, $text) = @_;

    $self->reject_comment($text);
}

=item input_declaration ( TEXT )

Handles an declaration from the input document.

=cut

sub input_declaration {
    my ($self, $text) = @_;

    $self->reject_declaration($text);
}

=item input_end_document ()

Call this method to signal the end of the input document.

=cut

sub input_end_document {
    my ($self) = @_;

    delete $self->{_hssSkipToEnd};

    pop @{ $self->{_hssStack} };
    foreach my $leftopen (@{ $self->{_hssStack} }) {
        $self->output_end('</' . $leftopen->{NAME} . '>');
    }
    delete $self->{_hssStack};

    $self->output_end_document;
}

=item filtered_document ()

Returns the filtered document as a string.

=cut

sub filtered_document {
    my ($self) = @_;

    $self->{_hssOutput};
}

=back

=head1 SUBCLASSING

The C<HTML::StripScripts> class is subclassable.  Filter objects are plain
hashes and C<HTML::StripScripts> reserves only hash keys that start with
C<_hss>.  The filter configuration can be set up by invoking the
hss_init() method, which takes the same arguments as new().

=head1 OUTPUT METHODS

The filter outputs a stream of start tags, end tags, text, comments,
declarations and processing instructions, via the following C<output_*>
methods.  Subclasses may override these to intercept the filter output.

The default implementations of the C<output_*> methods pass the
text on to the output() method.  The default implementation of the
output() method appends the text to a string, which can be fetched with
the filtered_document() method once processing is complete.

If the output() method or the individual C<output_*> methods are
overridden in a subclass, then filtered_document() will not work in
that subclass.

=over

=item output_start_document ()

This method gets called once at the start of each HTML document passed
through the filter.  The default implementation does nothing.

=cut

sub output_start_document {}

=item output_end_document ()

This method gets called once at the end of each HTML document passed
through the filter.  The default implementation does nothing.

=cut

*output_end_document = \&output_start_document;

=item output_start ( TEXT )

This method is used to output a filtered start tag.

=cut

sub output_start          { $_[0]->output($_[1]) }

=item output_end ( TEXT )

This method is used to output a filtered end tag.

=cut

*output_end = \&output_start;

=item output_text ( TEXT )

This method is used to output some filtered non-tag text.

=cut

*output_text = \&output_start;

=item output_declaration ( TEXT )

This method is used to output a filtered declaration.

=cut

*output_declaration = \&output_start;

=item output_comment ( TEXT )

This method is used to output a filtered HTML comment.

=cut

*output_comment = \&output_start;

=item output_process ( TEXT )

This method is used to output a filtered processing instruction.

=cut

*output_process = \&output_start;

=item output ( TEXT )

This method is invoked by all of the default C<output_*> methods.  The
default implementation appends the text to the string that the
filtered_document() method will return.

=cut

sub output {
    my ($self, $text) = @_;

    $self->{_hssOutput} .= $text;
}

=back

=head1 REJECT METHODS

When the filter encounters something in the input document which it
cannot transform into an acceptable construct, it invokes one of
the following C<reject_*> methods to put something in the output
document to take the place of the unacceptable construct.

The TEXT parameter is the full text of the unacceptable construct.

The default implementations of these methods output an HTML comment
containing the text C<filtered>.

Subclasses may override these methods, but should exercise caution.
The TEXT parameter is unfiltered input and may contain malicious
constructs.

=over

=item reject_start ( TEXT )

=item reject_end ( TEXT )

=item reject_text ( TEXT )

=item reject_declaration ( TEXT )

=item reject_comment ( TEXT )

=item reject_process ( TEXT )

=back

=cut

sub reject_start { $_[0]->output_comment('<!--filtered-->'); }
*reject_end         = \&reject_start;
*reject_text        = \&reject_start;
*reject_declaration = \&reject_start;
*reject_comment     = \&reject_start;
*reject_process     = \&reject_start;


=head1 WHITELIST INITIALIZATION METHODS

The filter refers to various whitelists to determine which constructs
are acceptable.  To modify these whitelists, subclasses can override
the following methods.

Each method is called once at object initialization time, and must
return a reference to a nested data structure.  These references are
installed into the object, and used whenever the filter needs to refer
to a whitelist.

The default implementations of these methods can be invoked as class
methods.

=over

=item init_context_whitelist ()

Returns a reference to the C<Context> whitelist, which determines
which tags may appear at each point in the document, and which other
tags may be nested within them.

It is a hash, and the keys are context names, such as C<Flow> and
C<Inline>.

The values in the hash are hashrefs.  The keys in these subhashes are
lowercase tag names, and the values are context names, specifying the
context that the tag provides to any other tags nested within it.

The special context C<EMPTY> as a value in a subhash indicates that
nothing can be nested within that tag.

=cut

use vars qw(%_Context);
BEGIN {

    my %pre_content = (
      'br'      => 'EMPTY',
      'span'    => 'Inline',
      'tt'      => 'Inline',
      'i'       => 'Inline',
      'b'       => 'Inline',
      'u'       => 'Inline',
      's'       => 'Inline',
      'strike'  => 'Inline',
      'em'      => 'Inline',
      'strong'  => 'Inline',
      'dfn'     => 'Inline',
      'code'    => 'Inline',
      'q'       => 'Inline',
      'samp'    => 'Inline',
      'kbd'     => 'Inline',
      'var'     => 'Inline',
      'cite'    => 'Inline',
      'abbr'    => 'Inline',
      'acronym' => 'Inline',
      'ins'     => 'Inline',
      'del'     => 'Inline',
      'a'       => 'Inline',
      'CDATA'   => 'CDATA',
    );

    my %inline = (
      %pre_content,
      'img'   => 'EMPTY',
      'big'   => 'Inline',
      'small' => 'Inline',
      'sub'   => 'Inline',
      'sup'   => 'Inline',
      'font'  => 'Inline',
      'nobr'  => 'Inline',
    );

    my %flow = (
      %inline,
      'ins'        => 'Flow',
      'del'        => 'Flow',
      'div'        => 'Flow',
      'p'          => 'Inline',
      'h1'         => 'Inline',
      'h2'         => 'Inline',
      'h3'         => 'Inline',
      'h4'         => 'Inline',
      'h5'         => 'Inline',
      'h6'         => 'Inline',
      'ul'         => 'list',
      'ol'         => 'list',
      'menu'       => 'list',
      'dir'        => 'list',
      'dl'         => 'dt_dd',
      'address'    => 'Inline',
      'hr'         => 'EMPTY',
      'pre'        => 'pre.content',
      'blockquote' => 'Flow',
      'center'     => 'Flow',
      'table'      => 'table',
    );

    my %table = (
      'caption'  => 'Inline',
      'thead'    => 'tr_only',
      'tfoot'    => 'tr_only',
      'tbody'    => 'tr_only',
      'colgroup' => 'colgroup',
      'col'      => 'EMPTY',
      'tr'       => 'th_td',
    );

    my %head = (
      'title'  => 'NoTags',
    );

    %_Context = (
      'Document'    => { 'html' => 'Html' },
      'Html'        => { 'head' => 'Head', 'body' => 'Flow' },
      'Head'        => \%head,
      'Inline'      => \%inline,
      'Flow'        => \%flow,
      'NoTags'      => { 'CDATA' => 'CDATA' },
      'pre.content' => \%pre_content,
      'table'       => \%table,
      'list'        => { 'li' => 'Flow' },
      'dt_dd'       => { 'dt' => 'Inline', 'dd' => 'Flow' },
      'tr_only'     => { 'tr' => 'th_td' },
      'colgroup'    => { 'col' => 'EMPTY' },
      'th_td'       => { 'th' => 'Flow', 'td' => 'Flow' },
    );
}

sub init_context_whitelist { return \%_Context; }

=item init_attrib_whitelist ()

Returns a reference to the C<Attrib> whitelist, which determines which
attributes each tag can have and the values that those attributes can
take.

It is a hash, and the keys are lowercase tag names.

The values in the hash are hashrefs.  The keys in these subhashes are
lowercase attribute names, and the values are attribute value class names,
which are short strings describing the type of values that the
attribute can take, such as C<color> or C<number>.

=cut

use vars qw(%_Attrib);
BEGIN {

    my %attr = ( 'style' => 'style' );

    my %font_attr = (
      %attr,
      'size'  => 'size',
      'face'  => 'wordlist',
      'color' => 'color',
    );

    my %insdel_attr = (
      %attr,
      'cite'     => 'href',
      'datetime' => 'text',
    );

    my %texta_attr = (
      %attr,
      'align' => 'word',
    );

    my %cellha_attr = (
      'align'    => 'word',
      'char'     => 'word',
      'charoff'  => 'size',
    );

    my %cellva_attr = (
      'valign' => 'word',
    );

    my %cellhv_attr = ( %attr, %cellha_attr, %cellva_attr );

    my %col_attr = (
      %attr, %cellhv_attr,
      'width' => 'size',
      'span'  => 'number',
    );

    my %thtd_attr = (
      %attr,
      'abbr'             => 'text',
      'axis'             => 'text',
      'headers'          => 'text',
      'scope'            => 'word',
      'rowspan'          => 'number',
      'colspan'          => 'number',
      %cellhv_attr,
      'nowrap'           => 'novalue',
      'bgcolor'          => 'color',
      'width'            => 'size',
      'height'           => 'size',
      'bordercolor'      => 'color',
      'bordercolorlight' => 'color',
      'bordercolordark'  => 'color',
    );

    %_Attrib = (
      'br'         => { 'clear' => 'word' },
      'em'         => \%attr,
      'strong'     => \%attr,
      'dfn'        => \%attr,
      'code'       => \%attr,
      'samp'       => \%attr,
      'kbd'        => \%attr,
      'var'        => \%attr,
      'cite'       => \%attr,
      'abbr'       => \%attr,
      'acronym'    => \%attr,
      'q'          => { %attr, 'cite' => 'href' },
      'blockquote' => { %attr, 'cite' => 'href' },
      'sub'        => \%attr,
      'sup'        => \%attr,
      'tt'         => \%attr,
      'i'          => \%attr,
      'b'          => \%attr,
      'big'        => \%attr,
      'small'      => \%attr,
      'u'          => \%attr,
      's'          => \%attr,
      'strike'     => \%attr,
      'font'       => \%font_attr,
      'table'      => { %attr,
                        'frame'            => 'word',
                        'rules'            => 'word',
                        %texta_attr,
                        'bgcolor'          => 'color',
                        'background'       => 'src',
                        'width'            => 'size',
			'height'           => 'size',
                        'cellspacing'      => 'size',
                        'cellpadding'      => 'size',
                        'border'           => 'size',
                        'bordercolor'      => 'color',
                        'bordercolorlight' => 'color',
                        'bordercolordark'  => 'color',
                        'summary'          => 'text',
                      },
      'caption'    => { %attr,
                        'align' => 'word',
                      },
      'colgroup'   => \%col_attr,
      'col'        => \%col_attr,
      'thead'      => \%cellhv_attr,
      'tfoot'      => \%cellhv_attr,
      'tbody'      => \%cellhv_attr,
      'tr'         => { %attr,
                        bgcolor => 'color',
                        %cellhv_attr,
                      },
      'th'         => \%thtd_attr,
      'td'         => \%thtd_attr,
      'ins'        => \%insdel_attr,
      'del'        => \%insdel_attr,
      'a'          => { %attr,
                        href => 'href',
                      },
      'h1'         => \%texta_attr,
      'h2'         => \%texta_attr,
      'h3'         => \%texta_attr,
      'h4'         => \%texta_attr,
      'h5'         => \%texta_attr,
      'h6'         => \%texta_attr,
      'p'          => \%texta_attr,
      'div'        => \%texta_attr,
      'span'       => \%texta_attr,
      'ul'         => { %attr,
                        'type'    => 'word',
                        'compact' => 'novalue',
                      },
      'ol'         => { %attr,
                        'type'    => 'text',
                        'compact' => 'novalue',
                        'start'   => 'number',
                      },
      'li'         => { %attr,
                        'type'  => 'text',
                        'value' => 'number',
                      },
      'dl'         => { %attr, 'compact' => 'novalue' },
      'dt'         => \%attr,
      'dd'         => \%attr,
      'address'    => \%attr,
      'hr'         => { %texta_attr,
                        'width'   => 'size',
                        'size '   => 'size',
                        'noshade' => 'novalue',
                      },
      'pre'        => { %attr, 'width' => 'size' },
      'center'     => \%attr,
      'nobr'       => {},
      'img'        => { 'src'    => 'src',
                        'alt'    => 'text',
                        'width'  => 'size',
                        'height' => 'size',
                        'border' => 'size',
                        'hspace' => 'size',
                        'vspace' => 'size',
                        'align'  => 'word',
                      },
      'body'       => { 'bgcolor'    => 'color',
                        'background' => 'src',
                        'link'       => 'color',
                        'vlink'      => 'color',
                        'alink'      => 'color',
                        'text'       => 'color',
                      },
      'head'       => {},
      'title'      => {},
      'html'       => {},
    );
}

sub init_attrib_whitelist { return \%_Attrib; }

=item init_attval_whitelist ()

Returns a reference to the C<AttVal> whitelist, which is a hash that maps
attribute value class names from the C<Attrib> whitelist to coderefs to
subs to validate (and optionally transform) a particular attribute value.

The filter calls the attribute value validation subs with the
following parameters:

=over

=item C<filter>

A reference to the filter object.

=item C<tagname>

The lowercase name of the tag in which the attribute appears.

=item C<attrname>

The name of the attribute.

=item C<attrval>

The attribute value found in the input document, in canonical form
(see L</"CANONICAL FORM">).

=back

The validation sub can return undef to indicate that the attribute
should be removed from the tag, or it can return the new value for
the attribute, in canonical form.

=cut

use vars qw(%_AttVal);
BEGIN {
    %_AttVal = (
      'style'     => \&_hss_attval_style,
      'size'      => \&_hss_attval_size,
      'number'    => \&_hss_attval_number,
      'color'     => \&_hss_attval_color,
      'text'      => \&_hss_attval_text,
      'word'      => \&_hss_attval_word,
      'wordlist'  => \&_hss_attval_wordlist,
      'wordlistq' => \&_hss_attval_wordlistq,
      'href'      => \&_hss_attval_href,
      'src'       => \&_hss_attval_src,
      'stylesrc'  => \&_hss_attval_stylesrc,
      'novalue'   => \&_hss_attval_novalue,
    );
}

sub init_attval_whitelist { return \%_AttVal; }

=item init_style_whitelist ()

Returns a reference to the C<Style> whitelist, which determines which CSS
style directives are permitted in C<style> tag attributes.  The keys are
value names such as C<color> and C<background-color>, and the values are
class names to be used as keys into the C<AttVal> whitelist.

=cut

use vars qw(%_Style);
BEGIN {
    %_Style = (
      'color'            => 'color',
      'background-color' => 'color',
      'background'       => 'stylesrc',
      'background-image' => 'stylesrc',
      'font-size'        => 'size',
      'font-family'      => 'wordlistq',
      'text-align'       => 'word',
    );
}

sub init_style_whitelist { return \%_Style; }

=item init_deinter_whitelist

Returns a reference to the C<DeInter> whitelist, which determines which inline
tags the filter should attempt to automatically de-interleave if they are
encountered interleaved.  For example, the filter will transform:

  <b>hello <i>world</b> !</i>

Into:

  <b>hello <i>world</i></b><i> !</i>

because both C<b> and C<i> appear as keys in the C<DeInter> whitelist.

=cut

use vars qw(%_DeInter);
BEGIN {
    %_DeInter = map {$_ => 1} qw(
      tt i b big small u s strike font em strong dfn code
      q sub sup samp kbd var cite abbr acronym span
    );
}

sub init_deinter_whitelist { return \%_DeInter; }

=back

=head1 CHARACTER DATA PROCESSING

These methods transform attribute values and non-tag text from the
input document into canonical form (see L</"CANONICAL FORM">), and
transform text in canonical form into a suitable form for the output
document.

=over

=item text_to_canonical_form ( TEXT )

This method is used to reduce non-tag text from the input document to
canonical form before passing it to the filter_text() method.

The default implementation unescapes all entities that map to
C<US-ASCII> characters other than ampersand, and replaces any
ampersands that don't form part of valid entities with C<&amp;>.

=cut

sub text_to_canonical_form {
    my ($self, $text) = @_;

    $text =~ s#&gt;#>#g;
    $text =~ s#&lt;#<#g;
    $text =~ s#&quot;#"#g;
    $text =~ s#&apos;#'#g;

    $text =~
      s! ( [^&]+ | &[a-z0-9]{2,15}; )  |
         &[#](0*[0-9]{2,6});           |
         &[#](x0*[a-f0-9]{2,6});       |
         &
       !
         defined $1 ? $1                              :
         defined $2 ? $self->_hss_decode_numeric($2) :
         defined $3 ? $self->_hss_decode_numeric($3) :
         '&amp;'
       !igex;

    return $text;
}

=item quoted_to_canonical_form ( VALUE )

This method is used to reduce attribute values quoted with doublequotes
or singlequotes to canonical form before passing it to the handler subs
in the C<AttVal> whitelist.

The default behavior is the same as that of text_to_canonical_form().

=cut

*quoted_to_canonical_form = \&text_to_canonical_form;

=item unquoted_to_canonical_form ( VALUE )

This method is used to reduce attribute values without quotes to
canonical form before passing it to the handler subs in the C<AttVal>
whitelist.

The default implementation simply replaces all ampersands with C<&amp;>,
since that corresponds with the way most browsers treat entities in
unquoted values.

=cut

sub unquoted_to_canonical_form {
    my ($self, $text) = @_;

    $text =~ s#&#&amp;#g;
    return $text;
}

=item canonical_form_to_attval ( ATTVAL )

This method is used to convert the text in canonical form returned by
the C<AttVal> handler subs to a form suitable for inclusion in
doublequotes in the output tag.

The default implementation runs anything that doesn't look like a
valid entity through the escape_html_metachars() method.

=cut

sub canonical_form_to_attval {
    my ($self, $text) = @_;

    $text =~ s/ (&[#\w]+;) | (.[^&]*)
              / defined $1 ? $1 : $self->escape_html_metachars($2)
              /gex;

    return $text;
}

=item canonical_form_to_text ( TEXT )

This method is used to convert the text in canonical form returned by
the filter_text() method to a form suitable for inclusion in the output
document.

The default implementation runs anything that doesn't look like a
valid entity through the escape_html_metachars() method.

=cut

*canonical_form_to_text = \&canonical_form_to_attval;

=item validate_href_attribute ( TEXT )

If the C<AllowHref> filter configuration option is set, then this
method is used to validate C<href> type attribute values.  TEXT is
the attribute value in canonical form.  Returns a possibly modified
attribute value (in canonical form) or C<undef> to reject the attribute.

The default implementation allows only absolute C<http> and C<https>
URLs, permits port numbers and query strings, and imposes reasonable
length limits.

=cut

sub validate_href_attribute {
    my ($self, $text) = @_;

    return $1 if $self->{_hssCfg}{AllowRelURL} and $text =~ /^([\w\-\.\,\/]{1,100})$/;

    $text =~ m< ^ ( https? :// [\w\-\.]{1,100} (?:\:\d{1,5})?
                    (?: / (?:[\w\-.!~*|;/?=+\$,%#]|&amp;){0,100} )?
                  )
                $
              >x ? $1 : undef;
}

=item validate_src_attribute ( TEXT )

If the C<AllowSrc> filter configuration option is set, then this
method is used to validate C<src> type attribute values.  TEXT is
the attribute value in canonical form.  Returns a possibly modified
attribute value (in canonical form) or C<undef> to reject the attribute.

The default implementation behaves as validate_href_attribute().

=cut

*validate_src_attribute = \&validate_href_attribute;

=back

=head1 OTHER METHODS TO OVERRIDE

As well as the output, reject, init and cdata methods listed above,
it might make sense for subclasses to override the following methods:

=over

=item filter_text ( TEXT )

This method will be invoked to filter blocks of non-tag text in the
input document.  Both input and output are in canonical form, see
L</"CANONICAL FORM">.

The default implementation does no filtering.

=cut

sub filter_text {
    my ($self, $text) = @_;

    return $text;
}

=item escape_html_metachars ( TEXT )

This method is used to escape all HTML metacharacters in TEXT.
The return value must be a copy of TEXT with metacharacters escaped.

The default implementation escapes a minimal set of
metacharacters for security against XSS vulnerabilities.  The set
of characters to escape is a compromise between the need for
security and the need to ensure that the filter will work for
documents in as many different character sets as possible.

Subclasses which make strong assumptions about the document
character set will be able to escape much more aggressively.

=cut

use vars qw(%_Escape_HTML_map);
BEGIN {
    %_Escape_HTML_map = (
        '&' => '&amp;',
        '<' => '&lt;',
        '>' => '&gt;',
        '"' => '&quot;',
        "'" => '&#39;',
    );
}

sub escape_html_metachars {
    my ($self, $text) = @_;

    $text =~ s#([&<>"'])# $_Escape_HTML_map{$1} #ge;
    return $text;
}

=item strip_nonprintable ( TEXT )

Returns a copy of TEXT with runs of nonprintable characters replaced
with spaces or some other harmless string.  Avoids replacing anything
with the empty string, as that can lead to other security issues.

The default implementation strips out only NULL characters, in order to
avoid scrambling text for as many different character sets as possible.

Subclasses which make some sort of assumption about the character set
in use will be able to have a much wider definition of a nonprintable
character, and hence a more secure strip_nonprintable() implementation.

=cut

sub strip_nonprintable {
    my ($self, $text) = @_;

    $text =~ tr#\0# #s;
    return $text;
}

=cut

=back

=head1 ATTRIBUTE VALUE HANDLER SUBS

References to the following subs appear in the C<AttVal> whitelist
returned by the init_attval_whitelist() method.

=over

=item _hss_attval_style( FILTER, TAGNAME, ATTRNAME, ATTRVAL )

Attribute value hander for the C<style> attribute.

=cut

sub _hss_attval_style {
    my ($filter, $tagname, $attrname, $attrval) = @_;
    my @clean = ();

    # Split on semicolon, making a reasonable attempt to ignore
    # semicolons inside doublequotes or singlequotes.
    while ( $attrval =~ s{^((?:[^;'"]|'[^']*'|"[^"]*")+)}{} ) {
        my $elt = $1;
        $attrval =~ s/^;//;

        if ( $elt =~ m|^\s*([\w\-]+)\s*:\s*(.+?)\s*$|s ) {
            my ($key, $val) = (lc $1, $2);

            my $value_class = $filter->{_hssStyle}{$key};
            next unless defined $value_class;
            my $sub =  $filter->{_hssAttVal}{$value_class};
            next unless defined $sub;

            my $cleanval = &{$sub}($filter, 'style-psuedo-tag', $key, $val);
            if (defined $cleanval) {
                push @clean, "$key:$val";
            }
        }
    }

    return join '; ', @clean;
}

=item _hss_attval_size ( FILTER, TAGNAME, ATTRNAME, ATTRVAL )

Attribute value handler for attributes who's values are some sort of
size or length.

=cut

sub _hss_attval_size {
    $_[3] =~ /^\s*([+-]?\d{1,20}(?:\.\d{1,20)?)\s*((?:\%|\*|ex|px|pc|cm|mm|in|pt|em)?)\s*$/i
    ? lc "$1$2" : undef;
}

=item _hss_attval_number ( FILTER, TAGNAME, ATTRNAME, ATTRVAL )

Attribute value handler for attributes who's values are a simple
integer.

=cut

sub _hss_attval_number {
    $_[3] =~ /^\s*\+?(\d{1,20})\s*$/ ? $1 : undef;
}

=item _hss_attval_color ( FILTER, TAGNAME, ATTRNAME, ATTRVAL )

Attribute value handler for color attributes.

=cut

sub _hss_attval_color {
    $_[3] =~ /^\s*(\w{2,20}|#[\da-fA-F]{6})\s*$/ ? $1 : undef;
}

=item _hss_attval_text ( FILTER, TAGNAME, ATTRNAME, ATTRVAL )

Attribute value handler for text attributes.

=cut

sub _hss_attval_text {
    length $_[3] <= 200 ? $_[3] : undef;
}

=item _hss_attval_word ( FILTER, TAGNAME, ATTRNAME, ATTRVAL )

Attribute value handler for attributes who's values must consist of
a single short word, with minus characters permitted.

=cut

sub _hss_attval_word {
    $_[3] =~ /^\s*([\w\-]{1,30})\s*$/ ? $1 : undef;
}

=item _hss_attval_wordlist ( FILTER, TAGNAME, ATTRNAME, ATTRVAL )

Attribute value handler for attributes who's values must consist of
one or more words, separated by spaces and/or commas.

=cut

sub _hss_attval_wordlist {
    $_[3] =~ /^\s*([\w\-\, ]{1,200})\s*$/ ? $1 : undef;
}

=item _hss_attval_wordlistq ( FILTER, TAGNAME, ATTRNAME, ATTRVAL )

Attribute value handler for attributes who's values must consist of
one or more words, separated by commas, with optional doublequotes
around words and spaces allowed within the doublequotes.

=cut

sub _hss_attval_wordlistq {
    my ($filter, $tagname, $attrname, $attrval) = @_;

    my @words = grep /^\s*(?:(?:"[\w\- ]{1,50}")|(?:[\w\-]{1,30}))\s*$/,
                split /,/, $attrval;

    scalar(@words) ? join(', ', @words) : undef;
}

=item _hss_attval_href ( FILTER, TAGNAME, ATTRNAME, ATTRVAL )

Attribute value handler for C<href> type attributes.  If the C<AllowHref>
configuration option is set, uses the validate_href_attribute() method
to check the attribute value.

=cut

sub  _hss_attval_href {
   my ($filter, $tagname, $attname, $attval) = @_;

   if ( $filter->{_hssCfg}{AllowHref} ) {
       return $filter->validate_href_attribute($attval);
   }
   else {
       return undef;
   }
}

=item _hss_attval_src ( FILTER, TAGNAME, ATTRNAME, ATTRVAL )

Attribute value handler for C<src> type attributes.  If the C<AllowSrc>
configuration option is set, uses the validate_src_attribute() method
to check the attribute value.

=cut

sub  _hss_attval_src {
   my ($filter, $tagname, $attname, $attval) = @_;

   if ( $filter->{_hssCfg}{AllowSrc} ) {
       return $filter->validate_src_attribute($attval);
   }
   else {
       return undef;
   }
}

=item _hss_attval_stylesrc ( FILTER, TAGNAME, ATTRNAME, ATTRVAL )

Attribute value handler for C<src> type style pseudo attributes.

=cut

sub _hss_attval_stylesrc {
   my ($filter, $tagname, $attname, $attval) = @_;

   if ( $attval =~ m#^\s*url\((.+)\)\s*$# ) {
       return _hss_attval_src($filter, $tagname, $attname, $1);
   }
   else {
       return undef;
   }
}

=item _hss_attval_novalue ( FILTER, TAGNAME, ATTRNAME, ATTRVAL )

Attribute value handler for attributes that have no value or a value that
is ignored.  Just returns the attribute name as the value.

=cut

sub _hss_attval_novalue {
    my ($filter, $tagname, $attname, $attval) = @_;

    return $attname;
}

=back

=head1 CANONICAL FORM

Many of the methods described above deal with text from the input
document, encoded in what I call C<canonical form>, defined as
follows:

All characters other than ampersands represent themselves.  Literal
ampersands are encoded as C<&amp;>.  Non C<US-ASCII> characters
may appear as literals in whatever character set is in use, or they
may appear as named or numeric HTML entities such as C<&aelig;>,
C<&#31337;> and C<&#xFF;>.  Unknown named entities such as C<&foo;>
may appear.

The idea is to be able to be able to reduce input text to a minimal
form, without making too many assumptions about the character set in
use.

=head1 PRIVATE METHODS

The following methods are internal to this class, and should not be
invoked from elsewhere.  Subclasses should not use or override
these methods.

=over

=item _hss_decode_numeric ( NUMERIC )

Returns the string that should replace the numeric entity NUMERIC
in the text_to_canonical_form() method.

=cut

sub _hss_decode_numeric {
    my ($self, $numeric) = @_;

    my $hex = ( $numeric =~ s/^x//i ? 1 : 0 );

    $numeric =~ s/^0+//;
    my $number = ( $hex ? hex($numeric) : $numeric );

    if ( $number == ord '&' ) {
        return '&amp;';
    }
    elsif ( $number < 127 ) {
        return chr $number;
    }
    else {
        return '&#' . ($hex ? 'x' : '') . uc($numeric) . ';';
    }
}

=item _hss_tag_is_banned ( TAGNAME )

Returns true if the lower case tag name TAGNAME is on the list of
harmless tags that the filter is configured to block, false otherwise.

=cut

sub _hss_tag_is_banned {
    my ($self, $tag) = @_;

    exists $self->{_hssBanList}{$tag} ? 1 : 0;
}

=item _hss_get_to_valid_context ( TAG )

Tries to get the filter to a context in which the tag TAG is
allowed, by introducing extra end tags or start tags if
necessary.  TAG can be either the lower case name of a tag or
the string 'CDATA'.

Returns 1 if an allowed context is reached, or 0 if there's no
reasonable way to get to an allowed context and the tag should
just be rejected.

=cut

sub _hss_get_to_valid_context {
    my ($self, $tag) = @_;

    # Special case: nested <a> is never valid.
    if ($tag eq 'a') {
        foreach my $ancestor (@{ $self->{_hssStack} }) {
            return 0 if $ancestor->{NAME} eq 'a';
        }
    }

    return 1 if $self->_hss_valid_in_current_context($tag);

    if ( $self->_hss_context eq 'Document' ) {
        $self->input_start('<html>');
        return 1 if $self->_hss_valid_in_current_context($tag);
    }

    if ( $self->_hss_context eq 'Html' and
         $self->_hss_valid_in_context($tag, 'Flow')
       ) {
        $self->input_start('<body>');
        return 1;
    }

    return 0 unless grep { $self->_hss_valid_in_context($tag, $_->{CTX}) }
                         @{ $self->{_hssStack} };

    until ( $self->_hss_valid_in_current_context($tag) ) {
        $self->_hss_close_innermost_tag;
    }

    return 1;
}

=item _hss_close_innermost_tag ()

Closes the innermost open tag.

=cut

sub _hss_close_innermost_tag {
    my ($self) = @_;

    $self->output_end('</' . $self->{_hssStack}[0]{NAME} . '>');
    shift @{ $self->{_hssStack} };
    die 'tag stack underflow' unless scalar @{ $self->{_hssStack} };
}

=item _hss_context ()

Returns the current named context of the filter.

=cut

sub _hss_context {
    my ($self) = @_;

    $self->{_hssStack}[0]{CTX};
}

=item _hss_valid_in_context ( TAG, CONTEXT )

Returns true if the lowercase tag name TAG is valid in context
CONTEXT, false otherwise.

=cut

sub _hss_valid_in_context {
    my ($self, $tag, $context) = @_;

    $self->{_hssContext}{$context}{$tag} ? 1 : 0;
}

=item _hss_valid_in_current_context ( TAG )

Returns true if the lowercase tag name TAG is valid in the filter's
current context, false otherwise.

=cut

sub _hss_valid_in_current_context {
    my ($self, $tag) = @_;

    $self->_hss_valid_in_context($tag, $self->_hss_context);
}

=back

=head1 BUGS

=over

=item

This module does a lot of work to ensure that tags are correctly
nested and are not left open, causing unnecessary overhead for
applications where that doesn't matter.

Such applications may benefit from using the more lightweight
L<HTML::Scrubber::StripScripts> module instead.

=back

=head1 SEE ALSO

L<HTML::Parser>, L<HTML::StripScripts::Parser>,
L<HTML::StripScripts::Regex>

=head1 AUTHOR

Nick Cleaton E<lt>nick@cleaton.netE<gt>

=head1 COPYRIGHT

Copyright (C) 2003 Nick Cleaton.  All Rights Reserved.

This module is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1;

