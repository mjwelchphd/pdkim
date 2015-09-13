#pdkim


##GENERAL
PDKIM - a RFC4871 (DKIM) implementation
http://duncanthrax.net/pdkim/
Copyright (C) 2009  Tom Kistner <tom@duncanthrax.net>

Includes code from the PolarSSL project.
http://polarssl.org
Copyright (C) 2009  Paul Bakker <polarssl_maintainer@polarssl.org>
Copyright (C) 2006-2008 Christophe Devine

This gem (C) 2015 Michael J. Welch, Ph.D. <mjwelchphd@gmail.com>
Source code can be found on GitHub: https://github.com/mjwelchphd/pdkim
The Linux gem can be found on RubyGems.org: https://rubygems.org/gems/pdkim

PDKIM is the pacakge that Exim4 uses for DKIM support.


##CONTACT ME
Please study this README and look at the test program, pdkimgemtest.rb, before you ask me for help. You can also look at the documentation generated by RubyGems.org. I don't have a Windows or Mac computer, so I wasn't able to compile the gem for Windows or Mac. Sorry. If you really need to ask me a question, my email is <mjwelchphd@gmail.com>. Please don't email either Tom or Paul because they can't help you with this gem. Tom tells me that his current job does not allow much time to continue hacking on SMTP-related things, and it's probably the same for Paul.


##THIS GEM IS NOT YET PRODUCTION SOFTWARE
At the time of this writing (SEP 2015), this gem is not yet production software. Therefore, it may have bugs I haven't caught yet. This gem is licensed with the MIT license, so technically, you're on your own. Practically, however, I want this gem to be useful and I'll help as much as I can. Just drop me an email.


##WHAT IS DKIM?
DomainKeys Identified Mail (DKIM) is an email validation system designed to detect email spoofing by providing a mechanism to allow receiving mail exchangers to check that incoming mail from a domain is authorized by that domain's administrators and that the email (including attachments) has not been modified during transport. A digital signature included with the message can be validated by the recipient using the signer's public key published in the DNS. In technical term, DKIM is a technique to authorize the domain name which is associated with a message through cryptographic authentication.

DKIM is the result of merging DomainKeys and Identified Internet Mail.[1] This merged specification has been the basis for a series of IETF standards-track specifications and support documents which eventually resulted in STD 76 (aka RFC 6376).[2]

Prominent email service providers implementing DKIM include Yahoo, Gmail, AOL and FastMail. Any mail from these organizations should carry a DKIM signature.

(Wikipedia -- https://en.wikipedia.org/wiki/DomainKeys_Identified_Mail)


##WHAT IS RUBY GEM FOR DKIM?
The Ruby gem is a "wrapper" written in C for Tom Kistner's PDKIM library. The PDKIM is a C/C++ library that implements DomainKeys Identified Mail (DKIM) (RFC4871). Its main virtues are: 
* Self-contained, no dependencies (except for a C library), thanks to code included from the PolarSSL project.
* Cross-Platform. Works on Unix™ and Windows™.
* Straightforward API
* Small size
* GPL license
  [*] Well, except for a C library. But I guess you have one!

GIT Repos: The PDKIM GIT repos is currently hosted at GitHub
Authors: Tom Kistner (tom@duncanthrax.net)

The library implements all the calls needed to sign emails and verify signatures, and the Ruby gem makes them accesible to Ruby programs as a "mix-in" module. When the gem is "required" (loaded), all the predefined constants (which we'll get into below) are defined in Ruby for your methods to access. The signing and verifying methods are exposed when you include PDKIM in any of your classes.


##HOW DOES DKIM WORK?
The gem accepts an array of lines that form an email, and add a DKIM "signature." For example, a simple email may look like this:
```smtp
From: Tom Kistner <tom@duncanthrax.net><cr><lf>
X-Folded-Header: line one<cr><lf>
line two<cr><lf>
To: PDKIM<cr><lf>
Subject: PDKIM Test<cr><lf>
<cr><lf>
Test 3,4<cr><lf>
Heute bug ich, morgen fix ich.<cr><lf>
```

After the signing method is called, a DKIM header is added to the email, preceeding the part of the email that is being signed. The result may look something like this:
```smtp
DKIM-Signature: v=1; a=rsa-sha256; q=dns/txt; c=simple/simple;<cr><lf>
d=duncanthrax.net; s=cheezburger; h=Subject:To:From;<cr><lf>
	bh=TYfjX+U7VNSWkCdJ6jK/zo8Xze+WTNzPpy5l/ra8X+c=;<cr><lf>
	b=oe15Ft/x+EMYgPgfQPxJViYOpNUd3GHPVWq4LmHFIBsm5bokL5TPLWaG7X3iX8ALY91bdag2FIhsLVdNIg9ZDHvtnHYZmcl9r76n0JJG/XszO8iH6vWjZ9smjPDQuDHT8NB5UOUl2S6/M5+6dzdkbAwcrQ5W/cKsl/PYzofzVhA=;<cr><lf>
From: Tom Kistner <tom@duncanthrax.net><cr><lf>
X-Folded-Header: line one<cr><lf>
line two<cr><lf>
To: PDKIM<cr><lf>
Subject: PDKIM Test<cr><lf>
<cr><lf>
Test 3,4<cr><lf>
Heute bug ich, morgen fix ich.<cr><lf>
```

The Ruby gem stores the messages as an array of lines, with the ```<cr><lf>``` (hereafter CRLF) removed. The CRLF is added back when the message is reconstituted. Note that CRLF is a constant defined by this gem.

The DKIM signature consists of basically two parts: a hash of the body (the original email), and a hash to sign the email. The body hash (represented by bh) guarantees that the email cannot be modified without detection, and the signing hash (represented by b) guarantees that the email comes from the sender it preports to come from (represented by d). Take into account that there may be multiple DKIM signatures on any given email representing different servers the email has passed through.

Theoretically, any entity handling the mail can sign it, too. For example, by adding the "enigmail" plug-in to Thunderbird, Thunderbird can sign outgoing email, and verify incoming email.


##WHERE DO I GET THE RUBY PDKIM GEM?
To get the gem, just use "gem" to install it from RubyGems.org thusly:
```
sudo gem install pdkim
```  
That's all there is to it!


##HOW DO I USE IT?
There are two ways to sign and verify your emails. One is to make all the separate calls to the gem yourself (which gives you more control over the process). The other is to call the one-line sign or the one-line verify methods (which is easier to do). Both methods will be detailed in the text below.

If you call the methods yourself, you have more options to choose from, and you can turn on debugging (which I think is unnecessary).

If you call the one-line methods, it's quick and easy to add DKIM to your code.

##WHAT DO I NEED TO SIGN AN EMAIL?
To begin with, to sign an email you'll need to specify a few constants to define the signing parameters; you'll also need a private-key/public-key pair; and of course, the email to be signed. After that, there is a series of calls to make to process the email, and the output will be a signed email.

The easiest way to create the key pair is to use OpenSSL. To use this in a test, you can just look at the code for bin/pdkimgemtest.rb, but to actually use it with an MTA (mail server), you'll have to install the public key into the server's DNS records, and how you do that depends on the ISP you use to run your mail server.

A sample private key looks like this (in Ruby):

```ruby
rsa_private_key = <<EOT
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQC5+utIbbfbpssvW0TboF73Seos+1ijdPFGwc/z8Yu12cpjBvRb
5/qRJd83XCySRs0QkK1zWx4soPffbtyJ9TU5mO76M23lIuI5slJ4QLA0UznGxfHd
fXpK9qRnmG6A4HRHC9B93pjTo6iBksRhIeSsTL94EbUJ625i0Lqg4i6NVQIDAQAB
AoGBAIDGqJH/Pta9+GTzGovE0N0D9j1tUKPl/ocS/m4Ya7fgdQ36q8rTpyFICvan
QUmL8sQsmZ2Nkygt0VSJy/VOr6niQmoi97PY0egxvvK5mtc/nxePCGwYLOMpB6ql
0UptotmvJU3tjyHZbksOf6LlzvpAgk7GnxLF1Cg/RJhH9ubBAkEA6b32mr52u3Uz
BjbVWez1XBcxgwHk8A4NF9yCpHtVRY3751FZbrhy7oa+ZvYokxS4dzrepZlB1dqX
IXaq7CgakQJBAMuwpG4N5x1/PfLODD7PYaJ5GSIx6BZoJObnx/42PrIm2gQdfs6W
1aClscqMyj5vSBF+cWWqu1i7j6+qugSswIUCQA3T3BPZcqKyUztp4QM53mX9RUOP
yCBfZGzl8aCTXz8HIEDV8il3pezwcbEbnNjen+8Fv4giYd+p18j2ATSJRtECQGaE
lG3Tz4PYG/zN2fnu9KwKmSzNw4srhY82D0GSWcHerhIuKjmeTw0Y+EAC1nPQHIy5
gCd0Y/DIDgyTOCbML+UCQQClbgAoYnIpbTUklWH00Z1xr+Y95BOjb4lyjyIF98B2
FA0nM8cHuN/VLKjjcrJUK47lZEOsjLv+qTl0i0Lp6giq
-----END RSA PRIVATE KEY-----
EOT
```
A sample public key looks like this:
```
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC5+utIbbfbpssvW0TboF73Seos
+1ijdPFGwc/z8Yu12cpjBvRb5/qRJd83XCySRs0QkK1zWx4soPffbtyJ9TU5mO76
M23lIuI5slJ4QLA0UznGxfHdfXpK9qRnmG6A4HRHC9B93pjTo6iBksRhIeSsTL94
EbUJ625i0Lqg4i6NVQIDAQAB
-----END PUBLIC KEY-----
```
but it's stored into the server's DNS TXT record like this (in Ruby):
```ruby
rsa_private_key = "v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC5+utIbbfbpssvW0TboF73Seos+1ijdPFGwc/z8Yu12cpjBvRb5/qRJd83XCySRs0QkK1zWx4soPffbtyJ9TU5mO76M23lIuI5slJ4QLA0UznGxfHdfXpK9qRnmG6A4HRHC9B93pjTo6iBksRhIeSsTL94EbUJ625i0Lqg4i6NVQIDAQAB;"
```
The public key is retrieved by the gem's verification process.

A couple of other things needed for testing are
A test message:
```ruby
message = [
  "From: Tom Kistner <tom@duncanthrax.net>",
  "X-Folded-Header: line one",
  "\tline two",
  "To: PDKIM User",
  "Subject: PDKIM Test",
  "",
  "Test 1, 2, 3, 4",
  "This is a simple test of Ruby PDKIM."
]
```
The sending domain:
```ruby
domain = "duncanthrax.net"
```
A selector:
```ruby
selector = "cheezburger"
```
DKIM keys are stored on the sending server's DNS under the name ```selector._domainkey.domain.top-level-domain```. For example, DKIM looks for a public key for the test data above in the server's DNS TXT records with a name ```cheezburger._domainkey.duncanthrax.net```. A recommended practice is to rotate selectors by creating new ones and deleting old ones (once enough time has gone by for all the email signed with old selectors will have been verified). Google creates selectors like ```20120113```, i.e., date related.

For an example of how to set up a production mail server, see ```https://community.rackspace.com/developers/f/7/t/3449```.


##HOW DO I GENERATE THE DKIM KEYS WITH OPENSSL?
The easiest way to create a set of DKIM keys is using OpenSSL in 7 easy steps as follows:
```
$ openssl genrsa -out /tmp/dkim.private.key 1024
$ openssl rsa -in /tmp/dkim.private.key -out /tmp/dkim.public.key -pubout -outform PEM
```
Verify that the two keys are there:
```
$ ls /tmp
dkim.private.key  dkim.public.key <-- Make sure these two files are created.
```
Set the permissions as follows (assuming the process which will use the private key has root access: modify according to your own requirements):
```
$ chmod 400 /tmp/dkim.private.key # read only owner
$ chmod 444 /tmp/dkim.public.key # read only everybody
$ chown root:root /tmp/dkim.private.key
$ chown root:root /tmp/dkim.public.key
```
Move (don't copy) the two files from /tmp to where ever you want them.


##HOW DO I SIGN AN EMAIL THE LONG WAY?
The first call serves to initialize the signing process, and pass some signing choices to the initialization method. (The gem would normally look for the private key in a DNS TXT record named "cheezburger._domainkey.duncanthrax.net" during the verification process.) Typically, the keys would be read from files, not written into the code.

**_Note: for the full list of options, find the method description in the second section of this document.)_**
```ruby
ctx = pdkim_init_sign(PDKIM_INPUT_NORMAL, domain, selector, rsa_private_key)
(handle error) if ctx.nil?
```
The second call sets options, but this call can be skipped if you're happy with the defaults (below):
```ruby
ok = pdkim_set_optional(ctx, nil, nil, PDKIM_CANON_SIMPLE, PDKIM_CANON_SIMPLE, -1, PDKIM_ALGO_RSA_SHA256, 0, 0)
(handle error) if ok != PDKIM_OK
```
The third call passes the message to the signing methods:
```ruby
message.each { |line| 
  ok = pdkim_feed(ctx, line+CRLF, line.length+2)
  (handle error) if ok != PDKIM_OK
end
```
WARNING: Although you can pass the message in arbitrary pieces, there is
  a limit to their size. You can't pass the whole message at once, unless
  it's no bigger than our test message. Because it's natural for Ruby to
  handle the message as an array of lines, that's how this gem does it
  (for convenience). The same goes for the verification process.

Signing produces only one signature. The fourth call signs and retrieves the signature:
```ruby
ok, signatures = pdkim_feed_finish(ctx)
(handle error) if ok!=PDKIM_OK
signature = [signatures[0][:signature]]
```
NOTE: If you want to see what's in a signature, just use:
```ruby
puts signature.inspect
```
or better yet (you'll have to install the pretty_inspect gem),
```ruby
puts signature.pretty_inspect
```
To create the finished email, just concatenate the two:
```ruby
signed_message = signature + CRLF + message.join(CRLF) + CRLF
````
WARNING: Don't omit the trailing CRLF or the message will not be properly formed, and will not verify at the receiving end.

The fifth (and last) call releases the context. This is an important step because if the context is not released, it will be a memory leak. You can be sure this call is made by using a ```begin ... ensure ... end``` structure in Ruby, or just be sure that if you bail out on an error, you make this call first.
```ruby
pdkim_free_ctx(ctx)
```
The code above should generate the DKIM signature:
```
DKIM-Signature: v=1; a=rsa-sha256; q=dns/txt; c=simple/simple; d=duncanthrax.net; s=cheezburger;
	h=Subject:To:From; bh=+oeSNE7b9Ka6Gdh9ItFGX3J6Wacjc/JxAUaId7ON0T0=;
	b=Ap6DcX3x2MEoj1E3KBow7NF/2g5CnUoqkt0hgqJ0DufuOsFAPLl0tYA+yYIoCp8Acn/BJkjVYY+WQ7mlSUJfrZEZYIq1P+BZgBdP+Z+g3vrK2zEJchvwpnP0+xKniIktxT2WRQOoH3HBb/5Z1AhtuNfPEoE+kZN22Gksto4bqdg=;
```
That's the complete signing cycle.


##HOW DO I VERIFY AN EMAIL THE LONG WAY?
The verify process is similar to the signing process. Initialize, feed, finish, and pick up the results.

The first call serves to initialize the verifying process, and pass one choice to the initialization method. Also, the block on this call is required because PDKIM uses it to resolve public key requests for each of the signatures in the message (there may be more than one). Here we ignore the name (which in this case is "cheezburger.\_domainkey.duncanthrax.com", i.e., ready to be looked up with "pdkim\_dkim\_public\_key\_lookup(name)") and just return our test data because we know we only have one signature in the test message.
```ruby
ctx = pdkim_init_verify(PDKIM_INPUT_NORMAL) do |name|
  rsa_public_key
end
```
In a real method, we would probably use:
```ruby
ctx = pdkim_init_verify(PDKIM_INPUT_NORMAL) do |name|
  pdkim_dkim_public_key_lookup(name)
end
```
but you can substitute your own resolver for this task, if you wish. If the resolver can't retrieve the public key from the domain's DNS records, it returns nil, and that causes the ```pdkim_feed_finish(ctx)``` call to return the signature with PDKIM_VERIFY_FAIL.

When you call the one-line verify call (which will be explained soon), it defaults to the code above.

The second call(s) passes the (signed) message to the verifying methods:
```ruby
message.each { |line| 
  ok = pdkim_feed(ctx, line+CRLF, line.length+2)
  (handle error) if ok != PDKIM_OK
end
```
Verifying may produce multiple signatures because it produces one signature for each signature in the message. The third call verifies and retrieves the signatures:
```ruby
ok, signatures = pdkim_feed_finish(ctx)
(handle error) if ok!=PDKIM_OK
```
NOTE: If you want to see what's in the signatures, just use:
```ruby
puts signatures.inspect
```
or better yet (you'll need to install the pretty_inspect gem),
```ruby
puts signatures.pretty_inspect
```
NOTE: This is when the callbacks to the block in ```pdkim_init_verify``` will
  be made, once per DKIM signature in the message.

The return status will be found in each signature in:
```ruby
signature[:verify_status]
```
The pdkimgemtest.rb program has a counter/display for demonstration.

The fourth (and last) call releases the context. This is an important step because if the context is not released, it will be a memory leak. You can be sure this call is made by using a ```begin ... ensure ... end``` structure in Ruby, or just be sure that if you bail out on an error, you make this call first.
```ruby
pdkim_free_ctx(ctx)
```
That's the complete verification cycle.


##HOW DO I SIGN/VERIFY AN EMAIL THE SHORT WAY?
The signing and verifying procedures are reduced to one line each. Ya, usually this is preferable.

To sign a message, call:
```ruby
  ok, signed_message = pdkim_sign_an_email(PDKIM_INPUT_NORMAL, domain, selector, \
    rsa_private_key, PDKIM_CANON_SIMPLE, PDKIM_CANON_SIMPLE, message)
  (handle error) if ok != PDKIM_OK
```
And to verify a message, call:
```ruby
  ok, signatures = pdkim_verify_an_email(PDKIM_INPUT_NORMAL, signed_message, :fake_domain_lookup)
  (handle error) if ok != PDKIM_OK
```
The verify method returns an array of signatures: (only 1 shown here)
```
------------------------------------------------------------
---- The signature of the DKIM header:                     -
------------------------------------------------------------
- duncanthrax.net                     PDKIM_VERIFY_PASS    -
------------------------------------------------------------
```
And you'll need a fake domain lookup routine for this test to work. Notice the optional third parameter above, ":fake\_domain\_lookup." That tells the lib to use fake\_domain\_lookup() method rather than the default "pdkim\_dkim\_public\_key\_lookup" method for the public key lookup:
```ruby
  def fake_domain_lookup(name)
    rsa_private_key
  end
```
That's the complete sign/verify cycle using the short way.


#METHOD CALLS
```
This is a sample of the aray of signatures (hashes) that comes out
of the signing/verifying methods. Some fields shown here are only
in one or the other.

Sample of signatures array with one signature:
    [
      {
        :error=>0,
        :signature=>"DKIM-Signature: v=1; a=rsa-sha256; q=dns/txt;
          c=simple/simple; d=duncanthrax.net; s=cheezburger;
          h=Subject:To:From; bh=+oeSNE7b9Ka6Gdh9ItFGX3J6Wacjc/JxAUaId7ON0T0=;
          b=Ap6DcX3x2MEoj1E3KBow7NF/2g ... /5Z1AhtuNfPEoE+kZN22Gksto4bqdg=;",
        :version=>1,
        :algo=>0,
        :canon_headers=>0,
        :canon_body=>0,
        :querymethod=>0,
        :selector=>"cheezburger",
        :domain=>"duncanthrax.net",
        :identity=>nil,
        :created=>0,
        :expires=>0,
        :bodylength=>-1,
        :headernames=>"Subject:To:From",
        :copiedheaders=>nil,
        :sigdata=>"\x02\x9E\x83q}\xF1 ... 91\x93v\xD8i,\xB6\x8E\e\xA9\xD8",
        :bodyhash=>"\xFA\x87\x924N\xD ... 7#s\xF2q\x01F\x88w\xB3\x8D\xD1=",    
        :signature_header=>"DKIM-Signature: v=1; a=rsa-sha256; q=dns/txt;
          c=simple/simple; d=duncanthrax.net; s=cheezburger; th=Subject:To:From;
          bh=+oeSNE7b9Ka6Gdh9ItFGX3J6Wacjc/JxAUaId7ON0T0=;
          b=Ap6DcX3x2MEoj1E3KBow7NF/2 ... /5Z1AhtuNfPEoE+kZN22Gksto4bqdg=;",
        :verify_status=>0, # (if verifying, else 0)
        :verify_ext_status=>0,
        :pubkey=>{
          :version=>"DKIM1",
          :granularity=>"*",
          :hashes=>nil,
          :keytype=>"rsa",
          :srvtype=>"*",
          :notes=>nil,
          :key=>"0\x81\x9F0\r\x06\t*\ ... 0\xE2.\x8DU\x02\x03\x01\x00\x01",
          :testing=>0,
          :no_subdomaining=>0
        }
      }
    ]
```


```
ctx = pdkim_init_sign(mode, domain, selector, rsa_private_key)

Initialize context for signing.

  mode
    PDKIM_INPUT_NORMAL or PDKIM_INPUT_SMTP. When SMTP
    input is used, the lib will deflate double-dots at
    the start of a line to a single dot, and it will
    stop processing input when a line with and single
    dot is received (Excess input will simply be ignored).

  domain
    The domain to sign as. This value will land in the
    d= tag of the signature. For example, if the MAIL FROM
    address is joe@mail.example.com, the domain is
    example.com.

  selector
    The selector string to use. This value will land in
    the s= tag of the signature. For example, if the DNS DKIM TXT
    record contains 2015may._domainkey.example.com, the selector
    is 2015may.

  rsa_private_key
    The private RSA key, in ASCII armor. It MUST NOT be
    encrypted.

Returns: A freshly allocated ctx (context)
```


```
ctx = pdkim_init_verify(mode) { |name| ...code to retrieve domain's public key... }

Initialize context for verification.

  mode
    PDKIM_INPUT_NORMAL or PDKIM_INPUT_SMTP. When SMTP
    input is used, the lib will deflate double-dots at
    the start of a line to a single dot, and it will
    stop processing input when a line with and single
    dot is received (Excess input will simply be ignored).

  block
    Tom's pdkim lib does not include a DNS resolver, so one
    has been provided in this gem called "pdkim_dkim_public_key_lookup(name)."
    You may provide some other mechanism, however. This call, then, would be:

    ctx = pdkim_init_verify(mode) do |name|
      your_public_key_lookup(name)
    end

    NOTE: Although the block is on this call to pdkim_init_verify,
    the ACTUAL callbacks are made from pdkim_feed_finish as the
    DKIM signatures (there can be many) are being validated one by
    one. As each signature will have a different domain, a callback
    is used to do the lookup.

Returns: A freshly allocated ctx (context)
```


```
pdkim_set_debug_stream(ctx, file_name)
pdkim_set_debug_stream(ctx, file_number)

Set up debugging stream.

When pdkim.c was compiled with DEBUG defined (which is the
recommended default), you can set up a stream where it
sends debug output to. If you don't set a debug
stream, no debug output is generated.

  file_name
    If the first option is called, a file by the name
    file_name is opened, and debugging output is APPENDED to it.
    Ex: pdkim_set_debug_stream(ctx, "my_debug_log")

  file_number
    If the second option is choosen, a file by the number
    file_number is opened, and debugging output is APPENDED to it.
    Ex: pdkim_set_debug_stream(ctx, 2) # STDERR

Returns: nil
```


```
ok = pdkim_set_optional(ctx, sign_headers, identity, canon_headers, \
  canon_body, bodylength, algo, created, expires)

OPTIONAL: Set additional optional signing options. If you do
not use this function, sensible defaults (see below) are used.
Any strings you pass in are dup'ed, so you can safely release
your copy even before calling pdkim_free() on your context.

  sign_headers (default nil)
    Colon-separated list of header names. Headers with
    a name matching the list will be included in the
    signature. When this is NULL, the list of headers
    recommended in RFC4781 will be used.

  identity (default nil)
    An identity string as described in RFC4781. It will
    be put into the i= tag of the signature.

  canon_headers (default PDKIM_CANON_SIMPLE)
    Canonicalization algorithm to use for headers. One
    of PDKIM_CANON_SIMPLE or PDKIM_CANON_RELAXED.

  canon_body (default PDKIM_CANON_SIMPLE)
    Canonicalization algorithm to use for the body. One
    of PDKIM_CANON_SIMPLE or PDKIM_CANON_RELAXED.

  bodylength (default -1)
    Amount of canonicalized body bytes to include in
    the body hash calculation. A value of 0 means that
    the body is not included in the signature. A value
    of -1 (the default) means that there is no limit.

  algo (default PDKIM_ALGO_RSA_SHA256)
    One of PDKIM_ALGO_RSA_SHA256 or PDKIM_ALGO_RSA_SHA1.

  created (default 0)
    Seconds since the epoch, describing when the signature
    was created. This is copied to the t= tag of the
    signature. Setting a value of 0 (the default) omits
    the tag from the signature.

  expires (default 0)
    Seconds since the epoch, describing when the signature
    expires. This is copied to the x= tag of the
    signature. Setting a value of 0 (the default) omits
    the tag from the signature.

Returns: 0 (PDKIM_OK) for success or a PDKIM_ERR_* constant
```


```
ok = pdkim_feed(ctx, data, data_len)

(Repeatedly) feed data to the signing algorithm. The message
data MUST use CRLF line endings (like SMTP uses on the
wire). The data chunks do not need to be a "line" - you
can split chunks at arbitrary locations.

  data (Ruby String which is also allowed to contain binary)
    Pointer to data to feed. Please note that despite
    the example given below, this is not necessarily a
    C string, i.e., NULL terminated.

  data_len
    Length of data being fed, in bytes.

Returns: 0 (PDKIM_OK) for success or a PDKIM_ERR_* constant
```


```
ok = pdkim_feed_finish(ctx)

Signal end-of-message and retrieve the signature block.

Returns:
  ok
    0 (PDKIM_OK) for success or a PDKIM_ERR_* constant

   signatures (An array of hashes of signatures.)
     If the function returns PDKIM_OK, it will return
     one or more signatures.

     Sign only returns 1 signature, but verify will return 1 signature
     for each DKIM header in the email being verified.

     Returns an array of hashes (only 1 for sign) with the signatures in them
     [
       {
         "error"=>0, # 0 (PDKIM_OK) for success or a PDKIM_ERR_* constant
         "signature"=>nil,
         "version"=>1,
         "algo"=>0,
         "canon_headers"=>0,
         "canon_body"=>0,
         "querymethod"=>0,
         "selector"=>"cheezburger",
         "domain"=>"duncanthrax.net",
         "identity"=>nil,
         "created"=>0,
         "expires"=>0,
         "bodylength"=>-1,
         "headernames"=>"Subject:To:From",
         "copiedheaders"=>nil,
         "sigdata"=>"\xA1\xEDy\x16\xDF\xF1\xF8C\x18\x80\xF8\x1F@\xFCIV&\x0E\xA4\xD5 ...",
         "bodyhash"=>"M\x87\xE3_\xE5;T\xD4\x96\x90'I\xEA2\xBF\xCE\x8F\x17\xCD\xEF ...",
         "signature_header"=>nil,
         "verify_status"=>3,
         "verify_ext_status"=>0,
         "pubkey"=>{
           "version"=>"DKIM1",
           "granularity"=>"*",
           "hashes"=>nil,
           "keytype"=>"rsa",
           "srvtype"=>"*",
           "notes"=>nil,
           "key"=>"0\x81\x9F0\r\x06\t*\x86H\x86\xF7\r\x01\x01\x01\x05\x00\x03\x81\x8D ...",
           "testing"=>0,
           "no_subdomaining"=>0
         }
       }
     ]
```

```
pdkim_free_ctx(ctx)

Free all allocated memory blocks referenced from
the context, as well as the context itself.

Returns: nil

Don't forget to call this or your application will "leak" memory.
```


```
ok = pdkim_sign_an_email(mode, domain, selector, rsa_private_key, \
  canon_headers, canon_body, unsigned_message)

Call a single function to sign an email message.

  mode
    PDKIM_INPUT_NORMAL or PDKIM_INPUT_SMTP. When SMTP
    input is used, the lib will deflate double-dots at
    the start of a line to a single dot, and it will
    stop processing input when a line with and single
    dot is received (Excess input will simply be ignored).

  domain
    The domain to sign as. This value will land in the
    d= tag of the signature. For example, if the MAIL FROM
    address is joe@mail.example.com, the domain is
    example.com.

  selector
    The selector string to use. This value will land in
    the s= tag of the signature. For example, if the DNS DKIM TXT
    record contains 2015may._domainkey.example.com, the selector
    is 2015may.

  rsa_private_key
    The private RSA key, in ASCII armor. It MUST NOT be
    encrypted. For example, in the sample used for this gem,
    the private key is: rsa_private_key:
    -----BEGIN RSA PRIVATE KEY-----
    MIICXQIBAAKBgQC5+utIbbfbpssvW0TboF73Seos+1ijdPFGwc/z8Yu12cpjBvRb
    ...
    FA0nM8cHuN/VLKjjcrJUK47lZEOsjLv+qTl0i0Lp6giq
    -----END RSA PRIVATE KEY-----

  canon_headers (default PDKIM_CANON_SIMPLE)
    Canonicalization algorithm to use for headers. One
    of PDKIM_CANON_SIMPLE or PDKIM_CANON_RELAXED.

  canon_body (default PDKIM_CANON_SIMPLE)
    Canonicalization algorithm to use for the body. One
    of PDKIM_CANON_SIMPLE or PDKIM_CANON_RELAXED.

  unsigned_message
    An array of lines containing the email preceeded by a
    DKIM header that was generated by a signing process. The message
    data array MUST NOT contain CRLF line endings; instead, each line
    will have a CRLF added here. The lines may be of arbitrary
    length. A line oriented format was chosen because it's
    the "natural" way of formatting the data for Ruby.

Returns: an array of 2 elements: [success_code, message]
    if successful, returns 0 (PDKIM_OK) and the signed_message
    if unsuccessful, returns a PDKIM_ERR_* constant and nil
```


```
ok = verify_an_email(mode, signed_message, sym_domain_lookup)

Call a single function to verify an email message.

  mode
    PDKIM_INPUT_NORMAL or PDKIM_INPUT_SMTP. When SMTP
    input is used, the lib will deflate double-dots at
    the start of a line to a single dot, and it will
    stop processing input when a line with and single
    dot is received (Excess input will simply be ignored).

  signed_message
    An array of lines containing the email preceeded by a
    DKIM header that was generated by a signing process. The message
    data array MUST NOT contain CRLF line endings; instead, each line
    will have a CRLF added here. The lines may be of arbitrary
    length. A line oriented format was chosen because it's
    the "natural" way of formatting the data for Ruby.

  sym_domain_lookup (OPTIONAL)
    A symbolic name of the method to use for private key lookups.
    If this parameter is not given, it defaults to :pdkim_dkim_public_key_lookup
    which is the built-in lookup function.

Returns:
  ok
    0 (PDKIM_OK) for success or a PDKIM_ERR_* constant

  signatures (An array of hashes of signatures.)
    If the function returns PDKIM_OK, it will return
    one or more signatures.
```


```
key = pdkim_dkim_public_key_lookup(name)

This method retrieves the public key from the domain's
website's DNS records, if any. If it fails, it will return
"nil" which will cause the validation to fail with 
PDKIM_VERIFY_FAIL.

  name
    The name to be looked up by the resolver. It has the form:
    selector._domainkey.domain.com (org, biz, us, gov, etc.)
    the name will be properly formatted if this method is
    called from the block in pdkim_init_verify.

Returns: The DKIM public key for the domain in 'name' or nil
```
