<<<<<<< HEAD
# v0.8
* Removed the linux version line in gemspec. Re-tested. Updated the README.

# v0.7
* Fixed a problem where ...

# v0.6
* Changed a `FIX2SHORT` to `FIX2INT` in pdkimglue.c in order to be compatible with Ruby 1.9.1.

# v0.5
* Fixed a problem with `pdkim_dkim_public_key_lookup` where if a key was split into multiple lines, only the first line would be returned.

* Changed the `pdkim_verify_an_email` method to return the signatures. This was done to make the function more like the long calls, and to give the calling method the coice of what to do with the signature data.

* Changed the `pdkimgemtest` program to add a GMail email signature verification test, and spiffed up the format of the test program.

* Double checked and updated the README.md file to make sure the calling instructions are right.

=======
# v0.7
* Fixed a problem where ...

# v0.6
* Changed a `FIX2SHORT` to `FIX2INT` in pdkimglue.c in order to be compatible with Ruby 1.9.1.

# v0.5
* Fixed a problem with `pdkim_dkim_public_key_lookup` where if a key was split into multiple lines, only the first line would be returned.

* Changed the `pdkim_verify_an_email` method to return the signatures. This was done to make the function more like the long calls, and to give the calling method the coice of what to do with the signature data.

* Changed the `pdkimgemtest` program to add a GMail email signature verification test, and spiffed up the format of the test program.

* Double checked and updated the README.md file to make sure the calling instructions are right.

>>>>>>> cc86330969a96d57b6f596567aff06ed1fea99cc
# v0.4
* Added a README file with usage instructions.
* Added comments to `lib/pdkim.rb`
* Added some additional error checking

# v0.3
* Added `pdkim_dkim_public_key_lookup`, a Resolv based key lookup that returns the DKIM public key.

# v0.2
* Added new gem.
