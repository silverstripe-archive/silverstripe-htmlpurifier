# HtmlPurifierSanitiser module

Replaces HtmlEditorSanitiser (which implements the TinyMCE valid_elements whitelist rules) with
a sanitiser based on [HTMLPurifier](http://htmlpurifier.org/)

TinyMCE's whitelist isn't capable of (for instance) allowing hrefs to contain
regular `http:` links but not `javascript:` links, and so doesn't completely eliminate XSS potential

This class uses the TinyMCE whitelist, but only as a reference for instructions it gives to
HTMLPurifier, which is a library designed specifically for filtering HTML to remove XSS vectors

Note that these features in TinyMCE whitelists are not supported:

 - Wildcards (on elements or attributes)
 - Default and Forced attribute values

## Maintainer Contact

* Hamish Friedlander <hamish (at) silverstripe (dot) com>

## Requirements

* SilverStripe 3.1+

