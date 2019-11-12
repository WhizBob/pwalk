# pwalk

*** NOTICE: 2.05b3 was incorrectly committed as 2.05b8 (8 versus 3).  The next push will  ***
*** will end with b4, and the b8 anomally will live in infamy. This build purports to     ***
*** correct major brokeness in the ACL-related code and related utilities.                ***

This repository contains a high-speed multi-threaded treewalk utility called 'PowerWalk' (pwalk)
for various ends including metadata extraction and formatting, tactical filesystem repair work,
and utility operations such as bulk file deletion.  Also included is an assortment of ancillary
programs and documentation.

These programs are all by Bob Sneed of Dell EMC (Bob.Sneed@Dell.com) as part of a collection of
utilities sometimes collectively referred to as "Bobware". While some of the utilities in the
Bobware collection date back to the early 1980's, pwalk has only been under development since 2012.
It has accumulated a unique set of features for solving various problems in a scale-out NAS
environments.

pwalk is an ongoing work-in-progress, with the ambition of becoming an increasingly general-purpose
tool for various operations on highly-scaled filesystems, including but not limited to;

	- high-speed parameter-driven metadata extraction and formatting
	- bulk data operations (e.g. bulk file comparisons)
	- data migration aid (e.g. POSIX-to-NFS4 ACL migration)
	- file heirarchy comparisons with -cmp
	- being a framework for custom-coded tasks requiring a high-speed treewalker foundation

pwalk code management was moved to Github as a private project on September 29, 2017, and later
made public.  It is not intended that anyone come into possession of this code without first
collaborating with the author, Bob Sneed.

*** DISCLAIMERS ***

1. This is FREE CODE. Appropriate recognition of the author in derivative works
	is both ethical and appreciated, but not legally mandated.
2. This code carries no warrantees of any sort whatsoever, including any implied
	warrantees of correctness or suitability for any particular purpose.
3. This code is not a supported product of Dell EMC or any other commercial entity.
4. Apart from the provided documentation, the code is the documentation.
5. In no event shall the author be liable in any way for any damages that may arise
	from using this code or derivatives of this code.
6. The deployment and use of any code associated herewith under Isilon OneFS is
	neither condoned nor supported by Dell EMC.
7. Use at your own risk.

*** All That Being Said ... ***

Documentation for pwalk is spread across a number of documents;

	- pwalk_slides.pptx (Powerpoint) - the best basic orientation to pwalk
	- pwalk_acls.docx (Word) - detailed discussion of ACL-handling features
		and associated utility programs
	- pwalk_manpage.docx (Word) - preliminary manpage (VERY prelilminary)
	- acl_decoder.xlsx (Excel) - 'secret decoder ring' for ACL permissions

Both the code and the documentation are maintained in a perpetual state of incompleteness
and begging for some cleanup and consolidation work!

*** Older Distribution Method ***

pwalk is often distributed as an E-Mail attachment in a uuencoded gzip'ed tarball format
('bundle') which has been designed to get past most E-Mail filters. The C-shell script
'uu-export.csh' creates these bundles in the directory superior to this directory, with
a name than includes a timestamp of when the bundle was created.

To unpack this format, the recipient should take the following steps;

	- Save the E-Mail attachment to a file, e.g. 'pwalk-export_20180312@161642_uu.allow'
	- Edit the file to remove the first line
	- uudecode -p < EDITTED_FILE | tar xzvf  -
		o  This will create a directory called pwalk with about 16 MB of content
		o  pwalk/bin/* will contain the last-built pwalk-related binaries

NOTE: The various bin/* directories are NOT assured to be in-sync from the same source code!
