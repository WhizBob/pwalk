s/ user:/user /
s/ group:/group /
/owner-uid/s/>//
/owner-uid/s/<owner-uid=//
/owner-gid/s/>//
/owner-gid/s/<owner-gid=//
s/SID:S-1-1-0/everyone/
s/SID:S-1-3-0/creator_owner/
s/SID:S-1-3-1/creator_group/
/^OWNER:/d
/^GROUP:/d
s/^ *[0-9][0-9]*: *//
