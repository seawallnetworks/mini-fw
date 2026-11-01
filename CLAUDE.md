# CLAUDE.md

## Code change workflow

1. After a code change builds cleanly and the tests pass, invoke the `code-reviewer` subagent. Give it the task's key requirements, so it can check the change against them as well as the diff.
2. Fix every [MUST FIX] item it reports. Rebuild and rerun the tests after fixing.
3. Re-run the review on the fixes. Stop after at most 3 review rounds in total. If [MUST FIX] items remain after round 3, stop and report them rather than continuing.
4. When reporting back, summarize the review results: rounds run, [MUST FIX] items found and how each was fixed, and any [SHOULD FIX] / [OPTIONAL] items left unaddressed.
