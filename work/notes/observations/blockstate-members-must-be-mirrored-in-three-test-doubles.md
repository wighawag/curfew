---
title: A new blockstate.State member has to be copied into three test doubles, and dropping one fails silently
slug: blockstate-members-must-be-mirrored-in-three-test-doubles
source: 'hit while adding PendingBlock to blockstate.State, 2026-08-08'
---

`blockstate.State` says, in its own doc comment, that the authoritative list of reboot-surviving members lives on the type and that you should "add it here and nowhere else". That is true of the production code and false of the tests. Adding `PendingBlock` also required editing three hand-written copies:

- `copyState` in `internal/policy/policy_test.go`
- `memState.Load` in `internal/httpui/httpui_test.go`
- `memState.Save` in the same file

Each of those doubles copies member by member, and each carries a comment warning that dropping one would hide a real defect. Both httpui copies dropped the new member, and the failure was not a compile error or a clear message: the handler returned 303 with no error, the state looked saved, and the test failed later with "nothing was persisted", which reads exactly like a bug in the feature rather than a bug in the double. It cost a debugging detour to find.

The doubles exist for a good reason (`memState` is deliberately dumb and encodes none of the logic under test), so the fix is not to delete them. Options, none taken yet:

- Have the doubles deep-copy with one shared helper, exported for tests from `blockstate` itself, so there is one copy routine and the type owns it.
- Or have them marshal to JSON and back, which follows the real store's own contract and makes a forgotten `json:` tag visible as well.

Either way the property to protect is: a member added to the type must not be able to go missing in a double without something failing loudly and pointing at the double.
