package dnspolicy

// Closing the easy half of the DNS-over-HTTPS bypass.
//
// A DNS restriction is only worth anything if the child's device actually asks
// this router. DoH and DoT let it ask somebody else instead, over 443 or 853,
// and then every rule in this package is inert while looking perfectly
// correct. That is the single most likely way for this feature to be "built"
// and useless.
//
// # What this closes, and what it does not
//
// Most DoH clients look their endpoint up by NAME before they can use it, and
// that lookup goes to the household resolver. Blocking the well-known endpoint
// hostnames therefore breaks DoH for:
//
//   - Firefox, which additionally checks a CANARY domain
//     (use-application-dns.net) and disables its automatic DoH when that
//     returns NXDOMAIN. MEASURED: AdGuard already blocks that canary ITSELF,
//     out of the box, with no rule from anyone, so curfew's entry for it is
//     belt-and-braces against an AdGuard configured otherwise rather than the
//     load-bearing part;
//   - a browser or OS pointed at a DoH provider by hostname, which is how
//     essentially every UI exposes the setting;
//   - Chrome's secure-DNS presets, which are named providers.
//
// It does NOT close:
//
//   - a client configured with a DoH endpoint by literal IP address, which
//     never asks DNS at all;
//   - DoT, which needs port 853 blocked in the firewall, not here;
//   - a plain hardcoded resolver such as 8.8.8.8:53, which needs the same;
//   - a VPN, which takes the whole traffic stream elsewhere.
//
// Those need enforcement rules in nftables and are specified separately in
// work/specs/proposed/force-dns-through-the-router.md. This part is cheap,
// carries no risk of taking DNS away from the household, and is worth having
// on its own.
//
// **This list will go stale.** New providers appear and hostnames change, and
// nothing here updates itself. It is a speed bump against a curious child, not
// a control, and it is deliberately not presented as one.
//
// One caveat worth knowing: the Firefox canary only disables DoH when the
// answer is NXDOMAIN. curfew's own AdGuard config sets `blocking_mode:
// nxdomain`, but an AdGuard curfew ADOPTED may be set to return 0.0.0.0
// instead, in which case Firefox is not deterred by the canary (though its
// endpoint hostname is still blocked, which is the stronger half anyway).
//
// The rules are NOT window-gated. A child sets a DoH endpoint once and it
// persists, so letting them resolve it outside the window would defeat the
// next one. They apply to every profile that has restrictions configured, and
// to nobody else: parents and ungoverned devices keep DoH.

// DoHBootstrapDomains are the hostnames a client must resolve before it can
// use a well-known DoH or DoT provider.
//
// Written as base domains where subdomain coverage is intended, because an
// AdGuard `||domain^` rule matches subdomains too: `||cloudflare-dns.com^`
// covers mozilla., chrome., security. and family. without listing them.
var DoHBootstrapDomains = []string{
	// Firefox's canary. NXDOMAIN here turns its automatic DoH off outright,
	// which is the cheapest win available.
	"use-application-dns.net",

	"cloudflare-dns.com",
	"one.one.one.one",
	"dns.google",
	"dns.google.com",
	"quad9.net",
	"nextdns.io",
	"opendns.com",
	"adguard-dns.com",
	"dns.adguard.com",
	"cleanbrowsing.org",
	"controld.com",
	"dns.sb",
	"alidns.com",
	"doh.360.cn",
	"dnsforge.de",
	"libredns.gr",
	"mullvad.net",
	"dns.switch.ch",
	"doh.tiar.app",
	"dnspod.cn",
}
