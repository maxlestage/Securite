//! Password rules after NIST SP 800-63B and OWASP ASVS V2.1, and breached
//! password checks with Have I Been Pwned's k-anonymity API.
//!
//! The modern rules are *length and blocklists*, not composition: no "one
//! uppercase, one digit, one symbol" (they produce `Password1!`), no forced
//! periodic changes, but a long minimum length, a generous maximum (pass
//! phrases), every Unicode character allowed, and a refusal of passwords that
//! are common, derived from the context (user name, e-mail, site name),
//! trivially repetitive or sequential, or known from breaches.
//!
//! ```
//! use securite::password_policy::{PasswordPolicy, Violation};
//!
//! let policy = PasswordPolicy::new().context(["alice", "alice@example.com", "Acme"]);
//!
//! assert!(policy.check("correct horse battery staple").is_ok());
//! let err = policy.check("password123").unwrap_err();
//! assert!(err.violations().contains(&Violation::Common));
//! assert!(policy.check("alice2026!!").unwrap_err().violations().contains(&Violation::Context));
//! assert!(policy.check("aaaaaaaaaaaa").is_err());
//! ```
//!
//! # Breached passwords (Have I Been Pwned)
//!
//! With k-anonymity, only the first 5 hexadecimal characters of the SHA-1 of
//! the password leave your server; the API answers every suffix of that
//! range, and the match is done locally. `securite` builds the request and
//! reads the answer; the HTTP call is yours (any client, sync or async), so
//! no HTTP stack is forced on you.
//!
//! ```
//! use securite::password_policy::{PasswordPolicy, hibp};
//!
//! let query = hibp::RangeQuery::new("P@ssw0rd");
//! assert_eq!(query.url(), "https://api.pwnedpasswords.com/range/21BD1");
//! // GET query.url() with the header `Add-Padding: true`, then:
//! let body = "0018A45C4D1DEF81644B54AB7F969B88D65:10\r\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:0\r\n";
//! let count = query.count(body);
//! assert_eq!(count, 0);
//! let policy = PasswordPolicy::new();
//! assert!(policy.check_with_breaches("P@ssw0rd-but-longer", count).is_ok());
//! assert!(policy.check_with_breaches("P@ssw0rd-but-longer", 3).is_err());
//! ```

use std::fmt;

use sha1::{Digest, Sha1};

/// The 200 most common passwords of public breach compilations (lowercase).
/// Long enough to stop the first guesses of every credential-stuffing list.
const COMMON: &[&str] = &[
    "123456",
    "password",
    "12345678",
    "qwerty",
    "123456789",
    "12345",
    "1234",
    "111111",
    "1234567",
    "dragon",
    "123123",
    "baseball",
    "abc123",
    "football",
    "monkey",
    "letmein",
    "696969",
    "shadow",
    "master",
    "666666",
    "qwertyuiop",
    "123321",
    "mustang",
    "1234567890",
    "michael",
    "654321",
    "pussy",
    "superman",
    "1qaz2wsx",
    "7777777",
    "121212",
    "000000",
    "qazwsx",
    "123qwe",
    "killer",
    "trustno1",
    "jordan",
    "jennifer",
    "zxcvbnm",
    "asdfgh",
    "hunter",
    "buster",
    "soccer",
    "harley",
    "batman",
    "andrew",
    "tigger",
    "sunshine",
    "iloveyou",
    "2000",
    "charlie",
    "robert",
    "thomas",
    "hockey",
    "ranger",
    "daniel",
    "starwars",
    "klaster",
    "112233",
    "george",
    "computer",
    "michelle",
    "jessica",
    "pepper",
    "1111",
    "zxcvbn",
    "555555",
    "11111111",
    "131313",
    "freedom",
    "777777",
    "pass",
    "maggie",
    "159753",
    "aaaaaa",
    "ginger",
    "princess",
    "joshua",
    "cheese",
    "amanda",
    "summer",
    "love",
    "ashley",
    "nicole",
    "chelsea",
    "biteme",
    "matthew",
    "access",
    "yankees",
    "987654321",
    "dallas",
    "austin",
    "thunder",
    "taylor",
    "matrix",
    "william",
    "corvette",
    "hello",
    "martin",
    "heather",
    "secret",
    "merlin",
    "diamond",
    "1234qwer",
    "gfhjkm",
    "hammer",
    "silver",
    "222222",
    "88888888",
    "anthony",
    "justin",
    "test",
    "bailey",
    "q1w2e3r4t5",
    "patrick",
    "internet",
    "scooter",
    "orange",
    "11111",
    "golfer",
    "cookie",
    "richard",
    "samantha",
    "bigdog",
    "guitar",
    "jackson",
    "whatever",
    "mickey",
    "chicken",
    "sparky",
    "snoopy",
    "maverick",
    "phoenix",
    "camaro",
    "peanut",
    "morgan",
    "welcome",
    "falcon",
    "cowboy",
    "ferrari",
    "samsung",
    "andrea",
    "smokey",
    "steelers",
    "joseph",
    "mercedes",
    "dakota",
    "arsenal",
    "eagles",
    "melissa",
    "boomer",
    "booboo",
    "spider",
    "nascar",
    "monster",
    "tigers",
    "yellow",
    "xxxxxx",
    "123123123",
    "gateway",
    "marina",
    "diablo",
    "bulldog",
    "qwer1234",
    "compaq",
    "purple",
    "hardcore",
    "banana",
    "junior",
    "hannah",
    "123654",
    "porsche",
    "lakers",
    "iceman",
    "money",
    "cowboys",
    "987654",
    "london",
    "tennis",
    "999999",
    "ncc1701",
    "coffee",
    "scooby",
    "0000",
    "miller",
    "boston",
    "q1w2e3r4",
    "brandon",
    "yamaha",
    "chester",
    "mother",
    "forever",
    "johnny",
    "edward",
    "333333",
    "oliver",
    "redsox",
    "player",
    "nikita",
    "knight",
    "fender",
    "barney",
    "midnight",
    "please",
    "brandy",
    "chicago",
    "badboy",
    "slayer",
    "admin",
    "administrator",
    "passw0rd",
    "p@ssw0rd",
    "p@ssword",
    "welcome1",
    "azerty",
    "motdepasse",
    "contrasena",
    "changeme",
    "default",
    "root",
    "toor",
    "letmein1",
    "qwerty123",
    "password1",
    "password123",
    "iloveyou1",
    "abcd1234",
    "1q2w3e4r",
];

/// A rule that a password breaks.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Violation {
    /// Fewer characters than the minimum.
    TooShort {
        /// The minimum length, in characters.
        min: usize,
    },
    /// More characters than the maximum.
    TooLong {
        /// The maximum length, in characters.
        max: usize,
    },
    /// A well-known password (or one with only digits / symbols around it).
    Common,
    /// Contains the user name, the e-mail or another context word.
    Context,
    /// Too few distinct characters (`aaaaaaaa`, `abababab`).
    Repetitive,
    /// A keyboard or alphabet sequence (`12345678`, `abcdefgh`, `qwertyui`).
    Sequential,
    /// Found in data breaches.
    Breached {
        /// How many times Have I Been Pwned has seen it.
        count: u64,
    },
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Violation::TooShort { min } => write!(f, "use at least {min} characters"),
            Violation::TooLong { max } => write!(f, "use at most {max} characters"),
            Violation::Common => f.write_str("this password is too common"),
            Violation::Context => f.write_str("do not use your name or e-mail address"),
            Violation::Repetitive => f.write_str("too many repeated characters"),
            Violation::Sequential => f.write_str("avoid sequences such as 12345 or abcde"),
            Violation::Breached { .. } => {
                f.write_str("this password appeared in a data breach, choose another one")
            }
        }
    }
}

/// The rules a password breaks (never empty).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError {
    violations: Vec<Violation>,
}

impl PolicyError {
    /// Every broken rule.
    pub fn violations(&self) -> &[Violation] {
        &self.violations
    }
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, v) in self.violations.iter().enumerate() {
            if i > 0 {
                f.write_str("; ")?;
            }
            write!(f, "{v}")?;
        }
        Ok(())
    }
}

impl std::error::Error for PolicyError {}

/// Password rules. See the [module docs](self).
#[derive(Debug, Clone)]
pub struct PasswordPolicy {
    min: usize,
    max: usize,
    context: Vec<String>,
    blocklist: Vec<String>,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self::new()
    }
}

fn fold(s: &str) -> String {
    s.chars()
        .flat_map(char::to_lowercase)
        .filter(|c| !c.is_whitespace())
        .collect()
}

impl PasswordPolicy {
    /// NIST SP 800-63B defaults: at least 12 characters (ASVS 5 level 1, a
    /// little above NIST's 8), at most 128, common, contextual, repetitive and
    /// sequential passwords refused.
    pub fn new() -> Self {
        Self {
            min: 12,
            max: 128,
            context: Vec::new(),
            blocklist: Vec::new(),
        }
    }

    /// Minimum length in characters (at least 8, NIST's floor).
    ///
    /// # Panics
    ///
    /// Below 8.
    pub fn min_length(mut self, min: usize) -> Self {
        assert!(min >= 8, "NIST SP 800-63B requires at least 8 characters");
        self.min = min;
        self
    }

    /// Maximum length in characters (at least 64, NIST's floor). Bounded so
    /// that hashing a huge password cannot be used for denial of service.
    ///
    /// # Panics
    ///
    /// Below 64.
    pub fn max_length(mut self, max: usize) -> Self {
        assert!(
            max >= 64,
            "NIST SP 800-63B requires accepting 64 characters"
        );
        self.max = max;
        self
    }

    /// Words the password must not contain: user name, e-mail (its local
    /// part is checked too), first name, site name … Case-insensitive; words
    /// shorter than 4 characters are ignored.
    pub fn context<I, S>(mut self, words: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for w in words {
            let w = fold(w.as_ref());
            if let Some((local, _)) = w.split_once('@') {
                self.context.push(local.to_owned());
            }
            self.context.push(w);
        }
        self.context.retain(|w| w.chars().count() >= 4);
        self
    }

    /// Adds your own forbidden passwords (product names, leaked internal
    /// passwords …), compared case-insensitively.
    pub fn blocklist<I, S>(mut self, words: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.blocklist
            .extend(words.into_iter().map(|w| fold(w.as_ref())));
        self
    }

    /// Checks `password`; on error, lists every broken rule.
    pub fn check(&self, password: &str) -> Result<(), PolicyError> {
        let mut violations = Vec::new();
        let len = password.chars().count();
        if len < self.min {
            violations.push(Violation::TooShort { min: self.min });
        }
        if len > self.max {
            violations.push(Violation::TooLong { max: self.max });
            // Not worth analysing further.
            return Err(PolicyError { violations });
        }
        let folded = fold(password);
        let core: String = folded.trim_matches(|c: char| !c.is_alphabetic()).to_owned();
        let is_common = |w: &str| COMMON.contains(&w) || self.blocklist.iter().any(|b| b == w);
        if is_common(&folded) || (!core.is_empty() && is_common(&core)) {
            violations.push(Violation::Common);
        }
        if self.context.iter().any(|w| folded.contains(w.as_str())) {
            violations.push(Violation::Context);
        }
        let mut distinct: Vec<char> = folded.chars().collect();
        distinct.sort_unstable();
        distinct.dedup();
        if !folded.is_empty() && distinct.len() <= 2.max(len / 6) && distinct.len() < 5 {
            violations.push(Violation::Repetitive);
        }
        if is_sequential(&folded) {
            violations.push(Violation::Sequential);
        }
        if violations.is_empty() {
            Ok(())
        } else {
            Err(PolicyError { violations })
        }
    }

    /// [`check`](Self::check), plus the breach count returned by
    /// [`hibp::RangeQuery::count`]: any count above zero is refused.
    pub fn check_with_breaches(
        &self,
        password: &str,
        breach_count: u64,
    ) -> Result<(), PolicyError> {
        let mut violations = match self.check(password) {
            Ok(()) => Vec::new(),
            Err(e) => e.violations,
        };
        if breach_count > 0 {
            violations.push(Violation::Breached {
                count: breach_count,
            });
        }
        if violations.is_empty() {
            Ok(())
        } else {
            Err(PolicyError { violations })
        }
    }
}

/// Whether most of the password is one run of consecutive characters, in
/// either direction, on the alphabet, the digits or a keyboard row.
fn is_sequential(s: &str) -> bool {
    const ROWS: &[&str] = &[
        "abcdefghijklmnopqrstuvwxyz",
        "01234567890",
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
        "azertyuiop",
        "qsdfghjklm",
        "wxcvbn",
        "1qaz2wsx3edc4rfv5tgb",
    ];
    let chars: Vec<char> = s.chars().collect();
    if chars.len() < 4 {
        return false;
    }
    let mut longest = 1usize;
    for row in ROWS {
        for rev in [false, true] {
            let row: Vec<char> = if rev {
                row.chars().rev().collect()
            } else {
                row.chars().collect()
            };
            let mut run = 1usize;
            for w in chars.windows(2) {
                let next = row
                    .iter()
                    .position(|&c| c == w[0])
                    .and_then(|i| row.get(i + 1));
                if next == Some(&w[1]) {
                    run += 1;
                    longest = longest.max(run);
                } else {
                    run = 1;
                }
            }
        }
    }
    longest * 3 >= chars.len() * 2
}

/// Have I Been Pwned's Pwned Passwords range API (k-anonymity).
pub mod hibp {
    use super::*;

    /// The API endpoint, without the prefix.
    pub const RANGE_ENDPOINT: &str = "https://api.pwnedpasswords.com/range/";

    /// A range request for one password: only [`prefix`](Self::prefix)
    /// leaves the server.
    #[derive(Clone, PartialEq, Eq)]
    pub struct RangeQuery {
        prefix: String,
        suffix: String,
    }

    impl fmt::Debug for RangeQuery {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            // The suffix narrows the password down: keep it out of logs.
            f.debug_struct("RangeQuery")
                .field("prefix", &self.prefix)
                .finish_non_exhaustive()
        }
    }

    impl RangeQuery {
        /// Hashes `password` (SHA-1, as the API requires) and splits the
        /// uppercase hex digest into a 5-character prefix and a suffix.
        pub fn new(password: &str) -> Self {
            let digest = Sha1::digest(password.as_bytes());
            let hex = crate::util::hex_encode(&digest).to_ascii_uppercase();
            let (p, s) = hex.split_at(5);
            Self {
                prefix: p.to_owned(),
                suffix: s.to_owned(),
            }
        }

        /// The 5 hex characters sent to the API.
        pub fn prefix(&self) -> &str {
            &self.prefix
        }

        /// `https://api.pwnedpasswords.com/range/<prefix>`. Send it with the
        /// `Add-Padding: true` header so that the size of the answer does not
        /// reveal the prefix either.
        pub fn url(&self) -> String {
            format!("{RANGE_ENDPOINT}{}", self.prefix)
        }

        /// How many times the password appears in the API answer (`0` when
        /// absent, or for padding lines). Lines that do not parse are
        /// ignored; at most 4 MiB of answer is read.
        pub fn count(&self, body: &str) -> u64 {
            let body = &body[..body.len().min(4 << 20)];
            body.lines()
                .filter_map(|line| line.trim().split_once(':'))
                .find(|(suffix, _)| suffix.eq_ignore_ascii_case(&self.suffix))
                .and_then(|(_, n)| n.trim().parse().ok())
                .unwrap_or(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn violations(p: &PasswordPolicy, pw: &str) -> Vec<Violation> {
        p.check(pw).err().map(|e| e.violations).unwrap_or_default()
    }

    #[test]
    fn length_counts_characters_not_bytes() {
        let p = PasswordPolicy::new();
        assert_eq!(violations(&p, "short"), [Violation::TooShort { min: 12 }]);
        assert!(p.check("çà et là, ŝi venis").is_ok());
        assert_eq!(
            violations(&p, &"x".repeat(129)),
            [Violation::TooLong { max: 128 }]
        );
        assert!(p.check(&"long pass phrase ".repeat(7)).is_ok());
        // Spaces, emoji and every Unicode character are allowed.
        assert!(p.check("🦀 crabs rule the deep sea").is_ok());
    }

    #[test]
    fn common_and_blocklist() {
        let p = PasswordPolicy::new().min_length(8).blocklist(["Acme-Corp"]);
        for pw in [
            "password",
            "Password123",
            "P@SSW0RD",
            "  qwerty123  ",
            "!!password!!",
            "123456789",
        ] {
            assert!(violations(&p, pw).contains(&Violation::Common), "{pw}");
        }
        assert!(violations(&p, "acme-corp").contains(&Violation::Common));
        assert!(p.check("purple-lake-garden").is_ok());
    }

    #[test]
    fn context_words() {
        let p = PasswordPolicy::new().context(["Bob", "jeanne.d@example.org", "Securite"]);
        assert!(violations(&p, "my-JEANNE.D-pass").contains(&Violation::Context));
        assert!(violations(&p, "securite2026!!").contains(&Violation::Context));
        assert!(
            p.check("bob is short ctx ok?").is_ok(),
            "3-letter words ignored"
        );
    }

    #[test]
    fn repetitive_and_sequential() {
        let p = PasswordPolicy::new();
        for pw in ["aaaaaaaaaaaa", "abababababab", "111111111111"] {
            assert!(violations(&p, pw).contains(&Violation::Repetitive), "{pw}");
        }
        for pw in [
            "abcdefghijkl",
            "123456789012",
            "zyxwvutsrqpo",
            "qwertyuiopas",
            "1qaz2wsx3edc",
        ] {
            assert!(violations(&p, pw).contains(&Violation::Sequential), "{pw}");
        }
        assert!(p.check("tr0ub4dor&3-horse").is_ok());
    }

    #[test]
    fn hibp_k_anonymity() {
        let q = hibp::RangeQuery::new("password");
        // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        assert_eq!(q.prefix(), "5BAA6");
        assert!(
            !format!("{q:?}").contains("1E4C9B93"),
            "suffix never logged"
        );
        let body = "003D68EB55068C33ACE09247EE4C639306B:3\n1e4c9b93f3f0682250b6cf8331b7ee68fd8:9545824\r\nZZZ\n";
        assert_eq!(q.count(body), 9_545_824);
        assert_eq!(q.count(""), 0);
        assert_eq!(hibp::RangeQuery::new("x").count(body), 0);
        let p = PasswordPolicy::new();
        let err = p
            .check_with_breaches("a fine long passphrase", 2)
            .unwrap_err();
        assert_eq!(err.violations(), [Violation::Breached { count: 2 }]);
        assert!(err.to_string().contains("breach"));
    }

    #[test]
    #[should_panic(expected = "at least 8")]
    fn nist_floor() {
        let _ = PasswordPolicy::new().min_length(6);
    }
}
