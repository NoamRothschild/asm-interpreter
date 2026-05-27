/// When true, only carry (CF) and zero (ZF) participate in pass/fail flag checks.
/// Mismatches on SF, OF, and other unmodeled flags are counted as skipped instead of failed.
pub const ignore_unmodeled_flag_mismatches: bool = true;

/// When true, [log.skip] is silent (unknown instructions, parse skips, unmodeled flags, etc.).
pub const suppress_skip_logs: bool = true;
