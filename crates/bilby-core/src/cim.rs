//! WMI (CIM) datetime parsing: `yyyymmddHHMMSS.mmmmmmsUUU`, where `s` is
//! `+` or `-` and `UUU` is the UTC offset in minutes. Pure, so it's tested on
//! any OS.

use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset};

/// Parses a CIM datetime into UTC. Returns `None` for malformed values and
/// for the all-zero or asterisk "not set" forms Windows uses.
pub fn parse_datetime(s: &str) -> Option<OffsetDateTime> {
    let s = s.trim();
    if s.len() < 25 || !s.is_ascii() || s.starts_with("00000000") || s.contains('*') {
        return None;
    }
    let num = |range: std::ops::Range<usize>| s.get(range)?.parse::<u32>().ok();
    let year = i32::try_from(num(0..4)?).ok()?;
    let month = Month::try_from(u8::try_from(num(4..6)?).ok()?).ok()?;
    let date = Date::from_calendar_date(year, month, u8::try_from(num(6..8)?).ok()?).ok()?;
    let time = Time::from_hms_micro(
        u8::try_from(num(8..10)?).ok()?,
        u8::try_from(num(10..12)?).ok()?,
        u8::try_from(num(12..14)?).ok()?,
        num(15..21)?,
    )
    .ok()?;
    if s.as_bytes().get(14) != Some(&b'.') {
        return None;
    }
    let sign: i32 = match s.as_bytes().get(21)? {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let minutes = sign * i32::try_from(num(22..25)?).ok()?;
    let offset = UtcOffset::from_whole_seconds(minutes * 60).ok()?;
    Some(
        PrimitiveDateTime::new(date, time)
            .assume_offset(offset)
            .to_offset(UtcOffset::UTC),
    )
}

/// Largest believable age in days for Defender's `*Age` fields (about 30
/// years). Windows reports "never" as 65535, or as 4294967295 (-1 as an
/// unsigned 32-bit number), depending on the build.
pub const MAX_AGE_DAYS: u32 = 11_000;

/// A Defender age in days, or `None` for the "never" values.
pub fn age_days(raw: u32) -> Option<u32> {
    (raw <= MAX_AGE_DAYS).then_some(raw)
}

/// Converts an OLE Automation date (days since 1899-12-30, as Windows Update
/// reports them) to UTC. Fractions are the time of day.
pub fn from_ole_date(days: f64) -> Option<OffsetDateTime> {
    if !days.is_finite() || days <= 0.0 {
        return None;
    }
    let epoch = PrimitiveDateTime::new(
        Date::from_calendar_date(1899, Month::December, 30).ok()?,
        Time::MIDNIGHT,
    )
    .assume_utc();
    // Truncation is intended: sub-second precision doesn't matter here, and
    // valid dates are far inside i64.
    #[allow(clippy::cast_possible_truncation)]
    let seconds = (days * 86_400.0).round() as i64;
    epoch.checked_add(time::Duration::seconds(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn parses_cim_datetimes() {
        assert_eq!(
            parse_datetime("20261109090000.000000+000"),
            Some(datetime!(2026-11-09 09:00:00 UTC))
        );
        // Sydney summer time, +660 minutes.
        assert_eq!(
            parse_datetime("20261109200000.123456+660"),
            Some(datetime!(2026-11-09 09:00:00.123456 UTC))
        );
        assert_eq!(
            parse_datetime("20261109040000.000000-300"),
            Some(datetime!(2026-11-09 09:00:00 UTC))
        );
    }

    #[test]
    fn rejects_unset_and_malformed() {
        assert_eq!(parse_datetime("00000000000000.000000+000"), None);
        assert_eq!(parse_datetime("2026**09090000.000000+000"), None);
        assert_eq!(parse_datetime("20261309090000.000000+000"), None);
        assert_eq!(parse_datetime("2026110909"), None);
        assert_eq!(parse_datetime("20261109090000x000000+000"), None);
        assert_eq!(parse_datetime(""), None);
    }

    #[test]
    fn age_sentinels_mean_never() {
        assert_eq!(age_days(0), Some(0));
        assert_eq!(age_days(6), Some(6));
        assert_eq!(age_days(65_535), None);
        // Seen on a windows-2025 runner for QuickScanAge with no scan yet.
        assert_eq!(age_days(4_294_967_295), None);
    }

    #[test]
    fn converts_ole_dates() {
        // 2026-11-09 12:00 UTC is OLE day 46335.5.
        assert_eq!(
            from_ole_date(46_335.5),
            Some(datetime!(2026-11-09 12:00:00 UTC))
        );
        assert_eq!(from_ole_date(0.0), None);
        assert_eq!(from_ole_date(f64::NAN), None);
    }
}
