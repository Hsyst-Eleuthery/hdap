//! Tempo canonical do HDAP (v2 / Teleios).
//!
//! Todo carimbo de tempo do protocolo é um `u64`: segundos Unix desde
//! 1970-01-01T00:00:00Z (UTC). Não há fuso horário, DST, offset local nem
//! strings de data no fio. O relógio do cliente nunca decide validade: o
//! servidor emite o `ts` dos desafios e o cliente apenas o devolve.

use std::time::{SystemTime, UNIX_EPOCH};

/// Agora, em segundos Unix UTC.
pub fn unix_secs_utc() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Regra única de expiração: `0` significa "nunca expira"; caso contrário o
/// valor é inválido no instante `now >= expires_at`.
pub fn is_expired(now: u64, expires_at: u64) -> bool {
    expires_at != 0 && now >= expires_at
}

/// Um carimbo recebido do cliente só é aceito se for **exatamente** o valor
/// emitido pelo servidor. Não existe "conversão de fuso": `ts` já é UTC.
/// `tolerance` só é usada por rotas de federação, onde ambos os lados geram o
/// timestamp localmente a partir de seus próprios relógios.
pub fn client_ts_matches(client_ts: u64, server_ts: u64) -> bool {
    client_ts == server_ts
}

/// Comparação de skew entre relógios de dois nós, sem overflow.
pub fn clock_skew_within(client_ts: u64, server_ts: u64, tolerance_secs: u64) -> bool {
    let diff = client_ts.abs_diff(server_ts);
    diff <= tolerance_secs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_boundary_is_inclusive() {
        assert!(!is_expired(99, 100));
        assert!(is_expired(100, 100));
        assert!(is_expired(101, 100));
        assert!(!is_expired(u64::MAX, 0));
    }

    #[test]
    fn client_timestamp_is_exact_and_skew_is_bounded() {
        assert!(client_ts_matches(1_700_000_000, 1_700_000_000));
        assert!(!client_ts_matches(1_700_000_000, 1_700_000_001));
        assert!(clock_skew_within(100, 130, 30));
        assert!(clock_skew_within(130, 100, 30));
        assert!(!clock_skew_within(100, 131, 30));
        assert!(clock_skew_within(0, u64::MAX, u64::MAX));
    }
}
