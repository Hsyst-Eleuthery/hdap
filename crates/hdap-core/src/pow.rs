//! Proof-of-work by bandwidth/band: `SHA256(challenge || be64(nonce))` with a
//! target number of leading zero bits (especificacao-hdap.md §9).

use crate::crypto::sha256;
use rand_core::{OsRng, RngCore};

/// Result of solving a challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowProof {
    pub nonce: u64,
    pub solution_hex: String,
    pub leading_bits: usize,
    pub attempts: u64,
}

fn target_mask(target_bits: usize) -> usize {
    // Number of leading zero bits required across the 32-byte digest.
    target_bits.min(256)
}

/// The exact bytes a solution hashes: `challenge || be64(nonce)`.
///
/// Public so a node can report `solved_bits` in its refusal instead of making
/// the client guess why it was wrong.
pub fn pow_preimage(challenge: &[u8], nonce: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(challenge.len() + 8);
    buf.extend_from_slice(challenge);
    buf.extend_from_slice(&nonce.to_be_bytes());
    buf
}

/// Verify a candidate solution. `leading_zero_bits(SHA256(challenge||be64(nonce))) >= target_bits`.
pub fn verify_pow(challenge: &[u8], nonce: u64, target_bits: usize) -> bool {
    leading_zero_bits(&sha256(&pow_preimage(challenge, nonce))) >= target_mask(target_bits)
}

/// Count the leading zero bits (MSB-first, byte 0 bit 7 down) of a digest.
pub fn leading_zero_bits(d: &[u8; 32]) -> usize {
    let mut count = 0;
    for byte in d {
        for bit in (0..8).rev() {
            if (byte >> bit) & 1 == 0 {
                count += 1;
            } else {
                return count;
            }
        }
    }
    count
}

/// Solve a challenge by scanning nonces incrementally. The search always
/// terminates for `target_bits <= 256` given the 64-bit nonce space is huge
/// compared to the expected number of trials.
pub fn solve_pow(
    challenge: &[u8],
    target_bits: usize,
    start: u64,
    budget: u64,
) -> Option<PowProof> {
    let mut nonce = start;
    let mut attempts = 0u64;
    let mut buf = vec![0u8; challenge.len() + 8];
    buf[..challenge.len()].copy_from_slice(challenge);
    while attempts < budget {
        buf[challenge.len()..].copy_from_slice(&nonce.to_be_bytes());
        let digest = sha256(&buf);
        let bits = leading_zero_bits(&digest);
        if bits >= target_mask(target_bits) {
            return Some(PowProof {
                nonce,
                solution_hex: hex::encode(digest),
                leading_bits: bits,
                attempts: attempts + 1,
            });
        }
        nonce = nonce.wrapping_add(1);
        attempts += 1;
    }
    None
}

/// Solve a challenge starting from an unpredictable random nonce, so that two
/// clients solving the same (deterministic per-node) challenge do not produce
/// the same proof — which the server's single-use guard (`mochthos_used`)
/// would otherwise reject for everyone but the first redeemer.
pub fn solve_pow_rand(challenge: &[u8], target_bits: usize, budget: u64) -> Option<PowProof> {
    solve_pow(challenge, target_bits, OsRng.next_u64(), budget)
}

/// `Canceller` is set by callers that want to abort a long-running solve.
#[derive(Debug, Default)]
pub struct Canceller {
    cancel: std::sync::atomic::AtomicBool,
}

impl Canceller {
    pub fn cancel(&self) {
        self.cancel
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Solve a challenge with a progress callback (called periodically with the
/// number of attempts so far) and a `Canceller` for abort. Returns `None` both
/// on budget exhaustion and on cancellation.
pub fn solve_pow_progress<F>(
    challenge: &[u8],
    target_bits: usize,
    budget: u64,
    canceller: &Canceller,
    mut on_progress: F,
) -> Option<PowProof>
where
    F: FnMut(u64),
{
    let start = OsRng.next_u64();
    let mut nonce = start;
    let mut attempts = 0u64;
    let mut buf = vec![0u8; challenge.len() + 8];
    buf[..challenge.len()].copy_from_slice(challenge);
    while attempts < budget {
        if canceller.is_cancelled() {
            return None;
        }
        buf[challenge.len()..].copy_from_slice(&nonce.to_be_bytes());
        let digest = sha256(&buf);
        let bits = leading_zero_bits(&digest);
        if bits >= target_mask(target_bits) {
            return Some(PowProof {
                nonce,
                solution_hex: hex::encode(digest),
                leading_bits: bits,
                attempts: attempts + 1,
            });
        }
        nonce = nonce.wrapping_add(1);
        attempts += 1;
        if attempts.is_multiple_of(16384) {
            on_progress(attempts);
        }
    }
    None
}

/// A client's own measurement of how fast it can hash, in H/s.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Hashrate(f64);

impl Hashrate {
    /// Build from a raw measurement, rejecting values that are not physically
    /// plausible (zero, negative, NaN, or absurdly beyond any SHA-256 core).
    pub fn new(hps: f64) -> Option<Self> {
        if hps.is_finite() && hps > 0.0 && hps <= 1e12 {
            Some(Hashrate(hps))
        } else {
            None
        }
    }

    pub fn hps(self) -> f64 {
        self.0
    }
}

/// The node's proof-of-work policy, expressed as a *time* budget with absolute
/// work bounds rather than as a bare difficulty.
///
/// # Why not just difficulty
///
/// A fixed `target_bits` is not adaptive: the same number of hashes is a
/// different amount of wall-clock on a phone and on a server. But making the
/// difficulty adaptive and letting the *client* pick it means the client picks
/// `0` bits and the band is free. So the policy knob has to be something the
/// client cannot lower, and the difficulty has to be *derived*:
///
/// - `target_secs` — how long a solve is meant to take. Hardware-neutral.
/// - `min_bits` — absolute work floor. Nobody earns band for less, so a fast
///   client cannot make the floor cheap by being fast.
/// - `max_bits` — ceiling. A client claiming an absurd hashrate is not
///   believed; it is clamped, and its extra claims earn nothing.
///
/// Band is proportional to proven absolute work, never to wall-clock, so the
/// reward cannot be inflated by claiming to be a datacenter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PowPolicy {
    pub target_secs: u32,
    pub min_bits: usize,
    pub max_bits: usize,
}

impl PowPolicy {
    pub fn new(target_secs: u32, min_bits: usize, max_bits: usize) -> Self {
        PowPolicy {
            target_secs,
            min_bits: min_bits.min(256),
            max_bits: max_bits.min(256),
        }
    }

    /// Difficulty for a claimed hashrate: `ceil(log2(hashrate * target_secs))`,
    /// clamped into `[min_bits, max_bits]`.
    ///
    /// This is the function a node uses to decide what it will accept, and a
    /// client uses to know what to solve. Both computing it from the same claim
    /// is deliberate: the server does not read a difficulty off the wire.
    pub fn bits_for(&self, hashrate: Hashrate) -> usize {
        let raw = (hashrate.hps() * f64::from(self.target_secs)).log2().ceil();
        let raw = if raw.is_finite() {
            raw
        } else {
            self.min_bits as f64
        };
        (raw.clamp(self.min_bits as f64, self.max_bits as f64)) as usize
    }

    /// Expected seconds a client with `hashrate` needs for this policy.
    pub fn expected_secs(&self, hashrate: Hashrate) -> f64 {
        let bits = self.bits_for(hashrate);
        2f64.powi(bits as i32) / hashrate.hps()
    }
}

impl Default for PowPolicy {
    fn default() -> Self {
        // ~4 s for a modest single core (~2 M H/s), 16 s for a fast one.
        PowPolicy::new(4, 18, 28)
    }
}

/// Measure the local hashrate by hashing `attempts` times and timing it.
///
/// Returns `None` when the elapsed time is too small to time reliably (a
/// single hash is not a measurement), so callers must use a real budget.
pub fn measure_hashrate(attempts: u64) -> Option<Hashrate> {
    if attempts == 0 {
        return None;
    }
    let mut buf = [0u8; 32];
    let start = std::time::Instant::now();
    for i in 0..attempts {
        buf = sha256(&i.to_be_bytes());
    }
    std::hint::black_box(buf);
    let secs = start.elapsed().as_secs_f64();
    Hashrate::new(attempts as f64 / secs)
}

/// Solve a challenge at the difficulty `policy` implies for the local
/// hardware, reporting progress and honouring cancellation.
///
/// The caller has already measured `hashrate`; this is the mining step.
pub fn solve_pow_adaptive<F>(
    challenge: &[u8],
    policy: PowPolicy,
    hashrate: Hashrate,
    canceller: &Canceller,
    on_progress: F,
) -> Option<PowProof>
where
    F: FnMut(u64),
{
    let bits = policy.bits_for(hashrate);
    solve_pow_progress(challenge, bits, u64::MAX, canceller, on_progress)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leading_zero_bits_counts_msb_first() {
        let mut d = [0u8; 32];
        assert_eq!(leading_zero_bits(&d), 256);
        d[0] = 0x80;
        assert_eq!(leading_zero_bits(&d), 0);
        d[0] = 0x7f;
        assert_eq!(leading_zero_bits(&d), 1);
        d[0] = 0x0f;
        assert_eq!(leading_zero_bits(&d), 4);
    }

    #[test]
    fn solve_and_verify_agree() {
        let challenge = b"hdap-pow-test-challenge";
        let proof = solve_pow(challenge, 8, 0, 1_000_000).unwrap();
        assert!(verify_pow(challenge, proof.nonce, 8));
        assert_eq!(
            proof.leading_bits,
            leading_zero_bits(
                &hex::decode(&proof.solution_hex)
                    .unwrap()
                    .try_into()
                    .unwrap()
            )
        );
    }

    #[test]
    fn verification_is_independent_of_solver() {
        let challenge = b"challenge-abc";
        let proof = solve_pow(challenge, 12, 0, 10_000_000).unwrap();
        assert!(verify_pow(challenge, proof.nonce, 12));
        assert!(!verify_pow(challenge, proof.nonce.wrapping_add(1), 12));
    }

    #[test]
    fn random_solver_produces_distinct_nonces_per_call() {
        // Regression: the client used to call solve_pow(_, _, start=0, _), so
        // every user solved the same (deterministic per-node) challenge with
        // the SAME nonce; the server's single-use guard then rejected everyone
        // but the first redeemer ("mochthos already redeemed on this pyle").
        let challenge = b"hdap-mochthos:node-a";
        let a = solve_pow_rand(challenge, 8, 1_000_000).unwrap();
        let b = solve_pow_rand(challenge, 8, 1_000_000).unwrap();
        assert_ne!(a.nonce, b.nonce, "nonces must not be predictable/repeated");
        assert!(verify_pow(challenge, a.nonce, 8));
        assert!(verify_pow(challenge, b.nonce, 8));
    }

    #[test]
    fn a_policy_maps_a_hashrate_onto_work_and_clamps_both_ends() {
        let p = PowPolicy::new(1, 10, 14);
        // The arithmetic the whole protocol rests on: bits = log2(hashrate * secs).
        assert_eq!(p.bits_for(Hashrate::new(1024.0).unwrap()), 10);
        assert_eq!(p.bits_for(Hashrate::new(2048.0).unwrap()), 11);
        assert_eq!(p.bits_for(Hashrate::new(8192.0).unwrap()), 13);

        // Both ends clamp, because both directions are attacks.
        assert_eq!(p.bits_for(Hashrate::new(1.0).unwrap()), 10); // "I'm a toaster"
        assert_eq!(p.bits_for(Hashrate::new(1e12).unwrap()), 14); // "I'm a datacenter"
    }

    #[test]
    fn an_implausible_hashrate_is_refused_rather_than_guessed() {
        // Zero, negative, NaN, infinity and petascale fantasy are all rejected
        // at construction. Silently coercing a bogus claim to a real one is how
        // a "difficulty 0" request turns into a free band grant.
        for bogus in [0.0, -1.0, f64::NAN, f64::INFINITY, 1e300] {
            assert!(
                Hashrate::new(bogus).is_none(),
                "{bogus} must not become a hashrate"
            );
        }
        assert!(Hashrate::new(1e12).is_some());
    }

    #[test]
    fn expected_seconds_lands_within_one_bit_of_the_budget() {
        let p = PowPolicy::new(4, 18, 28);
        let t = 4.0;
        // Difficulty is whole bits, so `ceil(log2(h*t))` can only land in
        // [t, 2t): a machine is never charged *less* than the budget, and at
        // worst it pays double. Anything outside this window means the
        // arithmetic drifted.
        for hps in [1e6, 2e6, 5e6, 1.5e7, 2e7] {
            let h = Hashrate::new(hps).unwrap();
            let secs = p.expected_secs(h);
            assert!(
                (t..2.0 * t).contains(&secs),
                "{hps} H/s: {secs}s outside [{t}, {})",
                2.0 * t
            );
        }
        // A claim is monotonic: inflating the hashrate can only raise the bar,
        // never lower it, so "I'm a datacenter" is never a discount.
        let mut prev = 0;
        for hps in [1.0, 1e3, 1e5, 2e6, 1.5e7, 1e9, 1e12] {
            let b = p.bits_for(Hashrate::new(hps).unwrap());
            assert!(
                b >= prev,
                "bits_for must not decrease as the claim rises ({hps})"
            );
            assert!(
                (p.min_bits..=p.max_bits).contains(&b),
                "{hps} -> {b} out of range"
            );
            prev = b;
        }
        // The ceiling bounds the work however absurd the claim: "1 PH/s" cannot
        // become an unbounded demand, and it cannot become free either.
        assert_eq!(p.bits_for(Hashrate::new(1e12).unwrap()), p.max_bits);
        assert_eq!(p.bits_for(Hashrate::new(0.001).unwrap()), p.min_bits);
    }

    #[test]
    fn a_client_claim_lands_exactly_on_the_difficulty_it_solved() {
        // Regression: the node used to verify against a `target_bits` the client
        // never sent (defaulting to max), so every honest claim failed; and the
        // client solver's budget was smaller than a fast machine's lawful
        // difficulty, so mining aborted with "budget exhausted". The contract is
        // that the hashrate the client sends back (`2^bits / target_secs`) makes
        // the node's `bits_for` reproduce the *same* bits it solved.
        for policy in [PowPolicy::default(), PowPolicy::new(4, 1, 6)] {
            let p = policy;
            let hps = measure_hashrate(200_000).expect("sample measures");
            let bits = p.bits_for(hps);
            // A solved proof must verify at `bits`.
            let challenge = format!("hdap-mochthos:{}", p.max_bits);
            let proof = solve_pow_rand(challenge.as_bytes(), bits, u64::MAX)
                .expect("solves within u64::MAX");
            assert!(verify_pow(challenge.as_bytes(), proof.nonce, bits));
            // The claim the client will post implies exactly the solved bits.
            let claim = Hashrate::new(2f64.powi(bits as i32) / f64::from(p.target_secs.max(1)))
                .expect("claim is plausible");
            assert_eq!(
                p.bits_for(claim),
                bits,
                "node must re-derive the difficulty the client solved"
            );
        }
    }

    #[test]
    fn a_measured_hashrate_is_physically_possible() {
        // Even a very small sample must produce a positive, plausible number:
        // a zero here would become log2(0) and a free proof.
        let h = measure_hashrate(4096).expect("a sample always measures");
        assert!(h.hps() > 0.0);
        assert!(h.hps() <= 1e12);
        // Determinism is not expected, but a second sample must not be absurd.
        let again = measure_hashrate(4096).expect("a sample always measures");
        assert!(again.hps() > 0.0);
    }

    #[test]
    fn the_policy_is_unsaturated_for_a_real_machine() {
        // Regression guard for the design: a modern CPU must land strictly
        // inside the window, not clamped at the ceiling. If this fails, the
        // default policy is mistuned for real hardware.
        let p = PowPolicy::default();
        let desktop = Hashrate::new(1.5e7).unwrap(); // ~15M SHA-256/s
        let bits = p.bits_for(desktop);
        assert!(
            bits > p.min_bits && bits < p.max_bits,
            "a 15 MH/s machine should sit inside the window, got {bits} in [{}, {}]",
            p.min_bits,
            p.max_bits
        );
        // And inside the one-bit time window, not instant and not an hour.
        let t = f64::from(p.target_secs);
        let secs = p.expected_secs(desktop);
        assert!(
            (t..2.0 * t).contains(&secs),
            "{secs}s outside [{}, {})",
            t,
            2.0 * t
        );
    }

    #[test]
    fn exhausted_budget_returns_none() {
        assert!(solve_pow(b"hard", 24, 0, 10).is_none());
    }

    /// The progress callback is throttled to every 16_384 attempts, so how
    /// many times it fires depends on how fast the nonce is found. Asserting
    /// "at least once" on a single solve is a coin flip — a target of 16 bits
    /// needs ~65k attempts on average, and roughly 1 in 5 solves finishes
    /// before the first tick. Test the throttle contract instead.
    const PROGRESS_EVERY: u64 = 16_384;

    #[test]
    fn progress_solver_reports_throttled_attempts_and_can_cancel() {
        let challenge = b"hdap-pow-progress";
        let canceller = Canceller::default();
        let mut calls = 0u64;
        let proof = solve_pow_progress(challenge, 16, 1 << 22, &canceller, |n| calls = n)
            .expect("solves in budget");
        assert!(verify_pow(challenge, proof.nonce, 16));
        // Any report must land on the throttle boundary and never claim more
        // work than was actually done.
        assert!(
            calls.is_multiple_of(PROGRESS_EVERY),
            "progress reported off-interval: {calls}"
        );
        assert!(calls <= proof.attempts, "{calls} > {}", proof.attempts);

        // Cancelling from inside the callback must stop the solve promptly.
        // This is the deterministic way to observe a callback: a 24-bit target
        // is ~16M attempts on average, so the solver is still working when the
        // first 16k-attempt report (and the cancel) arrives, even on a fast or
        // heavily loaded CI machine.
        let stopper = Canceller::default();
        let mut last = 0u64;
        let out = solve_pow_progress(challenge, 24, 1 << 22, &stopper, |a| {
            last = a;
            stopper.cancel();
        });
        assert!(
            out.is_none(),
            "cancelling from progress must abort the solve"
        );
        assert!(
            last > 0 && last.is_multiple_of(PROGRESS_EVERY),
            "expected a throttled report before the cancel, got {last}"
        );

        // A pre-cancelled solve aborts and returns None.
        let term = Canceller::default();
        term.cancel();
        assert!(solve_pow_progress(challenge, 16, 1_000_000, &term, |_| {}).is_none());
    }
}
